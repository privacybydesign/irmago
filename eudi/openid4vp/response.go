package openid4vp

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

type authorizationResponseConfig struct {
	state                               string
	queryResponses                      []dcql.QueryResponse
	responseUri                         string
	responseType                        string
	responseMode                        ResponseMode
	encryptionKeys                      *jwk.Set
	encryptedResponseEncValuesSupported []string

	audience string
	nonce    string
}

func createAuthorizationResponseHttpRequest(config authorizationResponseConfig) (*http.Request, error) {
	values := url.Values{}

	if config.responseMode == ResponseMode_DirectPost {
		vpToken, err := createDirectPostVpToken(config)
		if err != nil {
			return nil, err
		}
		values.Add("vp_token", vpToken)
		values.Add("state", config.state)

		eudi.Logger.Printf("VP-TOKEN: %s", vpToken)
	}

	if config.responseMode == ResponseMode_DirectPostJwt {
		if config.encryptionKeys == nil {
			return nil, fmt.Errorf("using response mode %v, but the encryption key is nil", ResponseMode_DirectPostJwt)
		}
		jwe, err := createEncryptedResponse(
			config,
			map[string]any{"state": config.state},
			*config.encryptionKeys,
			config.encryptedResponseEncValuesSupported,
		)
		if err != nil {
			return nil, err
		}
		values.Add("response", jwe)
	}

	req, err := http.NewRequest(http.MethodPost, config.responseUri, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")

	return req, nil
}

// createDcApiResponse builds the JSON object the wallet hands back to the
// platform's Digital Credentials API (Appendix A.4): the Authorization Response
// parameters for the response type. The state parameter is not defined for the
// DC API, so it is never included.
func createDcApiResponse(config authorizationResponseConfig) (string, error) {
	var payload map[string]any

	switch config.responseMode {
	case ResponseMode_DcApi:
		vpToken, err := createVpToken(config)
		if err != nil {
			return "", err
		}
		payload = map[string]any{"vp_token": vpToken}

	case ResponseMode_DcApiJwt:
		if config.encryptionKeys == nil {
			return "", fmt.Errorf("using response mode %v, but the encryption key is nil", ResponseMode_DcApiJwt)
		}
		jwe, err := createEncryptedResponse(
			config,
			nil,
			*config.encryptionKeys,
			config.encryptedResponseEncValuesSupported,
		)
		if err != nil {
			return "", err
		}
		payload = map[string]any{"response": jwe}

	default:
		return "", fmt.Errorf("response mode %v is not a digital credentials api response mode", config.responseMode)
	}

	result, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

// createEncryptedResponse encrypts the Authorization Response as an unsigned,
// encrypted JWT whose payload holds the response parameters as top-level members
// (Section 8.3). extraMembers carries the response-mode-specific members beyond
// vp_token, such as state for direct_post.jwt.
func createEncryptedResponse(config authorizationResponseConfig, extraMembers map[string]any, encryptionKeys jwk.Set, encSupported []string) (string, error) {
	vpToken, err := createVpToken(config)
	if err != nil {
		return "", err
	}

	payload := map[string]any{
		"vp_token": vpToken,
	}
	maps.Copy(payload, extraMembers)
	return encryptJwe(payload, encryptionKeys, encSupported)
}

func encryptJwe(payload map[string]any, keys jwk.Set, encSupported []string) (string, error) {
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to serialize payload for the encrypted response: %v", err)
	}

	encAlg, err := pickEncryptionAlgorithm(encSupported)
	if err != nil {
		return "", fmt.Errorf("no supported encryption algorithm: %v", err)
	}

	errors := []error{}

	for i := range keys.Len() {
		key, ok := keys.Key(i)
		if !ok {
			errors = append(errors, fmt.Errorf("couldn't find key at index %v", i))
			continue
		}

		h := jwe.NewHeaders()

		if kid, ok := key.KeyID(); !ok {
			errors = append(errors, fmt.Errorf("missing key id"))
			continue
		} else if kid != "" {
			h.Set(jwe.KeyIDKey, kid)
		}

		keyAlg, ok := key.Algorithm()
		if !ok {
			errors = append(errors, fmt.Errorf("key doesn't have alg"))
			continue
		}

		encrypted, err := jwe.Encrypt(
			payloadJson,
			jwe.WithKey(keyAlg, key),
			jwe.WithContentEncryption(encAlg),
			jwe.WithProtectedHeaders(h),
		)
		if err != nil {
			errors = append(errors, err)
			continue
		}
		return string(encrypted), nil
	}

	return "", fmt.Errorf("failed to encrypt response: %v", errors)
}

func pickEncryptionAlgorithm(options []string) (jwa.ContentEncryptionAlgorithm, error) {
	// according to openid4vp spec: when no algorithms are specified A128GCM is the default
	if len(options) == 0 {
		return jwa.A128GCM(), nil
	}

	// we'll just pick the first algorithm we support
	for _, opt := range options {
		alg, ok := jwa.LookupContentEncryptionAlgorithm(opt)
		if ok {
			return alg, nil
		}
	}

	return jwa.EmptyContentEncryptionAlgorithm(), fmt.Errorf("no supported encryption algorithm provided (%v)", options)
}

func createVpToken(config authorizationResponseConfig) (map[string]any, error) {
	content := map[string]any{}

	for _, resp := range config.queryResponses {
		switch resp.CredentialFormat {
		case "vc+sd-jwt":
			envelopedVerifiableCredentials := []any{}
			for _, cred := range resp.Credentials {
				evc := map[string]any{
					"@context": "https://www.w3.org/ns/credentials/v2",
					"type":     "EnvelopedVerifiableCredential",
					"id":       "data:application/vc+sd-jwt," + cred,
				}

				envelopedVerifiableCredentials = append(envelopedVerifiableCredentials, evc)
			}

			tok, err := jwt.NewBuilder().
				Claim("audience", config.audience).
				Claim("nonce", config.nonce).
				Claim("@context", []string{"https://www.w3.org/ns/credentials/v2"}).
				Claim("type", []string{"VerifiablePresentation"}).
				Claim("verifiableCredential", envelopedVerifiableCredentials).
				Build()
			if err != nil {
				return nil, fmt.Errorf("failed to build JWT: %v", err)
			}

			signed, err := jwt.Sign(tok, jwt.WithInsecureNoSignature())
			if err != nil {
				return nil, fmt.Errorf("failed to sign JWT: %v", err)
			}
			content[resp.QueryId] = []string{string(signed)}

		case "dc+sd-jwt":
			content[resp.QueryId] = resp.Credentials
		default:
			// default handling
			return nil, fmt.Errorf("unsupported credential format: %s", resp.CredentialFormat)
		}
	}

	return content, nil
}

func createDirectPostVpToken(config authorizationResponseConfig) (string, error) {
	content, err := createVpToken(config)
	if err != nil {
		return "", err
	}
	result, err := json.Marshal(content)
	return string(result), err
}
