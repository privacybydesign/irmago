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
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

type authorizationResponseConfig struct {
	State                               string
	QueryResponses                      []dcql.QueryResponse
	ResponseUri                         string
	ResponseType                        string
	ResponseMode                        ResponseMode
	EncryptionKeys                      *jwk.Set
	EncryptedResponseEncValuesSupported []string
}

func createAuthorizationResponseHttpRequest(config authorizationResponseConfig) (*http.Request, error) {
	values := url.Values{}

	if config.ResponseMode == ResponseMode_DirectPost {
		vpToken, err := createDirectPostVpToken(config.QueryResponses)
		if err != nil {
			return nil, err
		}
		values.Add("vp_token", vpToken)
		values.Add("state", config.State)
	}

	if config.ResponseMode == ResponseMode_DirectPostJwt {
		if config.EncryptionKeys == nil {
			return nil, fmt.Errorf("using response mode %v, but the encryption key is nil", ResponseMode_DirectPostJwt)
		}
		jwe, err := createEncryptedResponse(
			config.QueryResponses,
			map[string]any{"state": config.State},
			*config.EncryptionKeys,
			config.EncryptedResponseEncValuesSupported,
		)
		if err != nil {
			return nil, err
		}
		values.Add("response", jwe)
	}

	req, err := http.NewRequest(http.MethodPost, config.ResponseUri, strings.NewReader(values.Encode()))
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

	switch config.ResponseMode {
	case ResponseMode_DcApi:
		payload = map[string]any{"vp_token": createVpToken(config.QueryResponses)}

	case ResponseMode_DcApiJwt:
		if config.EncryptionKeys == nil {
			return "", fmt.Errorf("using response mode %v, but the encryption key is nil", ResponseMode_DcApiJwt)
		}
		jwe, err := createEncryptedResponse(
			config.QueryResponses,
			nil,
			*config.EncryptionKeys,
			config.EncryptedResponseEncValuesSupported,
		)
		if err != nil {
			return "", err
		}
		payload = map[string]any{"response": jwe}

	default:
		return "", fmt.Errorf("response mode %v is not a digital credentials api response mode", config.ResponseMode)
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
func createEncryptedResponse(queryResponses []dcql.QueryResponse, extraMembers map[string]any, encryptionKeys jwk.Set, encSupported []string) (string, error) {
	payload := map[string]any{
		"vp_token": createVpToken(queryResponses),
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

func createVpToken(queryResponses []dcql.QueryResponse) map[string][]string {
	content := map[string][]string{}
	for _, resp := range queryResponses {
		content[resp.QueryId] = append(content[resp.QueryId], resp.Credentials...)
	}

	return content
}

func createDirectPostVpToken(queryResponses []dcql.QueryResponse) (string, error) {
	content := createVpToken(queryResponses)
	result, err := json.Marshal(content)
	return string(result), err
}
