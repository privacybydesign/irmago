package openid4vp

import (
	"crypto"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

type authorizationResponseConfig struct {
	State          string
	QueryResponses []dcql.QueryResponse
	ResponseUri    string
	ResponseType   string
	ResponseMode   ResponseMode
	// EncryptionKey is the single key the response is encrypted to, chosen by
	// selectResponseEncryptionKey before disclosure so mso_mdoc's session
	// transcript can commit to its thumbprint.
	EncryptionKey                       jwk.Key
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
		if config.EncryptionKey == nil {
			return nil, fmt.Errorf("using response mode %v, but the encryption key is nil", ResponseMode_DirectPostJwt)
		}
		jwe, err := createEncryptedResponse(
			config.QueryResponses,
			map[string]any{"state": config.State},
			config.EncryptionKey,
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
		if config.EncryptionKey == nil {
			return "", fmt.Errorf("using response mode %v, but the encryption key is nil", ResponseMode_DcApiJwt)
		}
		jwe, err := createEncryptedResponse(
			config.QueryResponses,
			nil,
			config.EncryptionKey,
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
func createEncryptedResponse(queryResponses []dcql.QueryResponse, extraMembers map[string]any, encryptionKey jwk.Key, encSupported []string) (string, error) {
	payload := map[string]any{
		"vp_token": createVpToken(queryResponses),
	}
	maps.Copy(payload, extraMembers)
	return encryptJwe(payload, encryptionKey, encSupported)
}

// selectResponseEncryptionKey returns the key encryptJwe will encrypt to, and
// its SHA-256 JWK thumbprint.
//
// It exists so the choice can be made before the response is built: mso_mdoc's
// session transcript hashes that thumbprint into the handover its deviceAuth
// signs over, and the signature only verifies if the response then arrives
// encrypted to the same key. Picking here and encrypting later against "the
// first key that works" would be a silent mismatch whenever the verifier
// publishes more than one usable key.
//
// The selection mirrors encryptJwe's own requirements — a key needs an alg to
// be usable — and takes the first such key, which is also the order encryptJwe
// walks the set in.
func selectResponseEncryptionKey(keys jwk.Set) (jwk.Key, []byte, error) {
	for i := range keys.Len() {
		key, ok := keys.Key(i)
		if !ok {
			continue
		}
		if _, ok := key.Algorithm(); !ok {
			continue
		}
		thumbprint, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute the response encryption key's thumbprint: %v", err)
		}
		return key, thumbprint, nil
	}
	return nil, nil, fmt.Errorf("client metadata carries no usable response encryption key")
}

// encryptJwe encrypts to exactly the key selectResponseEncryptionKey returned.
// Trying other published keys on failure is deliberately not done: an mdoc's
// deviceAuth has already been signed over a transcript committing to this key's
// thumbprint, so falling back to another key would produce a response the
// verifier can decrypt but whose device signature does not verify.
func encryptJwe(payload map[string]any, key jwk.Key, encSupported []string) (string, error) {
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to serialize payload for the encrypted response: %v", err)
	}

	encAlg, err := pickEncryptionAlgorithm(encSupported)
	if err != nil {
		return "", fmt.Errorf("no supported encryption algorithm: %v", err)
	}

	keyAlg, ok := key.Algorithm()
	if !ok {
		return "", fmt.Errorf("response encryption key has no alg")
	}

	h := jwe.NewHeaders()
	if kid, ok := key.KeyID(); ok && kid != "" {
		h.Set(jwe.KeyIDKey, kid)
	}

	encrypted, err := jwe.Encrypt(
		payloadJson,
		jwe.WithKey(keyAlg, key),
		jwe.WithContentEncryption(encAlg),
		jwe.WithProtectedHeaders(h),
	)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt response: %v", err)
	}
	return string(encrypted), nil
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
