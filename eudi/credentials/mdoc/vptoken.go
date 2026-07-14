package mdoc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// VP_TOKEN — how a DeviceResponse actually travels in an OpenID4VP
// response_mode=direct_post response body
//
// Mirrors eudi/openid4vp/response.go's createDirectPostVpToken/
// createVpToken: one JSON object keyed by DCQL credential query id, each
// value an array of serialized credentials. That code builds the same
// shape for SD-JWT-VC credentials (opaque strings); here the serialized
// credential is base64url (no padding) CBOR — the standard OpenID4VP
// mdoc-format encoding for a DeviceResponse.
// ============================================================

// NewVPTokenJSON serializes resp as CBOR, base64url-encodes it, and wraps
// it into the vp_token JSON body under queryId (see
// DCQLQuery.CredentialQueryId).
func NewVPTokenJSON(queryId string, resp DeviceResponse) (string, error) {
	encoded, err := cbor.Marshal(resp)
	if err != nil {
		return "", fmt.Errorf("marshal DeviceResponse: %w", err)
	}
	content := map[string][]string{
		queryId: {base64.RawURLEncoding.EncodeToString(encoded)},
	}
	result, err := json.Marshal(content)
	if err != nil {
		return "", fmt.Errorf("marshal vp_token: %w", err)
	}
	return string(result), nil
}

// ParseVPTokenJSON is the verifier-side inverse of NewVPTokenJSON: decodes
// the first serialized credential under queryId back into a
// DeviceResponse.
func ParseVPTokenJSON(vpToken, queryId string) (DeviceResponse, error) {
	var content map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &content); err != nil {
		return DeviceResponse{}, fmt.Errorf("decode vp_token: %w", err)
	}
	creds, ok := content[queryId]
	if !ok || len(creds) == 0 {
		return DeviceResponse{}, fmt.Errorf("vp_token has no credential for query id %q", queryId)
	}
	encoded, err := base64.RawURLEncoding.DecodeString(creds[0])
	if err != nil {
		return DeviceResponse{}, fmt.Errorf("base64url-decode credential: %w", err)
	}
	var resp DeviceResponse
	if err := cbor.Unmarshal(encoded, &resp); err != nil {
		return DeviceResponse{}, fmt.Errorf("decode DeviceResponse: %w", err)
	}
	return resp, nil
}
