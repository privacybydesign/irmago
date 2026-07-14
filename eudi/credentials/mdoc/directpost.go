package mdoc

import (
	"fmt"
	"net/url"
)

// ============================================================
// DIRECT_POST FORM — the actual HTTP body response_mode=direct_post
// POSTs to response_uri
//
// eudi/openid4vp/response.go's createAuthorizationResponseHttpRequest
// doesn't send vp_token as a bare JSON body — it's one field inside an
// application/x-www-form-urlencoded body, alongside state:
//
//	values.Add("vp_token", vpToken)
//	values.Add("state", config.State)
//
// state is the verifier's own anti-CSRF / session-correlation value (see
// AuthorizationRequest.State in openid4vp.go) — opaque to this package,
// carried through completely unchanged. Unlike nonce, it never enters any
// hash or signature; it exists purely so the verifier's web server can
// tell which pending session an incoming POST answers.
// ============================================================

// NewDirectPostForm builds the application/x-www-form-urlencoded body a
// holder POSTs to response_uri: resp serialized via NewVPTokenJSON under
// queryId, alongside the verifier's own state value echoed back unchanged.
func NewDirectPostForm(queryId, state string, resp DeviceResponse) (string, error) {
	vpToken, err := NewVPTokenJSON(queryId, resp)
	if err != nil {
		return "", fmt.Errorf("build vp_token: %w", err)
	}
	values := url.Values{
		"vp_token": {vpToken},
		"state":    {state},
	}
	return values.Encode(), nil
}

// ParseDirectPostForm is the verifier-side inverse of NewDirectPostForm:
// decodes the form body back into the DeviceResponse under queryId, plus
// the state value the holder echoed back. The caller — not this function —
// is responsible for checking the returned state matches what it
// originally issued before trusting the response; this function only
// decodes, it has no notion of what the "correct" state is.
func ParseDirectPostForm(body, queryId string) (resp DeviceResponse, state string, err error) {
	values, err := url.ParseQuery(body)
	if err != nil {
		return DeviceResponse{}, "", fmt.Errorf("decode form body: %w", err)
	}
	vpToken := values.Get("vp_token")
	if vpToken == "" {
		return DeviceResponse{}, "", fmt.Errorf("form body has no vp_token field")
	}
	resp, err = ParseVPTokenJSON(vpToken, queryId)
	if err != nil {
		return DeviceResponse{}, "", fmt.Errorf("parse vp_token: %w", err)
	}
	return resp, values.Get("state"), nil
}
