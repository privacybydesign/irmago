package openid4vci

import (
	"encoding/json"
	"net/url"
	"reflect"
	"testing"
)

// TestNewTokenResponseMatchesBlueprintWorkedExample confirms
// NewTokenResponse's JSON output matches the exact shape shown in the AV
// Blueprint's Annex A §A.10 worked example — access_token, token_type,
// expires_in only. No c_nonce: see nonceendpoint.go.
func TestNewTokenResponseMatchesBlueprintWorkedExample(t *testing.T) {
	resp := NewTokenResponse("czZCaGRSa3F0MzpnWDFmQmF0M2JW", 86400)

	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal token response: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode token response generic: %v", err)
	}

	const want = `{
		"access_token": "czZCaGRSa3F0MzpnWDFmQmF0M2JW",
		"token_type": "Bearer",
		"expires_in": 86400
	}`
	var wantGeneric map[string]any
	if err := json.Unmarshal([]byte(want), &wantGeneric); err != nil {
		t.Fatalf("decode want generic: %v", err)
	}

	if !reflect.DeepEqual(got, wantGeneric) {
		t.Fatalf("token response shape mismatch:\ngot:  %s\nwant: %s", encoded, want)
	}
}

// TestNewPreAuthorizedTokenRequestMatchesBlueprintWorkedExample confirms
// NewPreAuthorizedTokenRequest's form body matches Annex A §A.10's worked
// example field-for-field.
func TestNewPreAuthorizedTokenRequestMatchesBlueprintWorkedExample(t *testing.T) {
	body := NewPreAuthorizedTokenRequest("SplxlOBeZQQYbYS6WxSbIA", "493536")

	got, err := url.ParseQuery(body)
	if err != nil {
		t.Fatalf("parse form body: %v", err)
	}

	want := url.Values{
		"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"scope":               {"proof_of_age"},
		"pre-authorized_code": {"SplxlOBeZQQYbYS6WxSbIA"},
		"tx_code":             {"493536"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("form body mismatch:\ngot:  %v\nwant: %v", got, want)
	}
}

// TestPreAuthorizedTokenRequestRoundTrips confirms a request built by
// NewPreAuthorizedTokenRequest decodes back to the exact pre-authorized_code
// and tx_code it was given.
func TestPreAuthorizedTokenRequestRoundTrips(t *testing.T) {
	body := NewPreAuthorizedTokenRequest("some-code-123", "9999")

	code, txCode, err := ParsePreAuthorizedTokenRequest(body)
	if err != nil {
		t.Fatalf("ParsePreAuthorizedTokenRequest: %v", err)
	}
	if code != "some-code-123" {
		t.Fatalf("expected pre-authorized_code %q, got %q", "some-code-123", code)
	}
	if txCode != "9999" {
		t.Fatalf("expected tx_code %q, got %q", "9999", txCode)
	}
}

// TestParsePreAuthorizedTokenRequestRejectsWrongGrantType confirms a form
// body with a different (or missing) grant_type is rejected rather than
// silently accepted.
func TestParsePreAuthorizedTokenRequestRejectsWrongGrantType(t *testing.T) {
	values := url.Values{
		"grant_type":          {"authorization_code"},
		"pre-authorized_code": {"some-code"},
		"tx_code":             {"1234"},
	}
	if _, _, err := ParsePreAuthorizedTokenRequest(values.Encode()); err == nil {
		t.Fatalf("expected error for wrong grant_type, got none")
	}
}

// TestParsePreAuthorizedTokenRequestRejectsMissingCode confirms a form
// body with the correct grant_type but no pre-authorized_code field is
// rejected rather than returning an empty code.
func TestParsePreAuthorizedTokenRequestRejectsMissingCode(t *testing.T) {
	values := url.Values{
		"grant_type": {preAuthorizedCodeGrantType},
		"tx_code":    {"1234"},
	}
	if _, _, err := ParsePreAuthorizedTokenRequest(values.Encode()); err == nil {
		t.Fatalf("expected error for missing pre-authorized_code, got none")
	}
}

// TestNewAccessTokenIsRandomAndOpaque confirms NewAccessToken produces
// distinct, non-empty values across calls.
func TestNewAccessTokenIsRandomAndOpaque(t *testing.T) {
	a, err := NewAccessToken()
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}
	b, err := NewAccessToken()
	if err != nil {
		t.Fatalf("NewAccessToken: %v", err)
	}
	if a == "" || b == "" {
		t.Fatalf("expected non-empty tokens, got %q and %q", a, b)
	}
	if a == b {
		t.Fatalf("expected two distinct access tokens, got the same value twice: %q", a)
	}
}
