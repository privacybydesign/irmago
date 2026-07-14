package mdoc

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestVPTokenRoundTrips confirms NewVPTokenJSON + ParseVPTokenJSON is a
// faithful round trip: the DeviceResponse that comes back out verifies
// exactly the same way the original one would have.
func TestVPTokenRoundTrips(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := NewDeviceResponse(*attached)

	queryId := "proof_of_age"
	vpToken, err := NewVPTokenJSON(queryId, resp)
	if err != nil {
		t.Fatalf("NewVPTokenJSON: %v", err)
	}

	gotResp, err := ParseVPTokenJSON(vpToken, queryId)
	if err != nil {
		t.Fatalf("ParseVPTokenJSON: %v", err)
	}

	results, err := verifier.VerifyDeviceResponse(gotResp, namespace, docType, transcript)
	if err != nil {
		t.Fatalf("VerifyDeviceResponse: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Valid {
		t.Fatalf("expected valid result, got error: %s", results[0].Error)
	}
	if !results[0].DeviceAuthValid {
		t.Fatalf("expected valid deviceAuth, got error: %s", results[0].Error)
	}
}

// TestVPTokenShape confirms the vp_token JSON is shaped exactly the way
// OpenID4VP's response_mode=direct_post expects: a JSON object keyed by
// the DCQL credential query id, whose value is an array of base64url (no
// padding) CBOR-encoded credentials — mirroring
// eudi/openid4vp/response.go's createDirectPostVpToken shape.
func TestVPTokenShape(t *testing.T) {
	_, _, _, presented, _, deviceAuthBytes, _, _ := buildHappyPathMDoc(t)

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := NewDeviceResponse(*attached)

	queryId := "proof_of_age"
	vpToken, err := NewVPTokenJSON(queryId, resp)
	if err != nil {
		t.Fatalf("NewVPTokenJSON: %v", err)
	}

	var generic map[string][]string
	if err := json.Unmarshal([]byte(vpToken), &generic); err != nil {
		t.Fatalf("decode vp_token generic: %v", err)
	}
	creds, ok := generic[queryId]
	if !ok || len(creds) != 1 {
		t.Fatalf("expected exactly 1 credential under key %q, got %v", queryId, generic)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(creds[0])
	if err != nil {
		t.Fatalf("credential is not valid base64url (no padding): %v", err)
	}
	var decodedResp DeviceResponse
	if err := cbor.Unmarshal(decoded, &decodedResp); err != nil {
		t.Fatalf("decoded credential is not valid CBOR DeviceResponse: %v", err)
	}
	if len(decodedResp.Documents) != 1 {
		t.Fatalf("expected 1 document, got %d", len(decodedResp.Documents))
	}
}

// TestVPTokenRejectsUnknownQueryId confirms ParseVPTokenJSON errors out
// when asked for a query id the vp_token has no credential for, rather
// than silently returning a zero-value DeviceResponse.
func TestVPTokenRejectsUnknownQueryId(t *testing.T) {
	_, _, _, presented, _, deviceAuthBytes, _, _ := buildHappyPathMDoc(t)
	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := NewDeviceResponse(*attached)

	vpToken, err := NewVPTokenJSON("proof_of_age", resp)
	if err != nil {
		t.Fatalf("NewVPTokenJSON: %v", err)
	}

	if _, err := ParseVPTokenJSON(vpToken, "some_other_query_id"); err == nil {
		t.Fatalf("expected error for unknown query id, got none")
	}
}
