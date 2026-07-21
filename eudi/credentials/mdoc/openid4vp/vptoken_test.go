package openid4vp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"mdoc"
)

// buildHappyPathMDoc runs the full issuer -> holder pipeline once via
// mdoc's exported API and returns everything a test in this package
// needs — the local equivalent of mdoc's own (unexported, package-private)
// testhelpers_test.go helper, which can't be shared across packages.
func buildHappyPathMDoc(t *testing.T) (*mdoc.Issuer, *mdoc.Holder, *mdoc.Verifier, *mdoc.MDoc, mdoc.SessionTranscript, []byte, string, string) {
	t.Helper()

	issuer, err := mdoc.NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	claims := map[string]any{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
	}

	credential, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	presented, err := mdoc.SelectiveDisclose(credential, namespace, []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	transcript, err := NewOpenID4VPSessionTranscript(
		"redirect_uri:https://verifier.example.com/response",
		"n-0S6_WzA2Mj",
		"https://verifier.example.com/response",
	)
	if err != nil {
		t.Fatalf("NewOpenID4VPSessionTranscript: %v", err)
	}

	deviceAuthBytes, err := holder.SignDeviceAuth(docType, transcript)
	if err != nil {
		t.Fatalf("SignDeviceAuth: %v", err)
	}

	verifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})

	return issuer, holder, verifier, presented, transcript, deviceAuthBytes, docType, namespace
}

// TestVPTokenRoundTrips confirms NewVPTokenJSON + ParseVPTokenJSON is a
// faithful round trip: the DeviceResponse that comes back out verifies
// exactly the same way the original one would have.
func TestVPTokenRoundTrips(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	attached, err := mdoc.AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := mdoc.NewDeviceResponse(*attached)

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

	attached, err := mdoc.AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := mdoc.NewDeviceResponse(*attached)

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
	var decodedResp mdoc.DeviceResponse
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
	attached, err := mdoc.AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := mdoc.NewDeviceResponse(*attached)

	vpToken, err := NewVPTokenJSON("proof_of_age", resp)
	if err != nil {
		t.Fatalf("NewVPTokenJSON: %v", err)
	}

	if _, err := ParseVPTokenJSON(vpToken, "some_other_query_id"); err == nil {
		t.Fatalf("expected error for unknown query id, got none")
	}
}
