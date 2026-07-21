package openid4vci

import (
	"crypto/x509"
	"encoding/json"
	"reflect"
	"testing"

	"mdoc"
)

// TestCredentialRequestMatchesBlueprintWorkedExample confirms
// NewCredentialRequest's JSON output matches Annex A §A.10's worked
// example shape: {"proofs": {"jwt": [...]}}.
func TestCredentialRequestMatchesBlueprintWorkedExample(t *testing.T) {
	req := NewCredentialRequest("proof-jwt-1")

	encoded, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode request generic: %v", err)
	}

	want := map[string]any{
		"proofs": map[string]any{"jwt": []any{"proof-jwt-1"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request shape mismatch:\ngot:  %v\nwant: %v", got, want)
	}
}

// TestCredentialRequestSingleProofRoundTrips confirms SingleProof
// extracts the exact JWT NewCredentialRequest was given.
func TestCredentialRequestSingleProofRoundTrips(t *testing.T) {
	req := NewCredentialRequest("only-proof")

	proof, err := req.SingleProof()
	if err != nil {
		t.Fatalf("SingleProof: %v", err)
	}
	if proof != "only-proof" {
		t.Fatalf("expected proof %q, got %q", "only-proof", proof)
	}
}

// TestCredentialRequestSingleProofRejectsWrongCount confirms SingleProof
// errors on zero or multiple proofs rather than silently picking one.
func TestCredentialRequestSingleProofRejectsWrongCount(t *testing.T) {
	if _, err := NewCredentialRequest().SingleProof(); err == nil {
		t.Fatalf("expected error for zero proofs, got none")
	}
	if _, err := NewCredentialRequest("a", "b").SingleProof(); err == nil {
		t.Fatalf("expected error for multiple proofs, got none")
	}
}

// issueTestMDoc builds a single freshly issued (not yet presented) mdoc,
// for tests in this file that only care about the credential-endpoint
// wire shapes, not the full presentation pipeline.
func issueTestMDoc(t *testing.T) (*mdoc.Issuer, *mdoc.Holder, *mdoc.MDoc) {
	t.Helper()
	issuer, err := mdoc.NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	credential, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1", map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return issuer, holder, credential
}

// TestCredentialResponseRoundTrips confirms NewCredentialResponse +
// SingleCredential is a faithful round trip — the MDoc that comes back
// out matches the original exactly.
func TestCredentialResponseRoundTrips(t *testing.T) {
	_, _, credential := issueTestMDoc(t)

	resp, err := NewCredentialResponse(*credential)
	if err != nil {
		t.Fatalf("NewCredentialResponse: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(resp.Credentials))
	}

	got, err := resp.SingleCredential()
	if err != nil {
		t.Fatalf("SingleCredential: %v", err)
	}
	if !reflect.DeepEqual(got, *credential) {
		t.Fatalf("round-tripped mdoc does not match original")
	}
}

// TestCredentialResponseShape confirms the JSON shape matches Annex A
// §A.10's worked example: {"credentials": [{"credential": "..."}]}.
func TestCredentialResponseShape(t *testing.T) {
	_, _, credential := issueTestMDoc(t)

	resp, err := NewCredentialResponse(*credential)
	if err != nil {
		t.Fatalf("NewCredentialResponse: %v", err)
	}
	encoded, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode response generic: %v", err)
	}
	creds, ok := got["credentials"].([]any)
	if !ok || len(creds) != 1 {
		t.Fatalf("expected credentials array of length 1, got %v", got["credentials"])
	}
	entry, ok := creds[0].(map[string]any)
	if !ok {
		t.Fatalf("expected credential entry to be an object, got %T", creds[0])
	}
	if _, ok := entry["credential"]; !ok {
		t.Fatalf("expected entry to have a credential field, got %v", entry)
	}
}

// TestCredentialResponseSingleCredentialRejectsWrongCount confirms
// SingleCredential errors on zero or multiple credentials.
func TestCredentialResponseSingleCredentialRejectsWrongCount(t *testing.T) {
	empty := CredentialResponse{}
	if _, err := empty.SingleCredential(); err == nil {
		t.Fatalf("expected error for zero credentials, got none")
	}

	_, _, credential := issueTestMDoc(t)
	multi, err := NewCredentialResponse(*credential, *credential)
	if err != nil {
		t.Fatalf("NewCredentialResponse: %v", err)
	}
	if _, err := multi.SingleCredential(); err == nil {
		t.Fatalf("expected error for multiple credentials, got none")
	}
}

// TestIssueFromCredentialRequestIssuesToProvenKey confirms
// IssueFromCredentialRequest verifies the proof of possession and issues
// an mdoc bound to the exact device key the holder proved it controls —
// a real, verifiable mdoc, not a stub.
func TestIssueFromCredentialRequestIssuesToProvenKey(t *testing.T) {
	issuer, err := mdoc.NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}

	const aud = "https://credential-issuer.example.com"
	const nonce = "some-c-nonce"

	proofJWT, err := SignProofOfPossession(holder, aud, nonce)
	if err != nil {
		t.Fatalf("SignProofOfPossession: %v", err)
	}
	req := NewCredentialRequest(proofJWT)

	claims := map[string]any{"age_over_18": true}
	credential, err := IssueFromCredentialRequest(issuer, req, "eu.europa.ec.av.1", "eu.europa.ec.av.1", claims, aud, nonce)
	if err != nil {
		t.Fatalf("IssueFromCredentialRequest: %v", err)
	}

	verifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	result := verifier.Verify(credential, "eu.europa.ec.av.1")
	if !result.Valid {
		t.Fatalf("expected issued mdoc to verify, got: %+v", result)
	}
	if result.Attributes["age_over_18"] != true {
		t.Fatalf("expected age_over_18=true, got %v", result.Attributes["age_over_18"])
	}
}

// TestIssueFromCredentialRequestRejectsInvalidProof confirms a proof
// signed over the wrong nonce is rejected before Issue() is ever called.
func TestIssueFromCredentialRequestRejectsInvalidProof(t *testing.T) {
	issuer, err := mdoc.NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := mdoc.NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}

	proofJWT, err := SignProofOfPossession(holder, "https://credential-issuer.example.com", "wrong-nonce")
	if err != nil {
		t.Fatalf("SignProofOfPossession: %v", err)
	}
	req := NewCredentialRequest(proofJWT)

	claims := map[string]any{"age_over_18": true}
	_, err = IssueFromCredentialRequest(issuer, req, "eu.europa.ec.av.1", "eu.europa.ec.av.1", claims, "https://credential-issuer.example.com", "expected-nonce")
	if err == nil {
		t.Fatalf("expected error for proof signed over wrong nonce, got none")
	}
}
