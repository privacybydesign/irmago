package openid4vp

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"mdoc"
)

// TestOpenID4VPSessionTranscriptShape confirms the produced SessionTranscript
// CBOR-encodes as [null, null, ["OpenID4VPHandover", digest]] and that the
// digest matches an independently-computed SHA-256(CBOR([clientId, nonce,
// null, responseUri])) — i.e. the exact construction documented on
// NewOpenID4VPSessionTranscript, cross-checked against Multipaz's
// vpSessionTranscript.
func TestOpenID4VPSessionTranscriptShape(t *testing.T) {
	clientId := "redirect_uri:https://verifier.example.com/response"
	nonce := "abc123"
	responseUri := "https://verifier.example.com/response"

	st, err := NewOpenID4VPSessionTranscript(clientId, nonce, responseUri)
	if err != nil {
		t.Fatalf("NewOpenID4VPSessionTranscript: %v", err)
	}

	if st.DeviceEngagementBytes != nil {
		t.Fatalf("expected nil DeviceEngagementBytes, got %v", st.DeviceEngagementBytes)
	}
	if st.EReaderKeyBytes != nil {
		t.Fatalf("expected nil EReaderKeyBytes, got %v", st.EReaderKeyBytes)
	}

	handover, ok := st.Handover.([]any)
	if !ok || len(handover) != 2 {
		t.Fatalf("expected Handover to be a 2-element []any, got %#v", st.Handover)
	}
	handoverType, ok := handover[0].(string)
	if !ok || handoverType != "OpenID4VPHandover" {
		t.Fatalf("expected handover[0] = \"OpenID4VPHandover\", got %#v", handover[0])
	}
	gotDigest, ok := handover[1].([]byte)
	if !ok || len(gotDigest) != 32 {
		t.Fatalf("expected handover[1] to be a 32-byte SHA-256 digest, got %#v", handover[1])
	}

	// Independently recompute HandoverInfo's digest and compare.
	wantInfoBytes, err := cbor.Marshal([]any{clientId, nonce, nil, responseUri})
	if err != nil {
		t.Fatalf("marshal expected handoverInfo: %v", err)
	}
	wantDigest := sha256.Sum256(wantInfoBytes)
	if string(gotDigest) != string(wantDigest[:]) {
		t.Fatalf("digest mismatch: got %x, want %x", gotDigest, wantDigest)
	}

	// The overall SessionTranscript must still round-trip as a 3-element
	// CBOR array, since it embeds the ",toarray" tag like every other
	// SessionTranscript regardless of Handover's shape.
	encoded, err := cbor.Marshal(st)
	if err != nil {
		t.Fatalf("marshal SessionTranscript: %v", err)
	}
	var generic []any
	if err := cbor.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("decode SessionTranscript generic: %v", err)
	}
	if len(generic) != 3 {
		t.Fatalf("expected SessionTranscript to encode as a 3-element array, got %d elements", len(generic))
	}
	if generic[0] != nil || generic[1] != nil {
		t.Fatalf("expected DeviceEngagementBytes/EReaderKeyBytes to encode as null, got %v / %v", generic[0], generic[1])
	}
}

// TestOpenID4VPSessionTranscriptBindsAllInputs confirms clientId, nonce, and
// responseUri each independently affect the resulting digest — if any of
// them didn't, a verifier could accept a deviceAuth signed for a different
// session/client than the one it actually requested.
func TestOpenID4VPSessionTranscriptBindsAllInputs(t *testing.T) {
	base, err := NewOpenID4VPSessionTranscript("client-a", "nonce-a", "https://a.example.com/response")
	if err != nil {
		t.Fatalf("NewOpenID4VPSessionTranscript base: %v", err)
	}
	baseDigest := base.Handover.([]any)[1].([]byte)

	variants := map[string]mdoc.SessionTranscript{}
	variants["clientId"], _ = NewOpenID4VPSessionTranscript("client-b", "nonce-a", "https://a.example.com/response")
	variants["nonce"], _ = NewOpenID4VPSessionTranscript("client-a", "nonce-b", "https://a.example.com/response")
	variants["responseUri"], _ = NewOpenID4VPSessionTranscript("client-a", "nonce-a", "https://b.example.com/response")

	for field, variant := range variants {
		variantDigest := variant.Handover.([]any)[1].([]byte)
		if string(variantDigest) == string(baseDigest) {
			t.Fatalf("changing %s did not change the handover digest — that field isn't actually bound", field)
		}
	}
}

// TestOpenID4VPSessionTranscriptIntegratesWithDeviceAuth confirms a real
// OpenID4VP-shaped SessionTranscript actually plugs into the existing
// SignDeviceAuth/VerifyWithDeviceAuth path — not just that its own shape
// looks right in isolation. Also confirms a verifier deriving the
// transcript from mismatched OpenID4VP request parameters (e.g. the
// wrong nonce) correctly fails deviceAuth verification, since the two
// sides would land on different SHA-256 digests.
func TestOpenID4VPSessionTranscriptIntegratesWithDeviceAuth(t *testing.T) {
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
	credential, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	presented, err := mdoc.SelectiveDisclose(credential, namespace, []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	clientId := "redirect_uri:https://verifier.example.com/response"
	nonce := "abc123"
	responseUri := "https://verifier.example.com/response"
	transcript, err := NewOpenID4VPSessionTranscript(clientId, nonce, responseUri)
	if err != nil {
		t.Fatalf("NewOpenID4VPSessionTranscript: %v", err)
	}

	deviceAuthBytes, err := holder.SignDeviceAuth(docType, transcript)
	if err != nil {
		t.Fatalf("SignDeviceAuth: %v", err)
	}

	verifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)
	if !result.Valid {
		t.Fatalf("expected valid result, got error: %s", result.Error)
	}
	if !result.DeviceAuthValid {
		t.Fatalf("expected valid deviceAuth against the OpenID4VP transcript, got error: %s", result.Error)
	}

	// A verifier that derives its transcript from a different nonce (e.g.
	// it issued one authorization request, the holder responded to
	// another) must NOT accept the same deviceAuth signature.
	wrongTranscript, err := NewOpenID4VPSessionTranscript(clientId, "different-nonce", responseUri)
	if err != nil {
		t.Fatalf("NewOpenID4VPSessionTranscript (wrong nonce): %v", err)
	}
	mismatchResult := verifier.VerifyWithDeviceAuth(presented, namespace, docType, wrongTranscript, deviceAuthBytes)
	if mismatchResult.DeviceAuthValid {
		t.Fatalf("expected deviceAuth to be rejected against a mismatched OpenID4VP transcript, but it was accepted")
	}
}
