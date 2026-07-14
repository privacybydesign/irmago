package mdoc

import (
	"crypto/x509"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// SHARED TEST HELPERS — used across multiple _test.go files
// ============================================================

// buildHappyPathMDoc runs the full issuer → holder pipeline once and
// returns everything a verifier needs. Centralized here so every test
// below starts from the same known-good, real (not hand-crafted) mdoc.
func buildHappyPathMDoc(t *testing.T) (*Issuer, *Holder, *Verifier, *MDoc, SessionTranscript, []byte, string, string) {
	t.Helper()

	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	holder, err := NewHolder()
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

	mdoc, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	presented, err := SelectiveDisclose(mdoc, namespace, []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	transcript := SessionTranscript{
		DeviceEngagementBytes: []byte("test-engagement"),
		EReaderKeyBytes:       []byte("test-reader-key"),
		Handover:              "test-handover",
	}

	deviceAuthBytes, err := holder.SignDeviceAuth(docType, transcript)
	if err != nil {
		t.Fatalf("SignDeviceAuth: %v", err)
	}

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})

	return issuer, holder, verifier, presented, transcript, deviceAuthBytes, docType, namespace
}

// keysOf is a small debug helper for readable failure messages.
func keysOf(m map[any]any) []any {
	out := make([]any, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// unwrapTag24Generic unwraps one layer of Tag-24 embedded CBOR and returns
// the raw inner bytes, without needing to know the target type — used by
// tests that inspect a Tag24-wrapped value generically (e.g. decoding it
// as a map[string]cbor.RawMessage) rather than into a concrete Go type.
func unwrapTag24Generic(t *testing.T, data []byte) []byte {
	t.Helper()
	var rawTag cbor.RawTag
	if err := cbor.Unmarshal(data, &rawTag); err != nil {
		t.Fatalf("unwrap tag24: %v", err)
	}
	var inner []byte
	if err := cbor.Unmarshal(rawTag.Content, &inner); err != nil {
		t.Fatalf("unwrap tag24 inner bytes: %v", err)
	}
	return inner
}
