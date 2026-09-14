package mdoc

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// ============================================================
// SHARED TEST HELPERS — used across multiple _test.go files
// ============================================================

// buildHappyPathMDoc runs the full issuer → holder pipeline once and
// returns everything a verifier needs. Centralized here so every test
// below starts from the same known-good, real (not hand-crafted) mdoc.
func buildHappyPathMDoc(t *testing.T) (*Issuer, *DefaultHolder, *Verifier, *MDoc, SessionTranscript, []byte, string, string) {
	t.Helper()

	issuer, err := NewIssuer()
	require.NoError(t, err, "NewIssuer: %v", err)

	holder, err := NewHolder()
	require.NoError(t, err, "NewHolder: %v", err)

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"

	claims := map[string]any{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
	}

	mdoc, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
	require.NoError(t, err, "Issue: %v", err)

	presented, err := SelectiveDisclose(mdoc, namespace, []string{"age_over_18"})
	require.NoError(t, err, "SelectiveDisclose: %v", err)

	transcript := SessionTranscript{
		DeviceEngagementBytes: []byte("test-engagement"),
		EReaderKeyBytes:       []byte("test-reader-key"),
		Handover:              "test-handover",
	}

	deviceAuthBytes, err := holder.SignDeviceAuth(docType, transcript)
	require.NoError(t, err, "SignDeviceAuth: %v", err)

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
	err := cbor.Unmarshal(data, &rawTag)
	require.NoError(t, err, "unwrap tag24: %v", err)
	var inner []byte
	err = cbor.Unmarshal(rawTag.Content, &inner)
	require.NoError(t, err, "unwrap tag24 inner bytes: %v", err)
	return inner
}

// sha256Digest is the digest function tests pass to verifyNamespaceDigests, which
// now takes it from the MSO's declared digestAlgorithm rather than assuming it.
// Every fixture in this package declares "SHA-256".
func sha256Digest(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
