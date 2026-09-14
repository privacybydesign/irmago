package mdoc_dcql

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
)

// TestOpenID4VPSessionTranscriptShape confirms the produced SessionTranscript
// CBOR-encodes as [null, null, ["OpenID4VPHandover", digest]] and that the
// digest matches an independently-computed SHA-256(CBOR([clientId, nonce,
// null, responseUri])) — i.e. the exact construction documented on
// newOpenID4VPSessionTranscript, cross-checked against Multipaz's
// vpSessionTranscript.
func TestOpenID4VPSessionTranscriptShape(t *testing.T) {
	clientId := "redirect_uri:https://verifier.example.com/response"
	nonce := "abc123"
	responseUri := "https://verifier.example.com/response"

	st, err := newOpenID4VPSessionTranscript(clientId, nonce, responseUri, nil)
	require.NoError(t, err, "newOpenID4VPSessionTranscript: %v", err)

	require.Nil(t, st.DeviceEngagementBytes, "expected nil DeviceEngagementBytes, got %v", st.DeviceEngagementBytes)
	require.Nil(t, st.EReaderKeyBytes, "expected nil EReaderKeyBytes, got %v", st.EReaderKeyBytes)

	handover, ok := st.Handover.([]any)
	require.True(t, ok, "expected Handover to be a 2-element []any, got %#v", st.Handover)
	require.Len(t, handover, 2, "expected Handover to be a 2-element []any, got %#v", st.Handover)

	handoverType, ok := handover[0].(string)
	require.True(t, ok, "expected handover[0] = \"OpenID4VPHandover\", got %#v", handover[0])
	require.Equal(t, "OpenID4VPHandover", handoverType, "expected handover[0] = \"OpenID4VPHandover\", got %#v", handover[0])

	gotDigest, ok := handover[1].([]byte)
	require.True(t, ok, "expected handover[1] to be a 32-byte SHA-256 digest, got %#v", handover[1])
	require.Len(t, gotDigest, 32, "expected handover[1] to be a 32-byte SHA-256 digest, got %#v", handover[1])

	// Independently recompute HandoverInfo's digest and compare.
	wantInfoBytes, err := cbor.Marshal([]any{clientId, nonce, nil, responseUri})
	require.NoError(t, err, "marshal expected handoverInfo: %v", err)
	wantDigest := sha256.Sum256(wantInfoBytes)
	require.Equal(t, wantDigest[:], gotDigest, "digest mismatch: got %x, want %x", gotDigest, wantDigest)

	// The overall SessionTranscript must still round-trip as a 3-element
	// CBOR array, since it embeds the ",toarray" tag like every other
	// SessionTranscript regardless of Handover's shape.
	encoded, err := cbor.Marshal(st)
	require.NoError(t, err, "marshal SessionTranscript: %v", err)
	var generic []any
	err = cbor.Unmarshal(encoded, &generic)
	require.NoError(t, err, "decode SessionTranscript generic: %v", err)
	require.Len(t, generic, 3, "expected SessionTranscript to encode as a 3-element array, got %d elements", len(generic))
	require.Nil(t, generic[0], "expected DeviceEngagementBytes/EReaderKeyBytes to encode as null, got %v / %v", generic[0], generic[1])
	require.Nil(t, generic[1], "expected DeviceEngagementBytes/EReaderKeyBytes to encode as null, got %v / %v", generic[0], generic[1])
}

// TestOpenID4VPSessionTranscriptBindsAllInputs confirms clientId, nonce, and
// responseUri each independently affect the resulting digest — if any of
// them didn't, a verifier could accept a deviceAuth signed for a different
// session/client than the one it actually requested.
func TestOpenID4VPSessionTranscriptBindsAllInputs(t *testing.T) {
	base, err := newOpenID4VPSessionTranscript("client-a", "nonce-a", "https://a.example.com/response", nil)
	require.NoError(t, err, "newOpenID4VPSessionTranscript base: %v", err)
	baseDigest := base.Handover.([]any)[1].([]byte)

	variants := map[string]mdoc.SessionTranscript{}
	variants["clientId"], _ = newOpenID4VPSessionTranscript("client-b", "nonce-a", "https://a.example.com/response", nil)
	variants["nonce"], _ = newOpenID4VPSessionTranscript("client-a", "nonce-b", "https://a.example.com/response", nil)
	variants["responseUri"], _ = newOpenID4VPSessionTranscript("client-a", "nonce-a", "https://b.example.com/response", nil)

	for field, variant := range variants {
		variantDigest := variant.Handover.([]any)[1].([]byte)
		require.NotEqual(t, baseDigest, variantDigest, "changing %s did not change the handover digest — that field isn't actually bound", field)
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
	require.NoError(t, err, "NewIssuer: %v", err)
	holder, err := mdoc.NewHolder()
	require.NoError(t, err, "NewHolder: %v", err)

	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	credential, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": true}, holder.PublicKey())
	require.NoError(t, err, "Issue: %v", err)
	presented, err := mdoc.SelectiveDisclose(credential, namespace, []string{"age_over_18"})
	require.NoError(t, err, "SelectiveDisclose: %v", err)

	clientId := "redirect_uri:https://verifier.example.com/response"
	nonce := "abc123"
	responseUri := "https://verifier.example.com/response"
	transcript, err := newOpenID4VPSessionTranscript(clientId, nonce, responseUri, nil)
	require.NoError(t, err, "newOpenID4VPSessionTranscript: %v", err)

	deviceAuthBytes, err := holder.SignDeviceAuth(docType, transcript)
	require.NoError(t, err, "SignDeviceAuth: %v", err)

	verifier := mdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)
	require.True(t, result.Valid, "expected valid result, got error: %s", result.Error)
	require.True(t, result.DeviceAuthValid, "expected valid deviceAuth against the OpenID4VP transcript, got error: %s", result.Error)

	// A verifier that derives its transcript from a different nonce (e.g.
	// it issued one authorization request, the holder responded to
	// another) must NOT accept the same deviceAuth signature.
	wrongTranscript, err := newOpenID4VPSessionTranscript(clientId, "different-nonce", responseUri, nil)
	require.NoError(t, err, "newOpenID4VPSessionTranscript (wrong nonce): %v", err)
	mismatchResult := verifier.VerifyWithDeviceAuth(presented, namespace, docType, wrongTranscript, deviceAuthBytes)
	require.False(t, mismatchResult.DeviceAuthValid, "expected deviceAuth to be rejected against a mismatched OpenID4VP transcript, but it was accepted")
}

// TestOpenID4VPSessionTranscriptCarriesEncryptionKeyThumbprint pins the
// encrypted-response half of the handover.
//
// The third HandoverInfo element is the SHA-256 JWK thumbprint of the verifier's
// response encryption key, and CBOR null only when the response travels
// unencrypted. Getting this wrong is invisible on the wallet side — the response
// is transmitted and accepted — and shows up at the verifier as a deviceAuth
// signature that does not verify, with nothing to point at the cause. So both
// the value and the fact that it changes the digest are asserted here.
func TestOpenID4VPSessionTranscriptCarriesEncryptionKeyThumbprint(t *testing.T) {
	clientId := "x509_san_dns:verifier.example.com"
	nonce := "abc123"
	responseUri := "https://verifier.example.com/response"
	thumbprint := sha256.Sum256([]byte("response encryption key"))

	encrypted, err := newOpenID4VPSessionTranscript(clientId, nonce, responseUri, thumbprint[:])
	require.NoError(t, err, "newOpenID4VPSessionTranscript: %v", err)

	wantInfoBytes, err := cbor.Marshal([]any{clientId, nonce, thumbprint[:], responseUri})
	require.NoError(t, err, "marshal expected handoverInfo: %v", err)
	wantDigest := sha256.Sum256(wantInfoBytes)

	gotDigest, ok := encrypted.Handover.([]any)[1].([]byte)
	require.True(t, ok, "expected handover[1] to be a digest, got %#v", encrypted.Handover.([]any)[1])
	require.Equal(t, wantDigest[:], gotDigest, "digest mismatch: got %x, want %x", gotDigest, wantDigest)

	// An unencrypted response must not produce the same transcript: a wallet that
	// ignored the thumbprint would still sign something, just not what the
	// verifier reconstructs.
	plain, err := newOpenID4VPSessionTranscript(clientId, nonce, responseUri, nil)
	require.NoError(t, err, "newOpenID4VPSessionTranscript (unencrypted): %v", err)
	plainDigest := plain.Handover.([]any)[1].([]byte)
	require.NotEqual(t, gotDigest, plainDigest, "the encrypted and unencrypted transcripts hash to the same digest; the thumbprint is not reaching the handover")

	// An empty (rather than nil) thumbprint means the same thing as nil — no
	// encryption — and must not encode as a zero-length byte string.
	empty, err := newOpenID4VPSessionTranscript(clientId, nonce, responseUri, []byte{})
	require.NoError(t, err, "newOpenID4VPSessionTranscript (empty thumbprint): %v", err)
	require.Equal(t, plainDigest, empty.Handover.([]any)[1].([]byte), "an empty thumbprint must produce the same transcript as no thumbprint at all")
}

// TestDcApiSessionTranscriptShape is the DC API mirror of
// TestOpenID4VPSessionTranscriptShape: [null, null, ["OpenID4VPDCAPIHandover",
// digest]] where digest is an independently computed SHA-256(CBOR([origin,
// nonce, null])). Three elements, not four — there is no response_uri over this
// transport — and the bare origin rather than a client identifier.
func TestDcApiSessionTranscriptShape(t *testing.T) {
	origin := "https://verifier.example.com"
	nonce := "abc123"

	st, err := newDcApiSessionTranscript(origin, nonce, nil)
	require.NoError(t, err, "newDcApiSessionTranscript: %v", err)

	require.Nil(t, st.DeviceEngagementBytes, "expected both leading elements nil, got %v / %v", st.DeviceEngagementBytes, st.EReaderKeyBytes)
	require.Nil(t, st.EReaderKeyBytes, "expected both leading elements nil, got %v / %v", st.DeviceEngagementBytes, st.EReaderKeyBytes)

	handover, ok := st.Handover.([]any)
	require.True(t, ok, "expected Handover to be a 2-element []any, got %#v", st.Handover)
	require.Len(t, handover, 2, "expected Handover to be a 2-element []any, got %#v", st.Handover)

	handoverType, ok := handover[0].(string)
	require.True(t, ok, "expected handover[0] = \"OpenID4VPDCAPIHandover\", got %#v", handover[0])
	require.Equal(t, "OpenID4VPDCAPIHandover", handoverType, "expected handover[0] = \"OpenID4VPDCAPIHandover\", got %#v", handover[0])

	gotDigest, ok := handover[1].([]byte)
	require.True(t, ok, "expected handover[1] to be a 32-byte SHA-256 digest, got %#v", handover[1])
	require.Len(t, gotDigest, 32, "expected handover[1] to be a 32-byte SHA-256 digest, got %#v", handover[1])

	wantInfoBytes, err := cbor.Marshal([]any{origin, nonce, nil})
	require.NoError(t, err, "marshal expected handoverInfo: %v", err)
	wantDigest := sha256.Sum256(wantInfoBytes)
	require.Equal(t, wantDigest[:], gotDigest, "digest mismatch: got %x, want %x", gotDigest, wantDigest)
}

// TestDcApiSessionTranscriptBindsAllInputs confirms each of the three inputs
// reaches the digest. The thumbprint matters for the same reason as in the URL
// flow: dc_api.jwt encrypts the response, and a wallet that ignored the key it
// encrypted to would sign a handover the verifier cannot reconstruct.
func TestDcApiSessionTranscriptBindsAllInputs(t *testing.T) {
	thumbprint := sha256.Sum256([]byte("response encryption key"))

	base, err := newDcApiSessionTranscript("https://a.example.com", "nonce-a", nil)
	require.NoError(t, err, "newDcApiSessionTranscript base: %v", err)
	baseDigest := base.Handover.([]any)[1].([]byte)

	variants := map[string]mdoc.SessionTranscript{}
	variants["origin"], _ = newDcApiSessionTranscript("https://b.example.com", "nonce-a", nil)
	variants["nonce"], _ = newDcApiSessionTranscript("https://a.example.com", "nonce-b", nil)
	variants["thumbprint"], _ = newDcApiSessionTranscript("https://a.example.com", "nonce-a", thumbprint[:])

	for field, variant := range variants {
		require.NotEqual(t, baseDigest, variant.Handover.([]any)[1].([]byte), "changing %s did not change the handover digest — that field isn't actually bound", field)
	}

	// An empty thumbprint means the same as none, matching the URL flow.
	empty, err := newDcApiSessionTranscript("https://a.example.com", "nonce-a", []byte{})
	require.NoError(t, err, "newDcApiSessionTranscript (empty thumbprint): %v", err)
	require.Equal(t, baseDigest, empty.Handover.([]any)[1].([]byte), "an empty thumbprint must produce the same transcript as no thumbprint at all")
}

// TestSessionTranscriptVariantsNeverCollide is the property that makes picking
// the wrong variant a detectable error rather than a silent one: the same
// session values must not hash to the same handover on both transports. If they
// ever did, a wallet signing the wrong variant would still be accepted, and the
// transport plumbing that selects between them would be untestable.
func TestSessionTranscriptVariantsNeverCollide(t *testing.T) {
	origin := "https://verifier.example.com"
	nonce := "abc123"

	// What the DC API path passes, and what the URL path would make of the same
	// session: an origin-prefixed audience and no response_uri.
	dcApi, err := newDcApiSessionTranscript(origin, nonce, nil)
	require.NoError(t, err, "newDcApiSessionTranscript: %v", err)
	urlFlow, err := newOpenID4VPSessionTranscript("origin:"+origin, nonce, "", nil)
	require.NoError(t, err, "newOpenID4VPSessionTranscript: %v", err)

	require.NotEqual(t, urlFlow.Handover.([]any)[0], dcApi.Handover.([]any)[0], "the two handovers must not share a label")
	require.NotEqual(t, urlFlow.Handover.([]any)[1].([]byte), dcApi.Handover.([]any)[1].([]byte), "the two handovers hashed to the same digest for one session")
}
