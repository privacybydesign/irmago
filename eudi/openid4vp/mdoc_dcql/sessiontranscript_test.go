package mdoc_dcql

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/fxamacker/cbor/v2"

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
	if err != nil {
		t.Fatalf("newOpenID4VPSessionTranscript: %v", err)
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
	base, err := newOpenID4VPSessionTranscript("client-a", "nonce-a", "https://a.example.com/response", nil)
	if err != nil {
		t.Fatalf("newOpenID4VPSessionTranscript base: %v", err)
	}
	baseDigest := base.Handover.([]any)[1].([]byte)

	variants := map[string]mdoc.SessionTranscript{}
	variants["clientId"], _ = newOpenID4VPSessionTranscript("client-b", "nonce-a", "https://a.example.com/response", nil)
	variants["nonce"], _ = newOpenID4VPSessionTranscript("client-a", "nonce-b", "https://a.example.com/response", nil)
	variants["responseUri"], _ = newOpenID4VPSessionTranscript("client-a", "nonce-a", "https://b.example.com/response", nil)

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
	transcript, err := newOpenID4VPSessionTranscript(clientId, nonce, responseUri, nil)
	if err != nil {
		t.Fatalf("newOpenID4VPSessionTranscript: %v", err)
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
	wrongTranscript, err := newOpenID4VPSessionTranscript(clientId, "different-nonce", responseUri, nil)
	if err != nil {
		t.Fatalf("newOpenID4VPSessionTranscript (wrong nonce): %v", err)
	}
	mismatchResult := verifier.VerifyWithDeviceAuth(presented, namespace, docType, wrongTranscript, deviceAuthBytes)
	if mismatchResult.DeviceAuthValid {
		t.Fatalf("expected deviceAuth to be rejected against a mismatched OpenID4VP transcript, but it was accepted")
	}
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
	if err != nil {
		t.Fatalf("newOpenID4VPSessionTranscript: %v", err)
	}

	wantInfoBytes, err := cbor.Marshal([]any{clientId, nonce, thumbprint[:], responseUri})
	if err != nil {
		t.Fatalf("marshal expected handoverInfo: %v", err)
	}
	wantDigest := sha256.Sum256(wantInfoBytes)

	gotDigest, ok := encrypted.Handover.([]any)[1].([]byte)
	if !ok {
		t.Fatalf("expected handover[1] to be a digest, got %#v", encrypted.Handover.([]any)[1])
	}
	if string(gotDigest) != string(wantDigest[:]) {
		t.Fatalf("digest mismatch: got %x, want %x", gotDigest, wantDigest)
	}

	// An unencrypted response must not produce the same transcript: a wallet that
	// ignored the thumbprint would still sign something, just not what the
	// verifier reconstructs.
	plain, err := newOpenID4VPSessionTranscript(clientId, nonce, responseUri, nil)
	if err != nil {
		t.Fatalf("newOpenID4VPSessionTranscript (unencrypted): %v", err)
	}
	plainDigest := plain.Handover.([]any)[1].([]byte)
	if string(plainDigest) == string(gotDigest) {
		t.Fatal("the encrypted and unencrypted transcripts hash to the same digest; the thumbprint is not reaching the handover")
	}

	// An empty (rather than nil) thumbprint means the same thing as nil — no
	// encryption — and must not encode as a zero-length byte string.
	empty, err := newOpenID4VPSessionTranscript(clientId, nonce, responseUri, []byte{})
	if err != nil {
		t.Fatalf("newOpenID4VPSessionTranscript (empty thumbprint): %v", err)
	}
	if string(empty.Handover.([]any)[1].([]byte)) != string(plainDigest) {
		t.Fatal("an empty thumbprint must produce the same transcript as no thumbprint at all")
	}
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
	if err != nil {
		t.Fatalf("newDcApiSessionTranscript: %v", err)
	}

	if st.DeviceEngagementBytes != nil || st.EReaderKeyBytes != nil {
		t.Fatalf("expected both leading elements nil, got %v / %v", st.DeviceEngagementBytes, st.EReaderKeyBytes)
	}

	handover, ok := st.Handover.([]any)
	if !ok || len(handover) != 2 {
		t.Fatalf("expected Handover to be a 2-element []any, got %#v", st.Handover)
	}
	if handoverType, ok := handover[0].(string); !ok || handoverType != "OpenID4VPDCAPIHandover" {
		t.Fatalf("expected handover[0] = \"OpenID4VPDCAPIHandover\", got %#v", handover[0])
	}
	gotDigest, ok := handover[1].([]byte)
	if !ok || len(gotDigest) != 32 {
		t.Fatalf("expected handover[1] to be a 32-byte SHA-256 digest, got %#v", handover[1])
	}

	wantInfoBytes, err := cbor.Marshal([]any{origin, nonce, nil})
	if err != nil {
		t.Fatalf("marshal expected handoverInfo: %v", err)
	}
	wantDigest := sha256.Sum256(wantInfoBytes)
	if string(gotDigest) != string(wantDigest[:]) {
		t.Fatalf("digest mismatch: got %x, want %x", gotDigest, wantDigest)
	}
}

// TestDcApiSessionTranscriptBindsAllInputs confirms each of the three inputs
// reaches the digest. The thumbprint matters for the same reason as in the URL
// flow: dc_api.jwt encrypts the response, and a wallet that ignored the key it
// encrypted to would sign a handover the verifier cannot reconstruct.
func TestDcApiSessionTranscriptBindsAllInputs(t *testing.T) {
	thumbprint := sha256.Sum256([]byte("response encryption key"))

	base, err := newDcApiSessionTranscript("https://a.example.com", "nonce-a", nil)
	if err != nil {
		t.Fatalf("newDcApiSessionTranscript base: %v", err)
	}
	baseDigest := base.Handover.([]any)[1].([]byte)

	variants := map[string]mdoc.SessionTranscript{}
	variants["origin"], _ = newDcApiSessionTranscript("https://b.example.com", "nonce-a", nil)
	variants["nonce"], _ = newDcApiSessionTranscript("https://a.example.com", "nonce-b", nil)
	variants["thumbprint"], _ = newDcApiSessionTranscript("https://a.example.com", "nonce-a", thumbprint[:])

	for field, variant := range variants {
		if string(variant.Handover.([]any)[1].([]byte)) == string(baseDigest) {
			t.Fatalf("changing %s did not change the handover digest — that field isn't actually bound", field)
		}
	}

	// An empty thumbprint means the same as none, matching the URL flow.
	empty, err := newDcApiSessionTranscript("https://a.example.com", "nonce-a", []byte{})
	if err != nil {
		t.Fatalf("newDcApiSessionTranscript (empty thumbprint): %v", err)
	}
	if string(empty.Handover.([]any)[1].([]byte)) != string(baseDigest) {
		t.Fatal("an empty thumbprint must produce the same transcript as no thumbprint at all")
	}
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
	if err != nil {
		t.Fatalf("newDcApiSessionTranscript: %v", err)
	}
	urlFlow, err := newOpenID4VPSessionTranscript("origin:"+origin, nonce, "", nil)
	if err != nil {
		t.Fatalf("newOpenID4VPSessionTranscript: %v", err)
	}

	if dcApi.Handover.([]any)[0] == urlFlow.Handover.([]any)[0] {
		t.Fatal("the two handovers must not share a label")
	}
	if string(dcApi.Handover.([]any)[1].([]byte)) == string(urlFlow.Handover.([]any)[1].([]byte)) {
		t.Fatal("the two handovers hashed to the same digest for one session")
	}
}
