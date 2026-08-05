package mdoc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// Every test for Verifier lives in this file, grouped by what it holds the
// verifier to: the issuance-time entry point, the presentation-time negative
// cases, validity windows, the certificate's authorization to sign at all, the
// binding between the envelope and the signed docType, and device
// authentication. Encoding-level tests live in wireformat_test.go and
// interop_vector_test.go instead, since those pin the wire shape rather than
// verification behaviour.
//
// Shared fixtures: buildHappyPathMDoc (testhelpers_test.go) issues, discloses
// and device-signs one document; the helpers immediately below cover the two
// cases it cannot, namely a hand-built certificate chain and a deviceAuth
// signature over something other than the default empty namespaces.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// issueWithDSEKU builds an IACA→DS chain where the DS certificate carries
// exactly the given extended key usages, signs a minimal MSO with it, and
// returns an mdoc plus a verifier trusting the IACA root.
func issueWithDSEKU(t *testing.T, eku []x509.ExtKeyUsage, unknownEKU []asn1.ObjectIdentifier) (*MDoc, *Verifier) {
	t.Helper()

	iacaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate IACA key: %v", err)
	}
	iacaTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test IACA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	iacaDER, err := x509.CreateCertificate(rand.Reader, iacaTemplate, iacaTemplate, &iacaKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatalf("create IACA cert: %v", err)
	}
	iacaCert, err := x509.ParseCertificate(iacaDER)
	if err != nil {
		t.Fatalf("parse IACA cert: %v", err)
	}

	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate DS key: %v", err)
	}
	dsTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test DS"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           eku,
		UnknownExtKeyUsage:    unknownEKU,
	}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTemplate, iacaCert, &dsKey.PublicKey, iacaKey)
	if err != nil {
		t.Fatalf("create DS cert: %v", err)
	}
	dsCert, err := x509.ParseCertificate(dsDER)
	if err != nil {
		t.Fatalf("parse DS cert: %v", err)
	}

	// Minimal signed MSO — only the chain is under test, so a single claim in
	// one namespace is enough for verifyIssuerAuthAndMSO to run end to end.
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	deviceKey, err := coseKeyFromECDSA(holder.PublicKey())
	if err != nil {
		t.Fatalf("coseKeyFromECDSA: %v", err)
	}
	const docType = "eu.europa.ec.av.1"
	item := IssuerSignedItem{DigestID: 0, Random: make([]byte, 16), ElementIdentifier: "age_over_18", ElementValue: true}
	digest, err := hashTag24Item(item)
	if err != nil {
		t.Fatalf("hashTag24Item: %v", err)
	}
	now := time.Now().UTC()
	mso := MSO{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[uint64][]byte{docType: {0: digest}},
		DocType:         docType,
		ValidityInfo:    ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(24 * time.Hour)},
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKey},
	}
	msoBytes, err := tag24WrapWithMode(mso, avTimeEncMode)
	if err != nil {
		t.Fatalf("wrap mso: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, dsKey)
	if err != nil {
		t.Fatalf("cose.NewSigner: %v", err)
	}
	msg := cose.NewSign1Message()
	msg.Payload = msoBytes
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Unprotected[int64(33)] = [][]byte{dsCert.Raw, iacaCert.Raw}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign mso: %v", err)
	}
	coseBytes, err := cbor.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal cose: %v", err)
	}
	wrapped, err := tag24Wrap(item)
	if err != nil {
		t.Fatalf("wrap item: %v", err)
	}

	doc := &MDoc{
		DocType: docType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{docType: {{EncodedItem: wrapped}}},
			IssuerAuth: coseBytes,
		},
	}
	return doc, NewVerifier([]*x509.Certificate{iacaCert})
}

// signDeviceAuthOver is Holder.SignDeviceAuth with the deviceNameSpaces element
// under the test's control instead of hardcoded to tag24(empty map). Everything
// else — the tag-24 wrapping, ES256, the untagged COSE_Sign1, the detached
// payload — is kept identical, since the point is to vary one input.
func signDeviceAuthOver(t *testing.T, h *Holder, docType string, transcript SessionTranscript, deviceNameSpaces []byte) []byte {
	t.Helper()

	payload, err := tag24Wrap(DeviceAuthentication{
		Context:           "DeviceAuthentication",
		SessionTranscript: transcript,
		DocType:           docType,
		DeviceNameSpaces:  cbor.RawMessage(deviceNameSpaces),
	})
	if err != nil {
		t.Fatalf("wrap deviceAuthentication: %v", err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, h.devicekey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers}
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign deviceAuth: %v", err)
	}
	msg.Payload = nil // detached on the wire, as SignDeviceAuth does

	encoded, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal deviceAuth: %v", err)
	}
	return encoded
}

// withDeviceSigned assembles the DeviceSigned envelope by hand, so the
// transmitted nameSpaces can differ from what AttachDeviceSigned would put there.
func withDeviceSigned(presented *MDoc, nameSpaces, deviceAuthBytes []byte) *MDoc {
	attached := *presented
	attached.DeviceSigned = &DeviceSigned{
		NameSpaces: cbor.RawMessage(nameSpaces),
		DeviceAuth: DeviceAuth{DeviceSignature: cbor.RawMessage(deviceAuthBytes)},
	}
	return &attached
}

// ---------------------------------------------------------------------------
// Issuance-time verification (VerifyAllDisclosedNamespaces) and result fields
// ---------------------------------------------------------------------------

// TestVerifyAllDisclosedNamespaces_HappyPath verifies a freshly issued (not
// yet selectively disclosed) mdoc across every namespace it carries — the
// issuance-time verification shape, unlike Verify's single-namespace
// presentation-time shape.
func TestVerifyAllDisclosedNamespaces_HappyPath(t *testing.T) {
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
	claims := map[string]any{"age_over_18": true, "age_over_16": true}

	issued, err := issuer.Issue(docType, namespace, claims, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	resolved, result := verifier.VerifyAllDisclosedNamespaces(issued)
	if !result.Valid {
		t.Fatalf("expected valid result, got error: %s", result.Error)
	}
	if result.DocType != docType {
		t.Fatalf("expected DocType %q, got %q", docType, result.DocType)
	}

	nsAttrs, ok := resolved[namespace]
	if !ok {
		t.Fatalf("expected namespace %q in resolved claims, got %v", namespace, resolved)
	}
	if nsAttrs["age_over_18"] != true || nsAttrs["age_over_16"] != true {
		t.Fatalf("expected both claims resolved, got %v", nsAttrs)
	}
}

// TestVerifyAllDisclosedNamespaces_TamperedDigestIsRejected mirrors
// TestTamperedDigestIsRejected for the multi-namespace entry point.
func TestVerifyAllDisclosedNamespaces_TamperedDigestIsRejected(t *testing.T) {
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
	issued, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tamperedItem := IssuerSignedItem{
		DigestID:          0,
		Random:            []byte("attacker-does-not-know-real-salt"),
		ElementIdentifier: "age_over_18",
		ElementValue:      false, // flipped from true
	}
	tamperedWrapped, err := tag24Wrap(tamperedItem)
	if err != nil {
		t.Fatalf("tag24Wrap: %v", err)
	}
	tamperedMDoc := &MDoc{
		DocType: issued.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: {{EncodedItem: tamperedWrapped}}},
			IssuerAuth: issued.IssuerSigned.IssuerAuth,
		},
	}

	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	_, result := verifier.VerifyAllDisclosedNamespaces(tamperedMDoc)
	if result.Valid {
		t.Fatalf("expected tampered claim to be rejected, but it was accepted")
	}
}

// TestVerify_PopulatesDeviceKeyAndValidityInfo confirms the new
// VerificationResult fields are populated on a successful Verify, and that
// DeviceKey matches the holder's actual public key embedded at issuance.
func TestVerify_PopulatesDeviceKeyAndValidityInfo(t *testing.T) {
	issuer, holder, verifier, presented, _, _, _, namespace := buildHappyPathMDoc(t)

	result := verifier.Verify(presented, namespace)
	if !result.Valid {
		t.Fatalf("expected valid result, got error: %s", result.Error)
	}

	if result.DeviceKey == nil {
		t.Fatalf("expected DeviceKey to be populated")
	}
	if !result.DeviceKey.Equal(holder.PublicKey()) {
		t.Fatalf("expected DeviceKey to match holder's public key")
	}

	if result.ValidityInfo.ValidFrom.IsZero() || result.ValidityInfo.ValidUntil.IsZero() {
		t.Fatalf("expected ValidityInfo to be populated, got %+v", result.ValidityInfo)
	}

	_ = issuer
}

// TestNewVerifierFromPool confirms NewVerifierFromPool behaves identically
// to NewVerifier when given an equivalent trust-root pool.
func TestNewVerifierFromPool(t *testing.T) {
	issuer, _, _, presented, _, _, _, namespace := buildHappyPathMDoc(t)

	pool := x509.NewCertPool()
	pool.AddCert(issuer.IACACert())
	verifier := NewVerifierFromPool(pool)

	result := verifier.Verify(presented, namespace)
	if !result.Valid {
		t.Fatalf("expected valid result, got error: %s", result.Error)
	}
}

// ---------------------------------------------------------------------------
// NEGATIVE CASES — these must all FAIL verification
// ---------------------------------------------------------------------------

func TestUntrustedRootIsRejected(t *testing.T) {
	_, _, verifier, _, _, _, docType, namespace := buildHappyPathMDoc(t)

	attackerIssuer, _ := NewIssuer()
	attackerHolder, _ := NewHolder()
	attackerMDoc, err := attackerIssuer.Issue(docType, namespace,
		map[string]any{"age_over_18": true}, attackerHolder.PublicKey())
	if err != nil {
		t.Fatalf("attacker Issue: %v", err)
	}
	attackerPresented, err := SelectiveDisclose(attackerMDoc, namespace, []string{"age_over_18"})
	if err != nil {
		t.Fatalf("attacker SelectiveDisclose: %v", err)
	}

	result := verifier.Verify(attackerPresented, namespace)
	if result.Valid {
		t.Fatalf("expected attacker mdoc (untrusted root) to be rejected, but it was accepted")
	}
}

func TestTamperedDigestIsRejected(t *testing.T) {
	_, _, verifier, presented, _, _, _, namespace := buildHappyPathMDoc(t)

	tamperedItem := IssuerSignedItem{
		DigestID:          0,
		Random:            []byte("attacker-does-not-know-real-salt"),
		ElementIdentifier: "age_over_18",
		ElementValue:      false, // flipped from true
	}
	tamperedWrapped, err := tag24Wrap(tamperedItem)
	if err != nil {
		t.Fatalf("tag24Wrap: %v", err)
	}
	tamperedMDoc := &MDoc{
		DocType: presented.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: {{EncodedItem: tamperedWrapped}}},
			IssuerAuth: presented.IssuerSigned.IssuerAuth,
		},
	}

	result := verifier.Verify(tamperedMDoc, namespace)
	if result.Valid {
		t.Fatalf("expected tampered claim to be rejected, but it was accepted")
	}
}

func TestUnknownDigestIDIsRejected(t *testing.T) {
	_, _, verifier, presented, _, _, _, namespace := buildHappyPathMDoc(t)

	// Same value/salt shape as a real item, but digestID 999 doesn't
	// exist in the MSO's valueDigests map at all.
	bogusItem := IssuerSignedItem{
		DigestID:          999,
		Random:            bytes.Repeat([]byte{0x01}, 16),
		ElementIdentifier: "age_over_18",
		ElementValue:      true,
	}
	bogusWrapped, err := tag24Wrap(bogusItem)
	if err != nil {
		t.Fatalf("tag24Wrap: %v", err)
	}
	bogusMDoc := &MDoc{
		DocType: presented.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: {{EncodedItem: bogusWrapped}}},
			IssuerAuth: presented.IssuerSigned.IssuerAuth,
		},
	}

	result := verifier.Verify(bogusMDoc, namespace)
	if result.Valid {
		t.Fatalf("expected unknown digestID to be rejected, but it was accepted")
	}
}

// ---------------------------------------------------------------------------
// Validity windows — the X.509 chain's and the MSO's own, checked separately
// ---------------------------------------------------------------------------

// TestFreshCertsVerifyUnderCurrentTime is a sanity check that chain
// verification's CurrentTime handling isn't broken by an off-by-one in
// NotBefore/NotAfter arithmetic — i.e. that a cert issued "now" with a
// 1-year validity window actually verifies "now".
func TestFreshCertsVerifyUnderCurrentTime(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})

	holder, _ := NewHolder()
	mdoc, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	presented, err := SelectiveDisclose(mdoc, "eu.europa.ec.av.1", []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	result := verifier.Verify(presented, "eu.europa.ec.av.1")
	if !result.Valid {
		t.Fatalf("expected freshly issued DS cert to be valid under current time, got: %s", result.Error)
	}
}

// TestExpiredDSCertIsRejected uses NewVerifierWithClock to pin the
// verifier's notion of "now" to a point roughly 400 days in the future —
// past the DS cert's 1-year (365 day) validity window — and checks the
// chain is correctly rejected as expired. This exercises the actual
// expiry-rejection path, unlike the sanity check above.
func TestExpiredDSCertIsRejected(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	holder, _ := NewHolder()
	mdoc, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	presented, err := SelectiveDisclose(mdoc, "eu.europa.ec.av.1", []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	futureClock := time.Now().Add(400 * 24 * time.Hour) // past the DS cert's 365-day NotAfter
	verifier := NewVerifierWithClock([]*x509.Certificate{issuer.IACACert()}, futureClock)

	result := verifier.Verify(presented, "eu.europa.ec.av.1")
	if result.Valid {
		t.Fatalf("expected DS cert to be rejected as expired when checked 400 days in the future, but it was accepted")
	}
	t.Logf("correctly rejected expired chain: %s", result.Error)
}

// TestExpiredMSOValidityIsRejected uses the verifier's clock to check the
// MSO's OWN validUntil (90 days from issuance per Issuer.Issue), separately
// from the X.509 DS cert's 365-day expiry. A clock ~100 days out is past the
// MSO's window but still well within the DS cert's — this specifically
// exercises the mso.ValidityInfo check, not the certificate chain check.
func TestExpiredMSOValidityIsRejected(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, _ := NewHolder()
	mdoc, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	presented, err := SelectiveDisclose(mdoc, "eu.europa.ec.av.1", []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	futureClock := time.Now().Add(100 * 24 * time.Hour) // past MSO's 90-day validUntil, well within DS cert's 365-day window
	verifier := NewVerifierWithClock([]*x509.Certificate{issuer.IACACert()}, futureClock)

	result := verifier.Verify(presented, "eu.europa.ec.av.1")
	if result.Valid {
		t.Fatalf("expected credential to be rejected as expired per MSO validityInfo, but it was accepted")
	}
	if !strings.HasPrefix(result.Error, "credential expired") {
		t.Fatalf("expected the MSO validityInfo check specifically to fail, got a different error: %s", result.Error)
	}
	t.Logf("correctly rejected on MSO validityInfo: %s", result.Error)
}

// TestNotYetValidMSOIsRejected mirrors the above but checks the ValidFrom
// side. The clock is pinned to 2 minutes before "now" — AFTER the certs'
// backdated NotBefore (-5 minutes, see Issuer cert templates) so the X.509
// chain check passes, but BEFORE the MSO's validFrom (~"now", set in
// Issue()) so only the MSO validityInfo check can fail. Asserts on the
// specific "credential not yet valid" prefix so this can't pass for the
// wrong reason (e.g. coincidentally matching the cert-chain error text).
func TestNotYetValidMSOIsRejected(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, _ := NewHolder()
	mdoc, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	presented, err := SelectiveDisclose(mdoc, "eu.europa.ec.av.1", []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	pastClock := time.Now().Add(-2 * time.Minute) // after cert NotBefore (-5min), before MSO validFrom (~now)
	verifier := NewVerifierWithClock([]*x509.Certificate{issuer.IACACert()}, pastClock)

	result := verifier.Verify(presented, "eu.europa.ec.av.1")
	if result.Valid {
		t.Fatalf("expected credential to be rejected as not-yet-valid per MSO validityInfo, but it was accepted")
	}
	if !strings.HasPrefix(result.Error, "credential not yet valid") {
		t.Fatalf("expected the MSO validityInfo check specifically to fail, got a different error (chain check probably fired first): %s", result.Error)
	}
	t.Logf("correctly rejected on MSO validityInfo: %s", result.Error)
}

// TestNotYetValidCertIsRejected pins the verifier's clock to a point
// BEFORE the certs' NotBefore (i.e. before issuance), which should also
// fail chain verification.
func TestNotYetValidCertIsRejected(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	holder, _ := NewHolder()
	mdoc, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	presented, err := SelectiveDisclose(mdoc, "eu.europa.ec.av.1", []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	pastClock := time.Now().Add(-24 * time.Hour) // before NotBefore
	verifier := NewVerifierWithClock([]*x509.Certificate{issuer.IACACert()}, pastClock)

	result := verifier.Verify(presented, "eu.europa.ec.av.1")
	if result.Valid {
		t.Fatalf("expected DS cert to be rejected as not-yet-valid when checked before issuance, but it was accepted")
	}
	t.Logf("correctly rejected not-yet-valid chain: %s", result.Error)
}

// ---------------------------------------------------------------------------
// Certificate role — chaining to a trusted root is not authorization to sign
// ---------------------------------------------------------------------------

// Chaining to a trusted IACA root does not by itself make a certificate a
// document signer. These tests pin that the DS certificate's extended key
// usage is checked, so a certificate issued for some other role beneath the
// same root cannot sign an MSO the wallet accepts.
func TestDocumentSignerEKUIsEnforced(t *testing.T) {
	const namespace = "eu.europa.ec.av.1"

	t.Run("DS cert with the ISO mdoc document-signer EKU is accepted", func(t *testing.T) {
		doc, v := issueWithDSEKU(t, nil, []asn1.ObjectIdentifier{isoMdocDocumentSignerEKU})
		if result := v.Verify(doc, namespace); !result.Valid {
			t.Fatalf("expected valid, got error: %s", result.Error)
		}
	})

	t.Run("DS cert with no EKU extension is accepted as unrestricted", func(t *testing.T) {
		// RFC 5280 4.2.1.12: an absent EKU means the certificate is not
		// restricted as to purpose, so there is nothing to contradict.
		doc, v := issueWithDSEKU(t, nil, nil)
		if result := v.Verify(doc, namespace); !result.Valid {
			t.Fatalf("expected valid, got error: %s", result.Error)
		}
	})

	t.Run("DS cert with anyExtKeyUsage is accepted", func(t *testing.T) {
		doc, v := issueWithDSEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, nil)
		if result := v.Verify(doc, namespace); !result.Valid {
			t.Fatalf("expected valid, got error: %s", result.Error)
		}
	})

	t.Run("DS cert issued for TLS server auth is rejected", func(t *testing.T) {
		// The finding this test exists for: a certificate legitimately issued
		// beneath the same IACA root, but for an unrelated role, must not be
		// able to sign an MSO.
		doc, v := issueWithDSEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil)
		result := v.Verify(doc, namespace)
		if result.Valid {
			t.Fatal("a TLS server certificate must not be accepted as an mdoc document signer")
		}
		if !strings.Contains(result.Error, "not authorized to sign mdocs") {
			t.Fatalf("expected an EKU rejection, got: %s", result.Error)
		}
	})

	t.Run("DS cert issued for TLS client auth is rejected", func(t *testing.T) {
		// This is the exact shape of the EUDI reference issuer's test
		// certificate (testdata/eudi-pid-issuer-py/certs/issuer.pem carries
		// clientAuth), recorded here so the interop consequence is visible in
		// the test suite rather than discovered during integration.
		doc, v := issueWithDSEKU(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
		result := v.Verify(doc, namespace)
		if result.Valid {
			t.Fatal("a TLS client certificate must not be accepted as an mdoc document signer")
		}
		if !strings.Contains(result.Error, "not authorized to sign mdocs") {
			t.Fatalf("expected an EKU rejection, got: %s", result.Error)
		}
	})

	t.Run("the reader-auth EKU is rejected", func(t *testing.T) {
		// 1.0.18013.5.1.6 is the sibling OID for reader authentication — an
		// 18013-5 role, but the verifier's role, not the issuer's.
		readerAuth := asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}
		doc, v := issueWithDSEKU(t, nil, []asn1.ObjectIdentifier{readerAuth})
		result := v.Verify(doc, namespace)
		if result.Valid {
			t.Fatal("a reader-auth certificate must not be accepted as a document signer")
		}
	})
}

// ---------------------------------------------------------------------------
// docType binding — the envelope's value against the signed one
// ---------------------------------------------------------------------------

// MDoc.DocType sits in the document map beside issuerSigned and is covered by
// no digest and no signature; MSO.docType is inside the signed MSO. These tests
// pin that the two must agree, at every entry point that reports a docType or
// consumes one.
//
// The consequence of not comparing them is not abstract: eudi/services' mdoc
// parser stores the value it reads as the credential's VerifiableCredentialType,
// which is what DCQL doctype_value matching and the scheme's relying-party
// authorization key off. Before this check, all three entry points below
// returned Valid=true while reporting the attacker's docType.

const attackerDocType = "eu.europa.ec.eudi.pid.1"

func TestTamperedEnvelopeDocTypeIsRejectedByVerify(t *testing.T) {
	_, _, verifier, presented, _, _, docType, namespace := buildHappyPathMDoc(t)

	tampered := *presented
	tampered.DocType = attackerDocType

	result := verifier.Verify(&tampered, namespace)
	if result.Valid {
		t.Fatalf("a document whose envelope docType was re-labelled to %q verified as valid, "+
			"and reported DocType=%q", attackerDocType, result.DocType)
	}
	if !strings.Contains(result.Error, "docType mismatch") {
		t.Errorf("error was %q, want it to name the docType mismatch", result.Error)
	}
	if result.DocType == attackerDocType {
		t.Errorf("result carries the attacker's docType %q", result.DocType)
	}
	// Sanity: the untampered document still verifies, and reports the signed value.
	if ok := verifier.Verify(presented, namespace); !ok.Valid || ok.DocType != docType {
		t.Errorf("untampered document: valid=%v docType=%q, want true/%q", ok.Valid, ok.DocType, docType)
	}
}

func TestTamperedEnvelopeDocTypeIsRejectedAtIssuanceVerification(t *testing.T) {
	issuer, holder, verifier, _, _, _, docType, namespace := buildHappyPathMDoc(t)

	// VerifyAllDisclosedNamespaces is the issuance-time entry point, so use a
	// freshly issued (not yet selectively disclosed) document.
	issued, err := issuer.Issue(docType, namespace, map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	issued.DocType = attackerDocType

	resolved, result := verifier.VerifyAllDisclosedNamespaces(issued)
	if result.Valid {
		t.Fatalf("re-labelled document passed issuance verification, reporting DocType=%q with claims %v",
			result.DocType, resolved)
	}
	if !strings.Contains(result.Error, "docType mismatch") {
		t.Errorf("error was %q, want it to name the docType mismatch", result.Error)
	}
}

func TestVerifierRequestedDocTypeMustMatchSignedMSO(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, _, namespace := buildHappyPathMDoc(t)

	// A verifier asking for a different docType than the issuer signed must be
	// told so plainly, rather than being left to infer it from a failed device
	// signature (the reconstructed DeviceAuthentication payload would differ).
	result := verifier.VerifyWithDeviceAuth(presented, namespace, attackerDocType, transcript, deviceAuthBytes)
	if result.Valid {
		t.Fatalf("verification succeeded for a docType the issuer never signed")
	}
	if !strings.Contains(result.Error, "docType mismatch") {
		t.Errorf("error was %q, want it to name the docType mismatch rather than an opaque signature failure", result.Error)
	}
}

func TestSignedDocTypeIsReportedNotTheEnvelopeValue(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)
	if !result.Valid || !result.DeviceAuthValid {
		t.Fatalf("happy path failed: valid=%v deviceAuth=%v err=%q", result.Valid, result.DeviceAuthValid, result.Error)
	}
	if result.DocType != docType {
		t.Errorf("DocType=%q, want the signed %q", result.DocType, docType)
	}
}

// ---------------------------------------------------------------------------
// Device authentication — signer, session, and the payload's own two halves
// ---------------------------------------------------------------------------

func TestDeviceAuthWrongSignerIsRejected(t *testing.T) {
	_, _, verifier, presented, transcript, _, docType, namespace := buildHappyPathMDoc(t)

	// A different holder (i.e. a different device) signs deviceAuth for
	// the SAME session transcript, but their key isn't the one embedded
	// in this mdoc's deviceKeyInfo. Simulates a cloned/copied mdoc.
	otherHolder, _ := NewHolder()
	wrongDeviceAuth, err := otherHolder.SignDeviceAuth(docType, transcript)
	if err != nil {
		t.Fatalf("SignDeviceAuth: %v", err)
	}

	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, wrongDeviceAuth)
	if result.DeviceAuthValid {
		t.Fatalf("expected deviceAuth signed by wrong device key to be rejected, but it was accepted")
	}
	// VerifyWithDeviceAuth intentionally marks the overall result invalid
	// when device binding fails — a presentation without a valid device
	// signature is not a valid presentation, even if issuerAuth/digests
	// check out on their own. Confirm the underlying issuerAuth checks
	// were in fact what ran (via the error message), rather than some
	// earlier unrelated failure.
	if result.Valid {
		t.Fatalf("expected overall result to be invalid when deviceAuth fails, but Valid was true")
	}
	if result.Error == "" {
		t.Fatalf("expected a descriptive error when deviceAuth fails, got empty string")
	}
}

func TestDeviceAuthWrongSessionIsRejected(t *testing.T) {
	_, holder, verifier, presented, transcript, _, docType, namespace := buildHappyPathMDoc(t)

	// Same (correct) device key, but signs over a DIFFERENT session
	// transcript than the one the verifier actually used. Simulates a
	// replayed deviceAuth from an earlier/different session.
	otherTranscript := SessionTranscript{
		DeviceEngagementBytes: []byte("different-engagement"),
		EReaderKeyBytes:       []byte("different-reader-key"),
		Handover:              "different-handover",
	}
	replayedDeviceAuth, err := holder.SignDeviceAuth(docType, otherTranscript)
	if err != nil {
		t.Fatalf("SignDeviceAuth: %v", err)
	}

	// Verifier checks against the ORIGINAL transcript it actually issued.
	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, replayedDeviceAuth)
	if result.DeviceAuthValid {
		t.Fatalf("expected deviceAuth bound to a different session to be rejected, but it was accepted")
	}
}

// TestDeviceAuthStillVerifiesWithDetachedPayload confirms that detaching
// the payload doesn't break verification — VerifyWithDeviceAuth must
// still succeed by reconstructing the payload itself before checking the
// signature, exactly as a real verifier would.
func TestDeviceAuthStillVerifiesWithDetachedPayload(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)
	if !result.DeviceAuthValid {
		t.Fatalf("expected deviceAuth to verify successfully despite detached payload, got: %s", result.Error)
	}
}

// The tests below cover the DeviceNameSpaces half of DeviceAuthentication: the
// verifier rebuilds the signed payload from the bytes it received at
// deviceSigned.nameSpaces, and judges whether their contents are permitted only
// after the signature over them has been verified.

// TestDeviceAuthAcceptsAlternativelyEncodedEmptyNameSpaces is the case the old
// reconstruction rejected. CBOR has more than one encoding of an empty map, and a
// holder that picks the indefinite-length form is asserting exactly nothing —
// the same as ours — but the bytes differ, so rebuilding tag24(map[string]any{})
// produced a payload that did not match the signature. The report came back as
// "deviceAuth signature invalid", which was not what had gone wrong.
func TestDeviceAuthAcceptsAlternativelyEncodedEmptyNameSpaces(t *testing.T) {
	_, holder, verifier, presented, transcript, _, docType, namespace := buildHappyPathMDoc(t)

	// bf ff — indefinite-length map with no entries. Valid CBOR, decodes to the
	// same empty map as a0, different bytes.
	indefiniteEmpty, err := tag24WrapBytes([]byte{0xbf, 0xff})
	if err != nil {
		t.Fatalf("wrap indefinite-length empty map: %v", err)
	}

	deviceAuthBytes := signDeviceAuthOver(t, holder, docType, transcript, indefiniteEmpty)
	attached := withDeviceSigned(presented, indefiniteEmpty, deviceAuthBytes)

	result := verifier.VerifyWithDeviceAuth(attached, namespace, docType, transcript, deviceAuthBytes)
	if !result.Valid || !result.DeviceAuthValid {
		t.Fatalf("a holder asserting nothing was rejected: valid=%v deviceAuth=%v err=%q",
			result.Valid, result.DeviceAuthValid, result.Error)
	}
}

// TestDeviceAuthRejectsHolderAssertedNameSpaces pins that holder-signed claims are
// still refused — but by the profile check, with a diagnosis that says so, rather
// than as a signature failure.
func TestDeviceAuthRejectsHolderAssertedNameSpaces(t *testing.T) {
	_, holder, verifier, presented, transcript, _, docType, namespace := buildHappyPathMDoc(t)

	holderClaims, err := tag24Wrap(map[string]any{
		"org.example.holder": map[string]any{"self_asserted": true},
	})
	if err != nil {
		t.Fatalf("wrap holder namespaces: %v", err)
	}

	deviceAuthBytes := signDeviceAuthOver(t, holder, docType, transcript, holderClaims)
	attached := withDeviceSigned(presented, holderClaims, deviceAuthBytes)

	result := verifier.VerifyWithDeviceAuth(attached, namespace, docType, transcript, deviceAuthBytes)
	if result.Valid {
		t.Fatal("a document asserting holder-signed namespaces was accepted")
	}
	if result.DeviceAuthValid {
		t.Error("DeviceAuthValid is true on a rejected document — a caller reading it " +
			"without checking Valid would treat this as accepted")
	}
	if !strings.Contains(result.Error, "not permitted") {
		t.Errorf("error does not name the profile rule: %q", result.Error)
	}
	if strings.Contains(result.Error, "signature invalid") {
		t.Errorf("rejected as a signature failure rather than a profile decision: %q", result.Error)
	}
	if !strings.Contains(result.Error, "org.example.holder") {
		t.Errorf("error does not name the offending namespace: %q", result.Error)
	}
}

// TestDeviceAuthRejectsNameSpacesNotCoveredBySignature is the adversarial
// counterpart: taking the nameSpaces from the wire is only safe because the
// signature covers them. A holder that signs the empty map and then transmits
// claims alongside it must fail, and fail as a signature error.
func TestDeviceAuthRejectsNameSpacesNotCoveredBySignature(t *testing.T) {
	_, holder, verifier, presented, transcript, _, docType, namespace := buildHappyPathMDoc(t)

	signedEmpty, err := tag24Wrap(map[string]any{})
	if err != nil {
		t.Fatalf("wrap empty namespaces: %v", err)
	}
	smuggled, err := tag24Wrap(map[string]any{
		"org.example.holder": map[string]any{"self_asserted": true},
	})
	if err != nil {
		t.Fatalf("wrap smuggled namespaces: %v", err)
	}

	// Signature covers the empty map; the envelope carries the claims.
	deviceAuthBytes := signDeviceAuthOver(t, holder, docType, transcript, signedEmpty)
	attached := withDeviceSigned(presented, smuggled, deviceAuthBytes)

	result := verifier.VerifyWithDeviceAuth(attached, namespace, docType, transcript, deviceAuthBytes)
	if result.Valid || result.DeviceAuthValid {
		t.Fatalf("namespaces outside the signature were accepted: valid=%v deviceAuth=%v",
			result.Valid, result.DeviceAuthValid)
	}
	if !strings.Contains(result.Error, "signature invalid") {
		t.Errorf("expected a signature failure, got %q", result.Error)
	}
}

// TestDeviceAuthRejectsMalformedNameSpaces covers the structural check that runs
// before verification, so a wrong shape is reported as such instead of surfacing
// as an unexplained signature mismatch.
func TestDeviceAuthRejectsMalformedNameSpaces(t *testing.T) {
	cases := []struct {
		name       string
		nameSpaces []byte
	}{
		// A bare map where DeviceNameSpacesBytes must be #6.24(bstr).
		{"untagged map", []byte{0xa0}},
		// Tag 24 wrapping a text string rather than a byte string.
		{"tag 24 over a tstr", []byte{0xd8, 0x18, 0x61, 0x78}},
		// Tag 18 (COSE_Sign1) instead of tag 24.
		{"wrong tag number", []byte{0xd2, 0x41, 0xa0}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, holder, verifier, presented, transcript, _, docType, namespace := buildHappyPathMDoc(t)

			deviceAuthBytes := signDeviceAuthOver(t, holder, docType, transcript, tc.nameSpaces)
			attached := withDeviceSigned(presented, tc.nameSpaces, deviceAuthBytes)

			result := verifier.VerifyWithDeviceAuth(attached, namespace, docType, transcript, deviceAuthBytes)
			if result.Valid {
				t.Fatal("a malformed deviceSigned.nameSpaces was accepted")
			}
			if !strings.Contains(result.Error, "malformed deviceSigned.nameSpaces") {
				t.Errorf("error does not identify the malformed field: %q", result.Error)
			}
		})
	}
}

// TestDeviceAuthWithoutDeviceSignedEnvelope pins the fallback: VerifyWithDeviceAuth
// is also called with deviceAuth as a parameter and no DeviceSigned to read from,
// which is how the demo and most of this package's tests use it.
func TestDeviceAuthWithoutDeviceSignedEnvelope(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	if presented.DeviceSigned != nil {
		t.Fatal("precondition: this test needs a document with no DeviceSigned envelope")
	}

	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)
	if !result.Valid || !result.DeviceAuthValid {
		t.Fatalf("out-of-band deviceAuth was rejected: valid=%v deviceAuth=%v err=%q",
			result.Valid, result.DeviceAuthValid, result.Error)
	}
}

// ---------------------------------------------------------------------------
// The DeviceResponse entry point
// ---------------------------------------------------------------------------

// TestVerifyDeviceResponseSucceeds runs the full flow through the real
// DeviceResponse container instead of calling VerifyWithDeviceAuth
// directly, confirming the container-based path produces the same result.
func TestVerifyDeviceResponseSucceeds(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	attached, err := AttachDeviceSigned(presented, deviceAuthBytes)
	if err != nil {
		t.Fatalf("AttachDeviceSigned: %v", err)
	}
	resp := NewDeviceResponse(*attached)

	results, err := verifier.VerifyDeviceResponse(resp, namespace, docType, transcript)
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

// TestVerifyDeviceResponseRejectsMissingDeviceSigned confirms a document
// without DeviceSigned attached is rejected with a descriptive error,
// rather than panicking on a nil dereference.
func TestVerifyDeviceResponseRejectsMissingDeviceSigned(t *testing.T) {
	_, _, verifier, presented, transcript, _, docType, namespace := buildHappyPathMDoc(t)

	resp := NewDeviceResponse(*presented) // never attached DeviceSigned

	_, err := verifier.VerifyDeviceResponse(resp, namespace, docType, transcript)
	if err == nil {
		t.Fatalf("expected error for document missing DeviceSigned, got none")
	}
}

// TestVerifierAcceptsTaggedCoseSign1 pins the deliberate asymmetry in
// decodeCoseSign1: this package writes the bare array ISO 18013-5 specifies,
// but must keep reading the tag-18 form, since implementations differ on it and
// the tag carries no security meaning (it is outside Sig_structure).
func TestVerifierAcceptsTaggedCoseSign1(t *testing.T) {
	_, _, verifier, presented, _, _, _, namespace := buildHappyPathMDoc(t)

	// Re-serialize the same issuerAuth in the tagged form by prefixing tag 18.
	untagged := presented.IssuerSigned.IssuerAuth
	tagged := append([]byte{0xd2}, untagged...)

	retagged := *presented
	retagged.IssuerSigned.IssuerAuth = cbor.RawMessage(tagged)

	result := verifier.Verify(&retagged, namespace)
	if !result.Valid {
		t.Fatalf("tagged COSE_Sign1 was rejected, but the tag is not security-relevant: %s", result.Error)
	}
}

// ---------------------------------------------------------------------------
// End-to-end
// ---------------------------------------------------------------------------

// TestFullIssuanceFlow_ProducesValidMDoc runs issuance → selective
// disclosure → deviceAuth → verification end to end, then prints the
// actual CBOR-encoded mdoc bytes (hex) so they can be independently
// inspected — e.g. pasted into https://cbor.me or decoded with any
// other CBOR/COSE tool to confirm this program produces spec-shaped
// output, not just output that satisfies its own verifier.
func TestFullIssuanceFlow_ProducesValidMDoc(t *testing.T) {
	_, _, verifier, presented, transcript, deviceAuthBytes, docType, namespace := buildHappyPathMDoc(t)

	// Dump the actual presented mdoc as CBOR bytes.
	mdocCBOR, err := cbor.Marshal(presented)
	if err != nil {
		t.Fatalf("marshal presented mdoc: %v", err)
	}
	t.Logf("presented mdoc CBOR (%d bytes):\n%s", len(mdocCBOR), hex.EncodeToString(mdocCBOR))

	// Dump the raw issuerAuth COSE_Sign1 bytes separately too — this is
	// the part a real verifier/relying-party library would decode first.
	t.Logf("issuerAuth COSE_Sign1 (%d bytes):\n%s",
		len(presented.IssuerSigned.IssuerAuth),
		hex.EncodeToString(presented.IssuerSigned.IssuerAuth))

	t.Logf("deviceAuth COSE_Sign1 (%d bytes):\n%s",
		len(deviceAuthBytes),
		hex.EncodeToString(deviceAuthBytes))

	result := verifier.VerifyWithDeviceAuth(presented, namespace, docType, transcript, deviceAuthBytes)

	if !result.Valid {
		t.Fatalf("expected valid mdoc, got error: %s", result.Error)
	}
	if !result.DeviceAuthValid {
		t.Fatalf("expected valid deviceAuth, got error: %s", result.Error)
	}
	if len(result.Attributes) != 1 {
		t.Fatalf("expected exactly 1 disclosed attribute, got %d: %v", len(result.Attributes), result.Attributes)
	}
	got, ok := result.Attributes["age_over_18"]
	if !ok {
		t.Fatalf("expected age_over_18 in disclosed attributes, got %v", result.Attributes)
	}
	if got != true {
		t.Fatalf("expected age_over_18 = true, got %v", got)
	}

	// age_over_16 / age_over_21 were withheld — must NOT be present.
	if _, present := result.Attributes["age_over_16"]; present {
		t.Fatalf("age_over_16 should have been withheld, but was disclosed")
	}
	if _, present := result.Attributes["age_over_21"]; present {
		t.Fatalf("age_over_21 should have been withheld, but was disclosed")
	}
}
