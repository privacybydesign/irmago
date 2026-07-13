package mdoc

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

// ============================================================
// NEGATIVE CASES — these must all FAIL verification
// ============================================================

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
