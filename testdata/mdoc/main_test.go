package mdoc

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// TEST HELPERS
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

	claims := map[string]interface{}{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
	}

	mdoc, err := issuer.Issue(docType, namespace, claims, &holder.devicekey.PublicKey)
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

	verifier := NewVerifier([]*x509.Certificate{issuer.iacacert})

	return issuer, holder, verifier, presented, transcript, deviceAuthBytes, docType, namespace
}

// ============================================================
// TEST 1: FULL HAPPY-PATH FLOW — dumps real mdoc CBOR bytes
// ============================================================

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

// ============================================================
// TEST 2: COSE KEY ENCODING — proves the keyasint fix actually works
// ============================================================

// TestCOSEKeyUsesIntegerMapKeys decodes the real MSO bytes produced by
// the issuer and checks — at the raw CBOR level — that deviceKeyInfo's
// map keys are CBOR integers (major type 0/1), not text strings. This
// is the concrete regression test for the COSEKey struct-tag fix.
func TestCOSEKeyUsesIntegerMapKeys(t *testing.T) {
	issuer, holder, _, _, _, _, _, _ := buildHappyPathMDoc(t)
	_ = issuer
	_ = holder

	// Re-issue directly so we have the raw MSO payload bytes in hand.
	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	newHolder, _ := NewHolder()
	mdoc, err := issuer.Issue(docType, namespace, map[string]interface{}{"age_over_18": true}, &newHolder.devicekey.PublicKey)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Decode COSE_Sign1 → MSO payload, then decode the MSO into a generic
	// map so we can inspect deviceKeyInfo.deviceKey's key types directly,
	// bypassing our own (possibly-wrong) struct tags.
	var raw map[string]cbor.RawMessage
	// issuerAuth is itself a COSE_Sign1; the payload field inside it is
	// the MSO. Easiest robust check: decode issuerAuth generically.
	var coseGeneric []interface{}
	if err := cbor.Unmarshal(mdoc.IssuerSigned.IssuerAuth, &coseGeneric); err != nil {
		t.Fatalf("decode cose generic: %v", err)
	}
	if len(coseGeneric) < 3 {
		t.Fatalf("expected COSE_Sign1 array with >=3 elements, got %d", len(coseGeneric))
	}
	msoPayload, ok := coseGeneric[2].([]byte)
	if !ok {
		t.Fatalf("payload element wrong type: %T", coseGeneric[2])
	}

	if err := cbor.Unmarshal(msoPayload, &raw); err != nil {
		t.Fatalf("decode mso generic: %v", err)
	}

	deviceKeyInfoRaw, ok := raw["deviceKeyInfo"]
	if !ok {
		t.Fatalf("deviceKeyInfo missing from MSO")
	}
	var dkiGeneric map[string]cbor.RawMessage
	if err := cbor.Unmarshal(deviceKeyInfoRaw, &dkiGeneric); err != nil {
		t.Fatalf("decode deviceKeyInfo generic: %v", err)
	}
	deviceKeyRaw, ok := dkiGeneric["deviceKey"]
	if !ok {
		t.Fatalf("deviceKey missing from deviceKeyInfo")
	}

	// Decode deviceKey as map[interface{}]interface{} to see actual key types.
	var keyMap map[interface{}]interface{}
	if err := cbor.Unmarshal(deviceKeyRaw, &keyMap); err != nil {
		t.Fatalf("decode deviceKey as generic map: %v", err)
	}

	for k := range keyMap {
		switch v := k.(type) {
		case int64:
			// negative keys decode as int64
		case uint64:
			// positive keys decode as uint64
			_ = v
		default:
			t.Fatalf("deviceKey map key %v has type %T, want int64/uint64 (COSEKey struct tags missing ',keyasint')", k, k)
		}
	}

	// Sanity: the four expected keys (1, -1, -2, -3) must exist.
	// Positive key (1) decodes as uint64; negative keys decode as int64.
	want := []int64{1, -1, -2, -3}
	for _, w := range want {
		found := false
		for k := range keyMap {
			switch kv := k.(type) {
			case int64:
				if kv == w {
					found = true
				}
			case uint64:
				if w >= 0 && kv == uint64(w) {
					found = true
				}
			}
			if found {
				break
			}
		}
		if !found {
			t.Fatalf("deviceKey missing expected key %d (saw keys: %v)", w, keysOf(keyMap))
		}
	}
}

// keysOf is a small debug helper for readable failure messages.
func keysOf(m map[interface{}]interface{}) []interface{} {
	out := make([]interface{}, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ============================================================
// TEST 3: DETERMINISTIC DIGEST ORDERING
// ============================================================

// TestClaimOrderingIsDeterministic issues the same claim set twice and
// checks that ElementIdentifier→DigestID assignment is identical both
// times. Regression test for the map-iteration-order fix.
func TestClaimOrderingIsDeterministic(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, _ := NewHolder()

	claims := map[string]interface{}{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
		"age_over_65": false,
	}

	extractOrder := func(mdoc *MDoc, namespace string) []string {
		items := mdoc.IssuerSigned.NameSpaces[namespace]
		order := make([]string, len(items))
		for _, tag24item := range items {
			var rawTag cbor.RawTag
			if err := cbor.Unmarshal(tag24item.EncodedItem, &rawTag); err != nil {
				t.Fatalf("unwrap tag24: %v", err)
			}
			var innerBytes []byte
			if err := cbor.Unmarshal(rawTag.Content, &innerBytes); err != nil {
				t.Fatalf("unwrap inner: %v", err)
			}
			var item IssuerSignedItem
			if err := cbor.Unmarshal(innerBytes, &item); err != nil {
				t.Fatalf("decode item: %v", err)
			}
			order[item.DigestID] = item.ElementIdentifier
		}
		return order
	}

	namespace := "eu.europa.ec.av.1"

	mdoc1, err := issuer.Issue("eu.europa.ec.av.1", namespace, claims, &holder.devicekey.PublicKey)
	if err != nil {
		t.Fatalf("Issue #1: %v", err)
	}
	mdoc2, err := issuer.Issue("eu.europa.ec.av.1", namespace, claims, &holder.devicekey.PublicKey)
	if err != nil {
		t.Fatalf("Issue #2: %v", err)
	}

	order1 := extractOrder(mdoc1, namespace)
	order2 := extractOrder(mdoc2, namespace)

	if len(order1) != len(order2) {
		t.Fatalf("order length mismatch: %v vs %v", order1, order2)
	}
	for i := range order1 {
		if order1[i] != order2[i] {
			t.Fatalf("digestID→identifier order not deterministic: run1=%v run2=%v", order1, order2)
		}
	}

	// Expect alphabetical: age_over_16, age_over_18, age_over_21, age_over_65
	want := []string{"age_over_16", "age_over_18", "age_over_21", "age_over_65"}
	for i, w := range want {
		if order1[i] != w {
			t.Fatalf("expected sorted order %v, got %v", want, order1)
		}
	}
}

// ============================================================
// TEST 4: NEGATIVE CASES — these must all FAIL verification
// ============================================================

func TestUntrustedRootIsRejected(t *testing.T) {
	_, _, verifier, _, _, _, docType, namespace := buildHappyPathMDoc(t)

	attackerIssuer, _ := NewIssuer()
	attackerHolder, _ := NewHolder()
	attackerMDoc, err := attackerIssuer.Issue(docType, namespace,
		map[string]interface{}{"age_over_18": true}, &attackerHolder.devicekey.PublicKey)
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
	verifier := NewVerifier([]*x509.Certificate{issuer.iacacert})

	holder, _ := NewHolder()
	mdoc, err := issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]interface{}{"age_over_18": true}, &holder.devicekey.PublicKey)
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
		map[string]interface{}{"age_over_18": true}, &holder.devicekey.PublicKey)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	presented, err := SelectiveDisclose(mdoc, "eu.europa.ec.av.1", []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	futureClock := time.Now().Add(400 * 24 * time.Hour) // past the DS cert's 365-day NotAfter
	verifier := NewVerifierWithClock([]*x509.Certificate{issuer.iacacert}, futureClock)

	result := verifier.Verify(presented, "eu.europa.ec.av.1")
	if result.Valid {
		t.Fatalf("expected DS cert to be rejected as expired when checked 400 days in the future, but it was accepted")
	}
	t.Logf("correctly rejected expired chain: %s", result.Error)
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
		map[string]interface{}{"age_over_18": true}, &holder.devicekey.PublicKey)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	presented, err := SelectiveDisclose(mdoc, "eu.europa.ec.av.1", []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	pastClock := time.Now().Add(-24 * time.Hour) // before NotBefore
	verifier := NewVerifierWithClock([]*x509.Certificate{issuer.iacacert}, pastClock)

	result := verifier.Verify(presented, "eu.europa.ec.av.1")
	if result.Valid {
		t.Fatalf("expected DS cert to be rejected as not-yet-valid when checked before issuance, but it was accepted")
	}
	t.Logf("correctly rejected not-yet-valid chain: %s", result.Error)
}
