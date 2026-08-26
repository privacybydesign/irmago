package mdoc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/veraison/go-cose"
)

// Salt-length rejection, exercised through the entry points a wallet actually
// calls, on complete credentials an issuer could really have sent.
//
// verifier_salt_test.go already covers the comparison itself: it calls
// verifyNamespaceDigests directly with a hand-built item and a matching digest.
// That pins the check but cannot show it is reachable — an earlier step in
// Verify or VerifyAllDisclosedNamespaces could reject or accept the credential
// before the salt is ever looked at, and the unit test would stay green either
// way. What is missing, and what these tests add, is the whole credential:
// signed by a real document signer, with a real x5chain, an open validity
// window, and digests that match. Everything about it verifies except the salt.
//
// Such a credential cannot come from Issue, which refuses to mint a short salt —
// that is the point of its own floor check — so it is built by
// issueWithSaltLength below, the same construction with the floor removed. That
// makes the control load-bearing: every rejection is paired with the identical
// credential at a legal length, so a failure can only be attributed to the salt
// and never to the hand-assembled envelope.

// issueWithSaltLength mints a fully self-consistent mdoc whose IssuerSignedItem
// random values are exactly saltLen bytes.
//
// "Self-consistent" is the important part. The MSO's valueDigests are computed
// over the short-salted items and the MSO is signed by the issuer's real
// document signer, with the real x5chain, so the credential passes every other
// check the verifier makes: the chain resolves, the COSE signature verifies, the
// validity window is open, the envelope docType matches the signed one, and each
// digest matches its item. A credential that merely had a short salt bolted onto
// a genuine one would fail on the digest instead, and the test would pass while
// proving nothing about the salt.
func issueWithSaltLength(
	t *testing.T,
	iss *Issuer,
	holderPub *ecdsa.PublicKey,
	docType, namespace string,
	claims map[string]any,
	saltLen int,
) *MDoc {
	t.Helper()

	items := make([]IssuerSignedItem, 0, len(claims))
	digestID := uint64(0)
	for identifier, value := range claims {
		salt := make([]byte, saltLen)
		if saltLen > 0 {
			if _, err := rand.Read(salt); err != nil {
				t.Fatalf("generate %d-byte salt: %v", saltLen, err)
			}
		}
		items = append(items, IssuerSignedItem{
			DigestID:          digestID,
			Random:            salt,
			ElementIdentifier: identifier,
			ElementValue:      value,
		})
		digestID++
	}

	return mdocFromItems(t, iss, holderPub, docType, namespace, items)
}

// mdocFromItems signs the given items into a credential, computing the MSO's
// digests over exactly the items supplied. It applies no floor of its own, which
// is what lets these tests build the credential Issue refuses to.
func mdocFromItems(
	t *testing.T,
	iss *Issuer,
	holderPub *ecdsa.PublicKey,
	docType, namespace string,
	items []IssuerSignedItem,
) *MDoc {
	t.Helper()

	valueDigests := make(map[uint64][]byte, len(items))
	for _, item := range items {
		digest, err := hashTag24Item(item)
		if err != nil {
			t.Fatalf("hash item %s: %v", item.ElementIdentifier, err)
		}
		valueDigests[item.DigestID] = digest
	}

	deviceKey, err := coseKeyFromECDSA(holderPub)
	if err != nil {
		t.Fatalf("convert holder public key: %v", err)
	}

	now := time.Now().UTC().Truncate(24 * time.Hour)
	mso := MSO{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[uint64][]byte{namespace: valueDigests},
		DocType:         docType,
		ValidityInfo: ValidityInfo{
			Signed:     now,
			ValidFrom:  now,
			ValidUntil: now.Add(90 * 24 * time.Hour),
		},
		DeviceKeyInfo: DeviceKeyInfo{DeviceKey: deviceKey},
	}

	msoBytes, err := tag24WrapWithMode(mso, avTimeEncMode)
	if err != nil {
		t.Fatalf("wrap mso: %v", err)
	}

	signer, err := cose.NewSigner(cose.AlgorithmES256, iss.dskey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers,
		Payload: msoBytes}
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Unprotected[int64(33)] = [][]byte{iss.dscert.Raw, iss.iacacert.Raw}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign mso: %v", err)
	}
	coseBytes, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal cose: %v", err)
	}

	tag24Items := make([]Tag24Item, len(items))
	for i, item := range items {
		wrapped, err := tag24Wrap(item)
		if err != nil {
			t.Fatalf("wrap item %s: %v", item.ElementIdentifier, err)
		}
		tag24Items[i] = Tag24Item{EncodedItem: wrapped}
	}

	return &MDoc{
		DocType: docType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: tag24Items},
			IssuerAuth: coseBytes,
		},
	}
}

// saltTestFixture is the issuer, holder and verifier the salt tests share.
func saltTestFixture(t *testing.T) (*Issuer, *ecdsa.PublicKey, *Verifier, string, string) {
	t.Helper()

	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	verifier := NewVerifier([]*x509.Certificate{issuer.IACACert()})
	return issuer, holder.PublicKey(), verifier, "eu.europa.ec.av.1", "eu.europa.ec.av.1"
}

// TestShortSaltIsRejectedAtIssuance is the case that matters most: this is the
// entry point a wallet uses on the credentials an issuer hands it, so it is
// where a defective issuer is actually caught.
func TestShortSaltIsRejectedAtIssuance(t *testing.T) {
	issuer, holderPub, verifier, docType, namespace := saltTestFixture(t)
	claims := map[string]any{"age_over_18": true}

	short := issueWithSaltLength(t, issuer, holderPub, docType, namespace, claims, minSaltLength-1)

	resolved, result := verifier.VerifyAllDisclosedNamespaces(short)
	if result.Valid {
		t.Fatalf("a %d-byte salt was accepted at issuance; ISO/IEC 18013-5 requires at least %d",
			minSaltLength-1, minSaltLength)
	}
	if resolved != nil {
		t.Errorf("claims were resolved from a rejected credential: %v", resolved)
	}

	// The reason has to name the salt. Reported as anything else — a digest
	// mismatch in particular — the check would look like it fired while the
	// credential was really being refused for an unrelated reason, and the
	// regression this test guards against would go unnoticed.
	if !strings.Contains(result.Error, "random value") {
		t.Errorf("rejection should name the random value, got %q", result.Error)
	}
	if strings.Contains(result.Error, "digest mismatch") {
		t.Errorf("rejected as a digest mismatch rather than a short salt: %q", result.Error)
	}
}

// TestLegalSaltFromTheSameConstructionIsAccepted is the control for every
// rejection here. It mints through the same floor-less path, changing only the
// salt length, so a passing rejection test cannot be explained by the
// hand-assembled credential being broken in some other way.
func TestLegalSaltFromTheSameConstructionIsAccepted(t *testing.T) {
	issuer, holderPub, verifier, docType, namespace := saltTestFixture(t)
	claims := map[string]any{"age_over_18": true}

	legal := issueWithSaltLength(t, issuer, holderPub, docType, namespace, claims, minSaltLength)

	resolved, result := verifier.VerifyAllDisclosedNamespaces(legal)
	if !result.Valid {
		t.Fatalf("a credential identical but for a %d-byte salt was rejected: %s",
			minSaltLength, result.Error)
	}
	if got := resolved[namespace]["age_over_18"]; got != true {
		t.Errorf("age_over_18 = %v, want true", got)
	}
}

// TestSaltLengthBoundary walks the floor from both sides, so the comparison is
// pinned at exactly minSaltLength rather than merely somewhere near it. An
// off-by-one here would be invisible to a single short-salt test.
func TestSaltLengthBoundary(t *testing.T) {
	tests := []struct {
		saltLen    int
		wantValid  bool
		reasonWhen string
	}{
		{saltLen: 0, wantValid: false, reasonWhen: "no salt at all"},
		{saltLen: 1, wantValid: false, reasonWhen: "a single byte"},
		{saltLen: 8, wantValid: false, reasonWhen: "half the floor"},
		{saltLen: minSaltLength - 1, wantValid: false, reasonWhen: "one byte below the floor"},
		{saltLen: minSaltLength, wantValid: true, reasonWhen: "exactly the floor"},
		{saltLen: minSaltLength + 1, wantValid: true, reasonWhen: "one byte above the floor"},
		{saltLen: 32, wantValid: true, reasonWhen: "double the floor"},
	}

	for _, test := range tests {
		t.Run(test.reasonWhen, func(t *testing.T) {
			issuer, holderPub, verifier, docType, namespace := saltTestFixture(t)
			m := issueWithSaltLength(t, issuer, holderPub, docType, namespace,
				map[string]any{"age_over_18": true}, test.saltLen)

			_, result := verifier.VerifyAllDisclosedNamespaces(m)
			if result.Valid != test.wantValid {
				t.Fatalf("salt of %d bytes: valid = %t, want %t (error: %q)",
					test.saltLen, result.Valid, test.wantValid, result.Error)
			}
		})
	}
}

// TestShortSaltIsRejectedAtPresentation covers the other entry point. A verifier
// receiving a presentation reaches the same floor through Verify, so a
// credential that somehow got past issuance is still refused when it travels.
func TestShortSaltIsRejectedAtPresentation(t *testing.T) {
	issuer, holderPub, verifier, docType, namespace := saltTestFixture(t)

	short := issueWithSaltLength(t, issuer, holderPub, docType, namespace,
		map[string]any{"age_over_18": true, "age_over_21": false}, minSaltLength-1)

	presented, err := SelectiveDisclose(short, namespace, []string{"age_over_18"})
	if err != nil {
		t.Fatalf("SelectiveDisclose: %v", err)
	}

	result := verifier.Verify(presented, namespace)
	if result.Valid {
		t.Fatalf("a presentation carrying a %d-byte salt was accepted", minSaltLength-1)
	}
	if !strings.Contains(result.Error, "random value") {
		t.Errorf("rejection should name the random value, got %q", result.Error)
	}
}

// TestShortSaltRejectedEvenWhenOnlyOneItemIsDefective guards the loop rather
// than the comparison: the check has to run for every disclosed item, not only
// the first. A credential whose defective element is disclosed alongside sound
// ones must still be refused.
func TestShortSaltRejectedEvenWhenOnlyOneItemIsDefective(t *testing.T) {
	issuer, holderPub, verifier, docType, namespace := saltTestFixture(t)

	// Two sound items and one defective one, all covered by the same MSO. The
	// items are built here rather than by issueWithSaltLength because that helper
	// applies one length to everything.
	items := []IssuerSignedItem{
		{DigestID: 0, ElementIdentifier: "age_over_16", ElementValue: true},
		{DigestID: 1, ElementIdentifier: "age_over_18", ElementValue: true},
		{DigestID: 2, ElementIdentifier: "age_over_21", ElementValue: false},
	}
	for i := range items {
		length := minSaltLength
		if items[i].ElementIdentifier == "age_over_21" {
			length = minSaltLength - 1 // the one defective element
		}
		salt := make([]byte, length)
		if _, err := rand.Read(salt); err != nil {
			t.Fatalf("generate salt: %v", err)
		}
		items[i].Random = salt
	}

	m := mdocFromItems(t, issuer, holderPub, docType, namespace, items)

	_, result := verifier.VerifyAllDisclosedNamespaces(m)
	if result.Valid {
		t.Fatal("a credential with one short-salted element among sound ones was accepted")
	}
	if !strings.Contains(result.Error, "age_over_21") {
		t.Errorf("rejection should name the defective element age_over_21, got %q", result.Error)
	}
}
