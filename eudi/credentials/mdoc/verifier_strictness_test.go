package mdoc

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"
)

// ============================================================
// STRICTNESS CHECKS — the ISO/IEC 18013-5 rules a reader has to
// enforce on receipt, each of which a defective or hostile
// issuer can otherwise slip past a signature that verifies fine
// ============================================================

// issueCustom mints a document from a caller-supplied MSO and a caller-supplied
// set of already-encoded IssuerSignedItemBytes, signed with iss's real DS key
// and shipped with its real chain.
//
// The point is that everything the verifier checks *before* the field under test
// is genuine — the chain walks to a trusted root, the COSE_Sign1 verifies, the
// docType binds — so a rejection can only have come from the one thing the test
// varied. Hand-building the whole document instead would let a rejection come
// from anywhere.
func issueCustom(t *testing.T, iss *Issuer, namespace string, mso MSO, itemBytes [][]byte) *MDoc {
	t.Helper()

	msoBytes, err := tag24WrapWithMode(mso, tdateEncMode)
	if err != nil {
		t.Fatalf("wrap mso: %v", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmES256, iss.dskey)
	if err != nil {
		t.Fatalf("cose.NewSigner: %v", err)
	}
	msg := cose.UntaggedSign1Message{Headers: cose.NewSign1Message().Headers, Payload: msoBytes}
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Unprotected[int64(33)] = [][]byte{iss.dscert.Raw, iss.iacacert.Raw}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign mso: %v", err)
	}
	coseBytes, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal cose: %v", err)
	}

	items := make([]Tag24Item, len(itemBytes))
	for i, b := range itemBytes {
		items[i] = Tag24Item{EncodedItem: b}
	}
	return &MDoc{
		DocType: mso.DocType,
		IssuerSigned: IssuerSigned{
			NameSpaces: map[string][]Tag24Item{namespace: items},
			IssuerAuth: coseBytes,
		},
	}
}

// baseMSO is a valid MSO over the given digests, for tests that vary one field.
func baseMSO(t *testing.T, namespace string, digests map[uint64][]byte) MSO {
	t.Helper()
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	deviceKey, err := coseKeyFromECDSA(holder.PublicKey())
	if err != nil {
		t.Fatalf("coseKeyFromECDSA: %v", err)
	}
	now := time.Now().UTC()
	return MSO{
		Version:         "1.0",
		DigestAlgorithm: "SHA-256",
		ValueDigests:    map[string]map[uint64][]byte{namespace: digests},
		DocType:         namespace,
		ValidityInfo:    ValidityInfo{Signed: now, ValidFrom: now, ValidUntil: now.Add(24 * time.Hour)},
		DeviceKeyInfo:   DeviceKeyInfo{DeviceKey: deviceKey},
	}
}

// wrapItem tag-24 wraps one item and returns the bytes alongside their digest,
// which is what the MSO has to commit to for the item to be accepted.
func wrapItem(t *testing.T, item IssuerSignedItem) (encoded []byte, digest []byte) {
	t.Helper()
	encoded, err := tag24Wrap(item)
	if err != nil {
		t.Fatalf("tag24Wrap: %v", err)
	}
	sum := sha256.Sum256(encoded)
	return encoded, sum[:]
}

// TestMSOVersionMustBeMajorOne covers 9.1.2.4: the MobileSecurityObject version
// "shall be 1.0" in this edition of the standard.
//
// A higher major version is a structure carrying fields this code has no
// definition for. Decoding silently drops what it does not recognise, so every
// field the verifier consults can decode cleanly while the document as a whole
// means something else — which is the case worth refusing, not a malformed one.
// Minor increments stay acceptable: 8.1's versioning rule makes them backward
// compatible by construction.
func TestMSOVersionMustBeMajorOne(t *testing.T) {
	const ns = "eu.europa.ec.av.1"

	for _, tc := range []struct {
		version  string
		accepted bool
	}{
		{"1.0", true},
		{"1.1", true},
		{"2.0", false},
		{"0.9", false},
		{"", false},
	} {
		t.Run("version "+tc.version, func(t *testing.T) {
			issuer, err := NewIssuer()
			if err != nil {
				t.Fatalf("NewIssuer: %v", err)
			}
			encoded, digest := wrapItem(t, IssuerSignedItem{
				DigestID: 0, Random: make([]byte, minSaltLength),
				ElementIdentifier: "age_over_18", ElementValue: true,
			})
			mso := baseMSO(t, ns, map[uint64][]byte{0: digest})
			mso.Version = tc.version

			doc := issueCustom(t, issuer, ns, mso, [][]byte{encoded})
			result := NewVerifier([]*x509.Certificate{issuer.IACACert()}).Verify(doc, ns)

			if tc.accepted && !result.Valid {
				t.Fatalf("version %q should be accepted, got: %s", tc.version, result.Error)
			}
			if !tc.accepted {
				if result.Valid {
					t.Fatalf("version %q must be refused: this code has no definition for that structure", tc.version)
				}
				if !strings.Contains(result.Error, "version") {
					t.Errorf("rejection should name the version, got: %s", result.Error)
				}
			}
		})
	}
}

// TestDuplicateElementIdentifierIsRejected covers 8.3.2.1.2.2: "The mdoc shall
// not include two or more IssuerSignedItem elements with the same
// DataElementIdentifier in a single NameSpace and Document."
//
// Both items here are genuinely signed for — different digestIDs, both digests
// in the MSO — so every cryptographic check passes and only the structural rule
// catches it. Accumulating into a map without this lets the later item win,
// which for a boolean profile means the value the verifier reports is decided by
// encoder ordering.
func TestDuplicateElementIdentifierIsRejected(t *testing.T) {
	const ns = "eu.europa.ec.av.1"

	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	trueItem, trueDigest := wrapItem(t, IssuerSignedItem{
		DigestID: 0, Random: make([]byte, minSaltLength),
		ElementIdentifier: "age_over_18", ElementValue: true,
	})
	falseItem, falseDigest := wrapItem(t, IssuerSignedItem{
		DigestID: 1, Random: make([]byte, minSaltLength),
		ElementIdentifier: "age_over_18", ElementValue: false,
	})

	mso := baseMSO(t, ns, map[uint64][]byte{0: trueDigest, 1: falseDigest})
	doc := issueCustom(t, issuer, ns, mso, [][]byte{trueItem, falseItem})

	result := NewVerifier([]*x509.Certificate{issuer.IACACert()}).Verify(doc, ns)
	if result.Valid {
		t.Fatalf("a document disclosing age_over_18 twice must be refused; got %v for the element",
			result.Attributes["age_over_18"])
	}
	if !strings.Contains(result.Error, "age_over_18") {
		t.Errorf("rejection should name the duplicated element, got: %s", result.Error)
	}
}

// TestDuplicateCBORMapKeyIsRejected covers 8.1: "maps (major type 5) shall not
// have multiple entries with the same key."
//
// The item below is byte-for-byte what the MSO commits to, so its digest matches
// and the signature is untouched — the only thing wrong with it is that it
// carries two elementValue entries. fxamacker's default DupMapKeyQuiet would
// decode it to whichever came last and report a clean verification, which means
// two implementations reading the same signed bytes can disagree about what was
// signed. mdocDecMode exists to make that a decode failure.
func TestDuplicateCBORMapKeyIsRejected(t *testing.T) {
	const ns = "eu.europa.ec.av.1"

	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}

	// Encode the item normally, then splice in a second elementValue pair and
	// bump the map header by one entry. Building the whole map by hand would be
	// unreadable, and this way only the duplication is hand-made.
	base, err := cbor.Marshal(IssuerSignedItem{
		DigestID: 0, Random: make([]byte, minSaltLength),
		ElementIdentifier: "age_over_18", ElementValue: false,
	})
	if err != nil {
		t.Fatalf("marshal item: %v", err)
	}
	if base[0] != 0xa4 {
		t.Fatalf("expected a 4-entry definite-length CBOR map header (0xa4), got 0x%02x", base[0])
	}
	dupKey, err := cbor.Marshal("elementValue")
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dupValue, err := cbor.Marshal(true)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	withDup := append([]byte{0xa5}, base[1:]...)
	withDup = append(withDup, dupKey...)
	withDup = append(withDup, dupValue...)

	encoded, err := tag24WrapBytes(withDup)
	if err != nil {
		t.Fatalf("tag24WrapBytes: %v", err)
	}
	sum := sha256.Sum256(encoded)

	mso := baseMSO(t, ns, map[uint64][]byte{0: sum[:]})
	doc := issueCustom(t, issuer, ns, mso, [][]byte{encoded})

	result := NewVerifier([]*x509.Certificate{issuer.IACACert()}).Verify(doc, ns)
	if result.Valid {
		t.Fatalf("an IssuerSignedItem with a duplicated map key must be refused; it decoded to age_over_18=%v",
			result.Attributes["age_over_18"])
	}
}

// TestVerifyCoversEveryNamespacePresent covers 9.3.1 step 3: "calculate the
// digest value for every IssuerSignedItem returned in the DeviceResponse", which
// carries no qualification about which namespace the caller asked for.
//
// The extra namespace here has no entry in the MSO at all, so nothing can vouch
// for its item. Verifying only the requested namespace left it neither checked
// nor refused — its values never reached Attributes, which is what kept it from
// being exploitable, but the document still came back Valid while carrying
// elements the verifier had said nothing about.
func TestVerifyCoversEveryNamespacePresent(t *testing.T) {
	_, _, verifier, doc, _, _, _, namespace := buildHappyPathMDoc(t)

	if result := verifier.Verify(doc, namespace); !result.Valid {
		t.Fatalf("precondition: the unmodified document should verify, got: %s", result.Error)
	}

	smuggled, _ := wrapItem(t, IssuerSignedItem{
		DigestID: 0, Random: make([]byte, minSaltLength),
		ElementIdentifier: "nationality", ElementValue: "NL",
	})
	doc.IssuerSigned.NameSpaces["org.iso.18013.5.1"] = []Tag24Item{{EncodedItem: smuggled}}

	result := verifier.Verify(doc, namespace)
	if result.Valid {
		t.Fatal("a document carrying a namespace the MSO does not cover must be refused, even when the caller asked about a different namespace")
	}
	if !strings.Contains(result.Error, "org.iso.18013.5.1") {
		t.Errorf("rejection should name the uncovered namespace, got: %s", result.Error)
	}
}

// TestSelectiveDiscloseRefusesEmptyResult covers the CDDL's
// `IssuerNameSpaces = {+ NameSpace => [+ IssuerSignedItemBytes]}` — a namespace
// key must map to at least one item.
//
// A nil slice encodes as CBOR null under a present namespace key: neither an
// array nor an absent namespace, and unreadable by any conformant verifier.
// Erroring rather than dropping the namespace keeps a presentation that is
// missing what the user consented to distinguishable from a verifier that asked
// for less.
func TestSelectiveDiscloseRefusesEmptyResult(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	const ns = "eu.europa.ec.av.1"
	doc, err := issuer.Issue(ns, ns, map[string]any{"age_over_18": true}, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := SelectiveDisclose(doc, ns, []string{"age_over_65"}); err == nil {
		t.Fatal("disclosing an element the credential does not hold must error rather than produce a namespace mapped to null")
	}

	if _, err := SelectiveDisclose(doc, "no.such.namespace", []string{"age_over_18"}); err == nil {
		t.Fatal("disclosing from a namespace the credential does not hold must error")
	}
}
