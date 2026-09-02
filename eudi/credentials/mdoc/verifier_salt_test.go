package mdoc

import (
	"crypto/sha256"
	"strings"
	"testing"
)

// wrapItemWithMatchingDigest Tag-24 wraps item and returns it alongside a
// digest map that already contains the correct digest for it. Any rejection is
// therefore attributable to the item itself rather than to a digest mismatch,
// which is what makes the salt-length assertions below meaningful.
func wrapItemWithMatchingDigest(t *testing.T, item IssuerSignedItem) ([]Tag24Item, map[uint64][]byte) {
	t.Helper()

	encoded, err := tag24Wrap(item)
	if err != nil {
		t.Fatalf("tag24Wrap: %v", err)
	}
	digest := sha256.Sum256(encoded)

	return []Tag24Item{{EncodedItem: encoded}}, map[uint64][]byte{item.DigestID: digest[:]}
}

func TestVerifyNamespaceDigestsRejectsShortSalt(t *testing.T) {
	// One byte under the floor: the boundary is what a future edit is most
	// likely to get wrong, and a 15-byte salt is otherwise indistinguishable
	// from a conformant one.
	item := IssuerSignedItem{
		DigestID:          1,
		Random:            make([]byte, minSaltLength-1),
		ElementIdentifier: "age_over_18",
		ElementValue:      true,
	}
	items, digests := wrapItemWithMatchingDigest(t, item)

	attrs, err := verifyNamespaceDigests(items, digests, sha256Digest)
	if err == nil {
		t.Fatalf("a %d-byte salt was accepted; the undisclosed elements of such a credential are brute-forceable", len(item.Random))
	}
	if attrs != nil {
		t.Errorf("attributes were returned alongside the error: %v", attrs)
	}
	// The message has to name the defect, not surface as a digest mismatch:
	// the two send an implementor looking in completely different places.
	if !strings.Contains(err.Error(), "random value") || !strings.Contains(err.Error(), "age_over_18") {
		t.Errorf("error should name the short random value and the element, got: %v", err)
	}
}

func TestVerifyNamespaceDigestsAcceptsSaltAtFloor(t *testing.T) {
	// Exactly at the floor must pass: our own issuer mints 16-byte salts, so a
	// check written as > rather than >= would reject every credential we issue.
	item := IssuerSignedItem{
		DigestID:          1,
		Random:            make([]byte, minSaltLength),
		ElementIdentifier: "age_over_18",
		ElementValue:      true,
	}
	items, digests := wrapItemWithMatchingDigest(t, item)

	attrs, err := verifyNamespaceDigests(items, digests, sha256Digest)
	if err != nil {
		t.Fatalf("a salt exactly at the ISO floor was rejected: %v", err)
	}
	if got, ok := attrs["age_over_18"]; !ok || got != true {
		t.Errorf("attrs[age_over_18] = %v, %v; want true, true", got, ok)
	}
}

func TestVerifyNamespaceDigestsRejectsMissingSalt(t *testing.T) {
	// A nil random decodes fine from CBOR, so the zero value has to be refused
	// explicitly rather than relying on the length comparison being reached.
	item := IssuerSignedItem{
		DigestID:          1,
		Random:            nil,
		ElementIdentifier: "age_over_21",
		ElementValue:      false,
	}
	items, digests := wrapItemWithMatchingDigest(t, item)

	if _, err := verifyNamespaceDigests(items, digests, sha256Digest); err == nil {
		t.Fatal("an item with no random value at all was accepted")
	}
}
