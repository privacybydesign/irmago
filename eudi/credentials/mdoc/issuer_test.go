package mdoc

import (
	"slices"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// RANDOMIZED DIGEST ORDERING
// ============================================================

// TestClaimOrderingIsRandomized issues the same claim set many times and
// checks two things: every claim is still reachable via its digestID
// regardless of order (shuffling must never lose or duplicate an item),
// and the order actually varies across issuances. The latter is a
// regression guard against silently reverting to a deterministic (e.g.
// alphabetical) order — see the comment on the shuffle in Issue() for why
// a predictable order leaks which undisclosed claims exist relative to a
// disclosed one, for a small/guessable vocabulary like this profile's
// age_over_NN thresholds.
func TestClaimOrderingIsRandomized(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, _ := NewHolder()

	claims := map[string]any{
		"age_over_18": true,
		"age_over_16": true,
		"age_over_21": false,
		"age_over_65": false,
	}
	namespace := "eu.europa.ec.av.1"
	want := []string{"age_over_16", "age_over_18", "age_over_21", "age_over_65"}

	extractOrder := func(mdoc *MDoc) []string {
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

	const runs = 30
	seenOrders := make(map[string]bool)
	for i := 0; i < runs; i++ {
		mdoc, err := issuer.Issue("eu.europa.ec.av.1", namespace, claims, holder.PublicKey())
		if err != nil {
			t.Fatalf("Issue #%d: %v", i, err)
		}
		order := extractOrder(mdoc)

		// Round-trip correctness: same set of identifiers, regardless of order.
		gotSet := slices.Clone(order)
		slices.Sort(gotSet)
		wantSet := slices.Clone(want)
		slices.Sort(wantSet)
		if !slices.Equal(gotSet, wantSet) {
			t.Fatalf("run %d: digestID assignment lost/duplicated a claim: got %v, want set %v", i, order, wantSet)
		}

		seenOrders[strings.Join(order, ",")] = true
	}

	// With 4 claims there are 4! = 24 possible orderings; seeing only one
	// order across 30 random issuances would mean the shuffle isn't
	// actually randomizing anything.
	if len(seenOrders) < 2 {
		t.Fatalf("expected digestID order to vary across issuances (randomized shuffle), but saw only %d distinct order(s) across %d issuances — looks deterministic", len(seenOrders), runs)
	}
}

// ============================================================
// AV PROFILE CLAIM VALIDATION (Annex A §4.1.2)
// ============================================================

func TestIssueRejectsDisallowedAttribute(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, _ := NewHolder()

	_, err = issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{
			"age_over_18": true,
			"family_name": "Smith", // not permitted per Annex A §4.1.2
		}, holder.PublicKey())

	if err == nil {
		t.Fatalf("expected Issue to reject family_name, but it succeeded")
	}
	if !strings.Contains(err.Error(), "family_name") {
		t.Fatalf("expected error to name the offending attribute, got: %v", err)
	}
	t.Logf("correctly rejected disallowed attribute: %v", err)
}

func TestIssueRejectsNonBooleanValue(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, _ := NewHolder()

	_, err = issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{
			"age_over_18": true,
			"age_over_21": "true", // string, not bool — must be rejected
		}, holder.PublicKey())

	if err == nil {
		t.Fatalf("expected Issue to reject a non-bool value, but it succeeded")
	}
	if !strings.Contains(err.Error(), "age_over_21") {
		t.Fatalf("expected error to name the offending attribute, got: %v", err)
	}
	t.Logf("correctly rejected non-bool value: %v", err)
}

func TestIssueRejectsMissingMandatoryAgeOver18(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, _ := NewHolder()

	_, err = issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{
			"age_over_21": true, // age_over_18 missing — mandatory per profile
		}, holder.PublicKey())

	if err == nil {
		t.Fatalf("expected Issue to reject a claim set missing age_over_18, but it succeeded")
	}
	if !strings.Contains(err.Error(), "age_over_18") {
		t.Fatalf("expected error to mention the missing mandatory attribute, got: %v", err)
	}
	t.Logf("correctly rejected missing mandatory attribute: %v", err)
}

func TestIssueAcceptsValidAgeOverNNVariants(t *testing.T) {
	issuer, err := NewIssuer()
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	holder, _ := NewHolder()

	// age_over_18 plus a few different NN variants, all bool — should issue cleanly.
	_, err = issuer.Issue("eu.europa.ec.av.1", "eu.europa.ec.av.1",
		map[string]any{
			"age_over_18": true,
			"age_over_16": true,
			"age_over_65": false,
		}, holder.PublicKey())

	if err != nil {
		t.Fatalf("expected valid age_over_NN variants to be accepted, got: %v", err)
	}
}
