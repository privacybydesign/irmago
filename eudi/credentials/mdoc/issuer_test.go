package mdoc

import (
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// DETERMINISTIC DIGEST ORDERING
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

	claims := map[string]any{
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

	mdoc1, err := issuer.Issue("eu.europa.ec.av.1", namespace, claims, holder.PublicKey())
	if err != nil {
		t.Fatalf("Issue #1: %v", err)
	}
	mdoc2, err := issuer.Issue("eu.europa.ec.av.1", namespace, claims, holder.PublicKey())
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
