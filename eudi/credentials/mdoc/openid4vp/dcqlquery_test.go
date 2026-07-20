package openid4vp

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestNewDCQLQueryRoundTrips builds a DCQL query for a set of attributes
// and confirms RequestedAttributes extracts the exact same namespace and
// attribute list back out.
func TestNewDCQLQueryRoundTrips(t *testing.T) {
	docType := "eu.europa.ec.av.1"
	namespace := "eu.europa.ec.av.1"
	attributes := []string{"age_over_18", "age_over_21"}

	q := NewDCQLQuery("proof_of_age", docType, namespace, attributes)

	gotNS, gotAttrs, err := q.RequestedAttributes(docType)
	if err != nil {
		t.Fatalf("RequestedAttributes: %v", err)
	}
	if gotNS != namespace {
		t.Fatalf("expected namespace %q, got %q", namespace, gotNS)
	}
	if !reflect.DeepEqual(gotAttrs, attributes) {
		t.Fatalf("expected attributes %v, got %v", attributes, gotAttrs)
	}
}

// TestDCQLQueryRejectsUnknownDocType confirms RequestedAttributes errors
// out for a docType that was never requested, rather than silently
// returning an empty/zero result.
func TestDCQLQueryRejectsUnknownDocType(t *testing.T) {
	q := NewDCQLQuery("proof_of_age", "eu.europa.ec.av.1", "eu.europa.ec.av.1", []string{"age_over_18"})

	if _, _, err := q.RequestedAttributes("org.iso.18013.5.1.mDL"); err == nil {
		t.Fatalf("expected error for unrequested docType, got none")
	}
}

// TestDCQLQueryRejectsMismatchedNamespaceClaims confirms a (malformed, for
// this single-namespace profile) query whose claims span more than one
// namespace is rejected rather than silently returning just the first
// claim's namespace.
func TestDCQLQueryRejectsMismatchedNamespaceClaims(t *testing.T) {
	q := DCQLQuery{Credentials: []DCQLCredentialQuery{{
		Id:     "proof_of_age",
		Format: mdocDCQLFormat,
		Meta:   DCQLMeta{DocTypeValue: "eu.europa.ec.av.1"},
		Claims: []DCQLClaim{
			{Path: []string{"eu.europa.ec.av.1", "age_over_18"}},
			{Path: []string{"some.other.namespace", "age_over_21"}},
		},
	}}}

	if _, _, err := q.RequestedAttributes("eu.europa.ec.av.1"); err == nil {
		t.Fatalf("expected error for mismatched-namespace claims, got none")
	}
}

// TestDCQLQueryMatchesBlueprintWorkedExample confirms NewDCQLQuery's JSON
// output matches the exact shape shown in the AV Blueprint's Annex A
// worked example for requesting a Proof of Age attestation:
//
//	{"credentials": [{"id": "proof_of_age", "format": "mso_mdoc",
//	  "meta": {"doctype_value": "eu.europa.ec.av.1"},
//	  "claims": [{"path": ["eu.europa.ec.av.1", "age_over_18"]}]}]}
func TestDCQLQueryMatchesBlueprintWorkedExample(t *testing.T) {
	q := NewDCQLQuery("proof_of_age", "eu.europa.ec.av.1", "eu.europa.ec.av.1", []string{"age_over_18"})

	encoded, err := json.Marshal(q)
	if err != nil {
		t.Fatalf("marshal query: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("decode query generic: %v", err)
	}

	const want = `{
		"credentials": [{
			"id": "proof_of_age",
			"format": "mso_mdoc",
			"meta": {"doctype_value": "eu.europa.ec.av.1"},
			"claims": [{"path": ["eu.europa.ec.av.1", "age_over_18"]}]
		}]
	}`
	var wantGeneric map[string]any
	if err := json.Unmarshal([]byte(want), &wantGeneric); err != nil {
		t.Fatalf("decode want generic: %v", err)
	}

	if !reflect.DeepEqual(got, wantGeneric) {
		t.Fatalf("query shape mismatch:\ngot:  %s\nwant: %s", encoded, want)
	}
}

// TestCredentialQueryIdRoundTrips confirms CredentialQueryId returns the
// exact id NewDCQLQuery was given.
func TestCredentialQueryIdRoundTrips(t *testing.T) {
	docType := "eu.europa.ec.av.1"
	q := NewDCQLQuery("proof_of_age", docType, "eu.europa.ec.av.1", []string{"age_over_18"})

	id, err := q.CredentialQueryId(docType)
	if err != nil {
		t.Fatalf("CredentialQueryId: %v", err)
	}
	if id != "proof_of_age" {
		t.Fatalf("expected id %q, got %q", "proof_of_age", id)
	}

	if _, err := q.CredentialQueryId("org.iso.18013.5.1.mDL"); err == nil {
		t.Fatalf("expected error for unrequested docType, got none")
	}
}
