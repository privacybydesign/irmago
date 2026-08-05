package mdoc_dcql

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// TestClaimValuesEqualDoesNotPanicOnUncomparableValues is the regression test
// for the crash vector: both operands are decoded from untrusted input into
// `any`, and Go's == panics when two interface values share an uncomparable
// dynamic type. An array-valued claim compared against an array in a DCQL
// `values` constraint is that case, and it was reached while rendering the
// permission screen — so a crafted authorization request killed the wallet
// before the user was asked to consent.
func TestClaimValuesEqualDoesNotPanicOnUncomparableValues(t *testing.T) {
	// These are the shapes encoding/json produces, which is what both the cached
	// ResolvedClaims and the verifier's query decode into.
	decode := func(t *testing.T, raw string) any {
		t.Helper()
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
		return v
	}

	cases := []struct {
		name           string
		actual, expect string
		want           bool
	}{
		{"identical arrays", `["a","b"]`, `["a","b"]`, true},
		{"arrays differing in an element", `["a","b"]`, `["a","c"]`, false},
		{"arrays differing in length", `["a"]`, `["a","b"]`, false},
		{"nested arrays", `[["a",1],["b",2]]`, `[["a",1],["b",2]]`, true},
		{"nested arrays differing deep", `[["a",1]]`, `[["a",2]]`, false},
		{"identical objects", `{"x":1,"y":[2,3]}`, `{"x":1,"y":[2,3]}`, true},
		{"objects differing in a value", `{"x":1}`, `{"x":2}`, false},
		{"objects differing in key set", `{"x":1}`, `{"x":1,"y":2}`, false},
		{"array against string", `["a"]`, `"a"`, false},
		{"object against array", `{"x":1}`, `[1]`, false},
		{"null against null", `null`, `null`, true},
		{"null against value", `null`, `1`, false},
		{"empty arrays", `[]`, `[]`, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual := decode(t, tc.actual)
			expected := decode(t, tc.expect)
			// A panic here fails the test rather than taking the process down,
			// because the testing framework recovers per-test — the point is that
			// it must not panic at all.
			if got := claimValuesEqual(actual, expected); got != tc.want {
				t.Errorf("claimValuesEqual(%s, %s) = %v, want %v", tc.actual, tc.expect, got, tc.want)
			}
		})
	}
}

// TestClaimValuesEqualAcrossDecoders pins that a claim value and a query
// constraint match even when they arrived through different decoders: CBOR
// yields uint64/int64 for integers, JSON yields float64 for every number. With
// a bare ==, a value constraint on an integer claim never matched.
func TestClaimValuesEqualAcrossDecoders(t *testing.T) {
	cases := []struct {
		name           string
		actual, expect any
		want           bool
	}{
		{"cbor uint64 vs json float64", uint64(18), float64(18), true},
		{"cbor int64 negative vs json float64", int64(-7), float64(-7), true},
		{"json float64 vs cbor uint64", float64(21), uint64(21), true},
		{"different integers", uint64(18), float64(21), false},
		{"integral float vs int", float64(18.0), int(18), true},
		{"non-integral float vs int", float64(18.5), int(18), false},
		{"non-integral floats equal", float64(18.5), float64(18.5), true},
		{"bool vs bool", true, true, true},
		{"bool mismatch", true, false, false},
		{"bool vs number", true, float64(1), false},
		{"string vs string", "NL", "NL", true},
		{"string vs number", "18", float64(18), false},
		{"cbor map keys vs json map keys", map[any]any{"x": uint64(1)}, map[string]any{"x": float64(1)}, true},
		{"cbor map with non-string key", map[any]any{uint64(1): "x"}, map[string]any{"1": "x"}, false},
		{"byte strings equal", []byte{1, 2, 3}, []byte{1, 2, 3}, true},
		{"byte strings differ", []byte{1, 2, 3}, []byte{1, 2, 4}, false},
		{"uint64 beyond int64 range, equal", uint64(1) << 63, uint64(1) << 63, true},
		{"uint64 beyond int64 range, differing", uint64(1) << 63, uint64(3) << 62, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := claimValuesEqual(tc.actual, tc.expect); got != tc.want {
				t.Errorf("claimValuesEqual(%#v, %#v) = %v, want %v", tc.actual, tc.expect, got, tc.want)
			}
		})
	}
}

// TestClaimMatchesWithArrayValueConstraint exercises the panic through the
// caller that actually reaches it, rather than the helper alone.
func TestClaimMatchesWithArrayValueConstraint(t *testing.T) {
	var resolvedClaims map[string]map[string]any
	if err := json.Unmarshal([]byte(`{"eu.europa.ec.av.1":{"age_over_NN":["18","21"]}}`), &resolvedClaims); err != nil {
		t.Fatalf("decode resolved claims: %v", err)
	}

	var values []any
	if err := json.Unmarshal([]byte(`[["18","21"]]`), &values); err != nil {
		t.Fatalf("decode query values: %v", err)
	}

	claim := dcql.Claim{Path: []any{"eu.europa.ec.av.1", "age_over_NN"}, Values: values}
	if !claimMatches(claim, resolvedClaims) {
		t.Error("an array-valued claim did not match an identical array constraint")
	}

	var other []any
	if err := json.Unmarshal([]byte(`[["16","21"]]`), &other); err != nil {
		t.Fatalf("decode query values: %v", err)
	}
	otherClaim := dcql.Claim{Path: []any{"eu.europa.ec.av.1", "age_over_NN"}, Values: other}
	if claimMatches(otherClaim, resolvedClaims) {
		t.Error("an array-valued claim matched a different array constraint")
	}
}
