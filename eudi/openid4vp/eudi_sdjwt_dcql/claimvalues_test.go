package eudi_sdjwt_dcql

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
)

// TestClaimMatchesWithArrayValueConstraint is the regression test for the same
// crash the mdoc handler had: claimMatches compared a disclosed claim value
// against a verifier-supplied `values` entry with ==, which panics when both
// interface values hold an uncomparable dynamic type. An SD-JWT array claim
// against an array constraint is that case — both are []any after JSON
// decoding — and it is reached while the permission screen is being rendered.
func TestClaimMatchesWithArrayValueConstraint(t *testing.T) {
	var payload sdjwt.ProcessedPayload
	if err := json.Unmarshal([]byte(`{"nationalities":["NL","BE"]}`), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var values []any
	if err := json.Unmarshal([]byte(`[["NL","BE"]]`), &values); err != nil {
		t.Fatalf("decode query values: %v", err)
	}

	claim := dcql.Claim{Path: []any{"nationalities"}, Values: values}
	if !claimMatches(claim, &payload) {
		t.Error("an array-valued claim did not match an identical array constraint")
	}

	var other []any
	if err := json.Unmarshal([]byte(`[["NL","DE"]]`), &other); err != nil {
		t.Fatalf("decode query values: %v", err)
	}
	otherClaim := dcql.Claim{Path: []any{"nationalities"}, Values: other}
	if claimMatches(otherClaim, &payload) {
		t.Error("an array-valued claim matched a different array constraint")
	}
}

// TestClaimMatchesWithObjectValueConstraint covers the other uncomparable shape
// JSON produces: a claim whose value is an object, against an object in
// `values`. Both are map[string]any, which == also panics on.
func TestClaimMatchesWithObjectValueConstraint(t *testing.T) {
	var payload sdjwt.ProcessedPayload
	if err := json.Unmarshal([]byte(`{"address":{"country":"NL","locality":"Nijmegen"}}`), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var values []any
	if err := json.Unmarshal([]byte(`[{"country":"NL","locality":"Nijmegen"}]`), &values); err != nil {
		t.Fatalf("decode query values: %v", err)
	}

	claim := dcql.Claim{Path: []any{"address"}, Values: values}
	if !claimMatches(claim, &payload) {
		t.Error("an object-valued claim did not match an identical object constraint")
	}
}

// TestClaimMatchesWildcardWithArrayValueConstraint reaches the comparison
// through the null-wildcard expansion in claimMatchesPath, so the fix is
// covered on that branch too.
func TestClaimMatchesWildcardWithArrayValueConstraint(t *testing.T) {
	var payload sdjwt.ProcessedPayload
	if err := json.Unmarshal([]byte(`{"driving_privileges":[{"codes":["A","B"]},{"codes":["C"]}]}`), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	var values []any
	if err := json.Unmarshal([]byte(`[["C"]]`), &values); err != nil {
		t.Fatalf("decode query values: %v", err)
	}

	claim := dcql.Claim{Path: []any{"driving_privileges", nil, "codes"}, Values: values}
	if !claimMatches(claim, &payload) {
		t.Error("no array element satisfied the array constraint under a wildcard path")
	}
}

// TestClaimMatchesNumericConstraint pins that the numeric normalisation the old
// local toFloat64 provided is preserved by the shared helper.
func TestClaimMatchesNumericConstraint(t *testing.T) {
	var payload sdjwt.ProcessedPayload
	if err := json.Unmarshal([]byte(`{"age_in_years":21,"height":1.75}`), &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	cases := []struct {
		name   string
		path   []any
		values string
		want   bool
	}{
		{"integer matches", []any{"age_in_years"}, `[21]`, true},
		{"integer mismatch", []any{"age_in_years"}, `[18]`, false},
		{"float matches", []any{"height"}, `[1.75]`, true},
		{"float mismatch", []any{"height"}, `[1.8]`, false},
		{"string against number", []any{"age_in_years"}, `["21"]`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var values []any
			if err := json.Unmarshal([]byte(tc.values), &values); err != nil {
				t.Fatalf("decode query values: %v", err)
			}
			claim := dcql.Claim{Path: tc.path, Values: values}
			if got := claimMatches(claim, &payload); got != tc.want {
				t.Errorf("claimMatches(%v, %s) = %v, want %v", tc.path, tc.values, got, tc.want)
			}
		})
	}
}

// Issue #772, disclosure side: protocol claims sit in the issuer-signed JWT,
// so they are in every verifier-side view. They must not be listed as
// disclosed attributes on the disclosure screen or in the activity log.
func TestCollectViewLeafPaths_SkipsProtocolClaims(t *testing.T) {
	for _, claim := range []string{"vct#integrity", "jti", "aud"} {
		t.Run(claim, func(t *testing.T) {
			view := map[string]any{
				"vct":        "https://vct.example.com/Cred",
				claim:        "protocol-value",
				"given_name": "Alice",
			}

			leaves := collectViewLeafPaths(view)

			if len(leaves) != 1 || len(leaves[0]) != 1 || leaves[0][0] != "given_name" {
				t.Fatalf("want only [given_name], got %v", leaves)
			}
		})
	}
}
