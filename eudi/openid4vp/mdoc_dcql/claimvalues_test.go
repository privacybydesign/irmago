package mdoc_dcql

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// TestClaimMatchesWithArrayValueConstraint exercises the uncomparable-type
// panic through the caller that actually reaches it, rather than the shared
// comparison helper alone (which dcql.TestClaimValuesEqual* covers). The path
// is FindCandidates -> selectClaims -> claimMatches, all of which run while the
// permission screen is being rendered.
func TestClaimMatchesWithArrayValueConstraint(t *testing.T) {
	var resolvedClaims map[string]map[string]any
	err := json.Unmarshal([]byte(`{"eu.europa.ec.av.1":{"age_over_NN":["18","21"]}}`), &resolvedClaims)
	require.NoError(t, err, "decode resolved claims: %v", err)

	var values []any
	err = json.Unmarshal([]byte(`[["18","21"]]`), &values)
	require.NoError(t, err, "decode query values: %v", err)

	claim := dcql.Claim{Path: []any{"eu.europa.ec.av.1", "age_over_NN"}, Values: values}
	require.True(t, claimMatches(claim, resolvedClaims), "an array-valued claim did not match an identical array constraint")

	var other []any
	err = json.Unmarshal([]byte(`[["16","21"]]`), &other)
	require.NoError(t, err, "decode query values: %v", err)
	otherClaim := dcql.Claim{Path: []any{"eu.europa.ec.av.1", "age_over_NN"}, Values: other}
	require.False(t, claimMatches(otherClaim, resolvedClaims), "an array-valued claim matched a different array constraint")
}

// TestSelectClaimsWithArrayValueConstraintFromMdlDocType is the reviewer's
// reproduction: an mdl-style array element (driving_privileges) against an
// array-valued constraint, entering at selectClaims as FindCandidates does.
func TestSelectClaimsWithArrayValueConstraintFromMdlDocType(t *testing.T) {
	var resolvedClaims map[string]map[string]any
	err := json.Unmarshal([]byte(`{"org.iso.18013.5.1":{"driving_privileges":["A","B"]}}`), &resolvedClaims)
	require.NoError(t, err, "decode resolved claims: %v", err)

	var values []any
	err = json.Unmarshal([]byte(`[["A","B"]]`), &values)
	require.NoError(t, err, "decode query values: %v", err)

	query := dcql.CredentialQuery{
		Claims: []dcql.Claim{{
			Path:   []any{"org.iso.18013.5.1", "driving_privileges"},
			Values: values,
		}},
	}

	selected := selectClaims(query, resolvedClaims)
	require.Len(t, selected, 1, "selectClaims returned %d claims, want 1", len(selected))
}

// TestClaimMatchesIntegerAcrossDecoders covers the second half of the report:
// mdoc claim values come out of CBOR as uint64/int64 while the DCQL constraint
// comes out of JSON as float64, so an age check compared unequal and a correct
// credential failed to match.
func TestClaimMatchesIntegerAcrossDecoders(t *testing.T) {
	// uint64 is what the CBOR decoder yields for an unsigned integer element.
	resolvedClaims := map[string]map[string]any{
		"eu.europa.ec.av.1": {"age_in_years": uint64(21)},
	}

	// float64 is what encoding/json yields for the verifier's constraint.
	var values []any
	err := json.Unmarshal([]byte(`[21]`), &values)
	require.NoError(t, err, "decode query values: %v", err)

	claim := dcql.Claim{Path: []any{"eu.europa.ec.av.1", "age_in_years"}, Values: values}
	require.True(t, claimMatches(claim, resolvedClaims), "a CBOR uint64 claim value did not match an equal JSON number constraint")
}
