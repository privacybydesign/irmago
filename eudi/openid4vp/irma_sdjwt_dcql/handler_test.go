package irma_sdjwt_dcql_test

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/openid4vp/irma_sdjwt_dcql"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDcqlCandidateSelection(t *testing.T) {
	t.Run("satisfiable single credential single option", testSatisfiableSingleCredentialSingleOption)
	t.Run("satisfiable single credential multiple instances", testSatisfiableSingleCredentialMultipleInstances)
	t.Run("unsatisfiable single credential", testUnsatisfiableSingleCredential)
	t.Run("satisfiable multiple credentials single option each", testSatisfiableMultipleCredentialsSingleOptionEach)
	t.Run("unsatisfiable multiple credentials one available", testUnsatisfiableMultipleCredentialsOneAvailable)
	t.Run("unsatisfiable multiple credentials none available", testUnsatisfiableMultipleCredentialsNoneAvailable)
	t.Run("satisfiable multiple attributes", testSatisfiableMultipleAttributes)
	t.Run("unsatisfiable partial attributes", testUnsatisfiablePartialAttributes)
	t.Run("credential sets all required different purpose", testCredentialSetsAllRequiredDifferentPurpose)
	t.Run("credential set two options same purpose", testCredentialSetTwoOptionsSamePurpose)
	t.Run("credential set two options multiple claims single candidate each", testCredentialSetTwoOptionsMultipleClaimsSingleCandidateEach)
	t.Run("credential set two options multiple claims multiple candidates", testCredentialSetTwoOptionsMultipleClaimsMultipleCandidates)
	t.Run("multiple credential queries in option are slots of one option", testMultipleCredentialQueriesInOptionAreSlots)
	t.Run("invalid format returns error", testInvalidFormatReturnsError)
	t.Run("satisfiable predefined value", testSatisfiablePredefinedValue)
	t.Run("unsatisfiable predefined value", testUnsatisfiablePredefinedValue)
	t.Run("multiple allowed values single match", testMultipleAllowedValuesSingleMatch)
	t.Run("multiple allowed values multiple matches", testMultipleAllowedValuesMultipleMatches)
	t.Run("claim sets one option satisfiable", testClaimSetsOneOptionSatisfiable)
	t.Run("claim sets both satisfiable picks first", testClaimSetsBothSatisfiablePicksFirst)
	t.Run("claim sets both satisfiable by different instances", testClaimSetsBothSatisfiableByDifferentInstances)
	t.Run("claim sets not satisfiable", testClaimSetsNotSatisfiable)
	t.Run("non-required credential set", testNonRequiredCredentialSet)
	t.Run("empty claim path does not panic", testEmptyClaimPathDoesNotPanic)
}

func testSatisfiableSingleCredentialSingleOption(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@email.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": ["email"] }]
		}]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 1, obtainable: 0})
	require.Len(t, firstCard(t, plan.Choices[0]).Credentials, 1)
	cred := firstCard(t, plan.Choices[0]).Credentials[0]
	assert.Equal(t, "test.test.email", cred.CredentialId)
	assert.Equal(t, []any{"email"}, cred.Attributes[0].ClaimPath)
}

func testSatisfiableSingleCredentialMultipleInstances(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	info1 := storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@test.com"})
	info2 := storeTestCred(t, s, "test.test.email", map[string]string{"email": "b@test.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": ["email"] }]
		}]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 2, obtainable: 0})
	hashes := ownedHashes(plan.Choices[0])
	assert.Contains(t, hashes, info1.Hash)
	assert.Contains(t, hashes, info2.Hash)
}

func testUnsatisfiableSingleCredential(t *testing.T) {
	h, _ := createTestDcqlHandler(t)

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": ["email"] }]
		}]
	}`)

	requireUnsatisfiable(t, plan, 1)
	assert.Equal(t, "test.test.email", firstMissing(t, plan).CredentialId)
}

func testSatisfiableMultipleCredentialsSingleOptionEach(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@test.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@test.com"})

	plan := buildPlan(t, h, `{
		"credentials": [
			{
				"id": "q1",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.email"] },
				"claims": [{ "path": ["email"] }]
			},
			{
				"id": "q2",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.mijnirma"] },
				"claims": [{ "path": ["email"] }]
			}
		]
	}`)

	requireSatisfiable(t, plan,
		expectChoice{cards: 1, obtainable: 0},
		expectChoice{cards: 1, obtainable: 0},
	)
}

func testUnsatisfiableMultipleCredentialsOneAvailable(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@test.com"})

	plan := buildPlan(t, h, `{
		"credentials": [
			{
				"id": "q1",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.email"] },
				"claims": [{ "path": ["email"] }]
			},
			{
				"id": "q2",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.mijnirma"] },
				"claims": [{ "path": ["email"] }]
			}
		]
	}`)

	requireUnsatisfiable(t, plan, 1)
	assert.Equal(t, "test.test.email", firstMissing(t, plan).CredentialId)
}

func testUnsatisfiableMultipleCredentialsNoneAvailable(t *testing.T) {
	h, _ := createTestDcqlHandler(t)

	plan := buildPlan(t, h, `{
		"credentials": [
			{
				"id": "q1",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.email"] },
				"claims": [{ "path": ["email"] }]
			},
			{
				"id": "q2",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.mijnirma"] },
				"claims": [{ "path": ["email"] }]
			}
		]
	}`)

	requireUnsatisfiable(t, plan, 1, 1)
}

func testSatisfiableMultipleAttributes(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [
				{ "path": ["email"] },
				{ "path": ["domain"] }
			]
		}]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 1, obtainable: 0})
	require.Len(t, firstCard(t, plan.Choices[0]).Credentials, 1)
	assert.Len(t, firstCard(t, plan.Choices[0]).Credentials[0].Attributes, 2)
}

func testUnsatisfiablePartialAttributes(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [
				{ "path": ["email"] },
				{ "path": ["domain"] }
			]
		}]
	}`)

	requireUnsatisfiable(t, plan, 1)
}

func testCredentialSetsAllRequiredDifferentPurpose(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@t.com"})

	plan := buildPlan(t, h, `{
		"credentials": [
			{
				"id": "q1",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.email"] },
				"claims": [{ "path": ["email"] }]
			},
			{
				"id": "q2",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.mijnirma"] },
				"claims": [{ "path": ["email"] }]
			}
		],
		"credential_sets": [
			{ "options": [["q1"]] },
			{ "options": [["q2"]] }
		]
	}`)

	requireSatisfiable(t, plan,
		expectChoice{cards: 1, obtainable: 0},
		expectChoice{cards: 1, obtainable: 0},
	)
}

func testCredentialSetTwoOptionsSamePurpose(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@t.com"})

	plan := buildPlan(t, h, `{
		"credentials": [
			{
				"id": "q1",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.email"] },
				"claims": [{ "path": ["email"] }]
			},
			{
				"id": "q2",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.mijnirma"] },
				"claims": [{ "path": ["email"] }]
			}
		],
		"credential_sets": [
			{ "options": [["q1"], ["q2"]] }
		]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 2, obtainable: 0})
}

func testCredentialSetTwoOptionsMultipleClaimsSingleCandidateEach(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	emailInfo := storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})
	loginInfo := storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@t.com"})

	plan := buildPlan(t, h, `{
		"credentials": [
			{
				"id": "email",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.email"] },
				"claims": [{ "path": ["email"] }, { "path": ["domain"] }]
			},
			{
				"id": "login",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.mijnirma"] },
				"claims": [{ "path": ["email"] }]
			}
		],
		"credential_sets": [
			{ "options": [["email"], ["login"]] }
		]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 2, obtainable: 0})
	byHash := ownedByHash(plan.Choices[0])
	assert.Len(t, byHash[emailInfo.Hash].Attributes, 2)
	assert.Len(t, byHash[loginInfo.Hash].Attributes, 1)
}

func testCredentialSetTwoOptionsMultipleClaimsMultipleCandidates(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "b@t.com", "domain": "t2.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "c@t.com"})

	plan := buildPlan(t, h, `{
		"credentials": [
			{
				"id": "email",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.email"] },
				"claims": [{ "path": ["email"] }, { "path": ["domain"] }]
			},
			{
				"id": "login",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.mijnirma"] },
				"claims": [{ "path": ["email"] }]
			}
		],
		"credential_sets": [
			{ "options": [["email"], ["login"]] }
		]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 3, obtainable: 0})
}

func testMultipleCredentialQueriesInOptionAreSlots(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})

	query := parseDcqlQuery(t, `{
		"credentials": [
			{
				"id": "q1",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.email"] },
				"claims": [{ "path": ["email"] }]
			},
			{
				"id": "q2",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.mijnirma"] },
				"claims": [{ "path": ["email"] }]
			}
		],
		"credential_sets": [
			{ "options": [["q1", "q2"]] }
		]
	}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	plan, err := h.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err, "an option naming two queries is answered per slot")
	require.Len(t, plan.Choices, 1)
	require.Len(t, plan.Choices[0].Options, 1)
	slots := plan.Choices[0].Options[0].Slots
	require.Len(t, slots, 2)
	assert.Equal(t, "q1", slots[0].Id)
	assert.Equal(t, "q2", slots[1].Id)
}

func testInvalidFormatReturnsError(t *testing.T) {
	h, _ := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "q1",
			"format": "mso_mdoc",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": ["email"] }]
		}]
	}`)

	_, err := h.FindCandidates(query)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential query handler")
}

func testSatisfiablePredefinedValue(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@gmail.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@hotmail.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": ["email"], "values": ["test@gmail.com"] }]
		}]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 1, obtainable: 0})
	require.Len(t, firstCard(t, plan.Choices[0]).Credentials, 1)
	assert.NotNil(t, firstCard(t, plan.Choices[0]).Credentials[0].Attributes[0].RequestedValue)
}

func testUnsatisfiablePredefinedValue(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "user@live.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": ["email"], "values": ["nope@nowhere.com"] }]
		}]
	}`)

	requireUnsatisfiable(t, plan, 1)
}

func testMultipleAllowedValuesSingleMatch(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "user@live.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{
				"path": ["email"],
				"values": ["test@gmail.com", "test@hotmail.com", "test@yahoo.com"]
			}]
		}]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 1, obtainable: 0})
}

func testMultipleAllowedValuesMultipleMatches(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "user@gmail.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{
				"path": ["email"],
				"values": ["user@gmail.com", "test@hotmail.com"]
			}]
		}]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 2, obtainable: 0})
}

func testClaimSetsOneOptionSatisfiable(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "t@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCred(t, s, "test.test.email", map[string]string{"email": "u@gmail.com", "domain": "gmail.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [
				{ "id": "em", "path": ["email"], "values": ["not@available.com"] },
				{ "id": "do", "path": ["domain"], "values": ["gmail.com"] }
			],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 1, obtainable: 0})
	bundle := firstCard(t, plan.Choices[0])
	require.Len(t, bundle.Credentials, 1)
	owned := bundle.Credentials[0]
	assert.Equal(t, infoGmail.Hash, owned.Hash)
	require.Len(t, owned.Attributes, 1)
	assert.Equal(t, []any{"domain"}, owned.Attributes[0].ClaimPath)
}

func testClaimSetsBothSatisfiablePicksFirst(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "t@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCred(t, s, "test.test.email", map[string]string{"email": "hello@gmail.com", "domain": "gmail.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [
				{ "id": "em", "path": ["email"], "values": ["hello@gmail.com"] },
				{ "id": "do", "path": ["domain"], "values": ["gmail.com"] }
			],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 1, obtainable: 0})
	bundle := firstCard(t, plan.Choices[0])
	require.Len(t, bundle.Credentials, 1)
	owned := bundle.Credentials[0]
	assert.Equal(t, infoGmail.Hash, owned.Hash)
	require.Len(t, owned.Attributes, 1)
	assert.Equal(t, []any{"email"}, owned.Attributes[0].ClaimPath) // first claim_set wins
}

func testClaimSetsBothSatisfiableByDifferentInstances(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	infoHotmail := storeTestCred(t, s, "test.test.email", map[string]string{"email": "t@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCred(t, s, "test.test.email", map[string]string{"email": "hello@gmail.com", "domain": "gmail.com"})

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [
				{ "id": "em", "path": ["email"], "values": ["hello@gmail.com"] },
				{ "id": "do", "path": ["domain"], "values": ["hotmail.com"] }
			],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 2, obtainable: 0})
	byHash := ownedByHash(plan.Choices[0])

	gmail := byHash[infoGmail.Hash]
	require.Len(t, gmail.Attributes, 1)
	assert.Equal(t, []any{"email"}, gmail.Attributes[0].ClaimPath)

	hotmail := byHash[infoHotmail.Hash]
	require.Len(t, hotmail.Attributes, 1)
	assert.Equal(t, []any{"domain"}, hotmail.Attributes[0].ClaimPath)
}

func testClaimSetsNotSatisfiable(t *testing.T) {
	h, _ := createTestDcqlHandler(t)

	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [
				{ "id": "em", "path": ["email"], "values": ["hello@gmail.com"] },
				{ "id": "do", "path": ["domain"], "values": ["hotmail.com"] }
			],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	requireUnsatisfiable(t, plan, 1)
}

func testNonRequiredCredentialSet(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "b@t.com", "domain": "t2.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "c@t.com"})

	plan := buildPlan(t, h, `{
		"credentials": [
			{
				"id": "email",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.email"] },
				"claims": [{ "path": ["email"] }, { "path": ["domain"] }]
			},
			{
				"id": "login",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["test.test.mijnirma"] },
				"claims": [{ "path": ["email"] }]
			}
		],
		"credential_sets": [
			{ "options": [["email"], ["login"]], "required": false }
		]
	}`)

	requireSatisfiable(t, plan, expectChoice{cards: 3, obtainable: 0, optional: true})
}

func testEmptyClaimPathDoesNotPanic(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com"})

	// A claim with an empty path must not panic on claim.Path[0]; it is skipped,
	// so the stored credential doesn't match and the query is unsatisfiable.
	plan := buildPlan(t, h, `{
		"credentials": [{
			"id": "q1",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "path": [] }]
		}]
	}`)

	requireUnsatisfiable(t, plan, 1)
}

// ========================================================================
// Test helpers
// ========================================================================

func buildPlan(t *testing.T, h *dcql.DcqlHandler, rawQuery string) *clientmodels.DisclosurePlan {
	t.Helper()
	query := parseDcqlQuery(t, rawQuery)
	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	plan, err := h.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)
	return plan
}

// expectChoice is what one choice of the plan holds: the usable cards of all
// its options together, and the descriptors its slots offer to add. The test
// scheme's types have no issue URL, so a slot with a usable card offers none.
type expectChoice struct {
	cards      int
	obtainable int
	optional   bool
}

// cards lists the usable candidates of all of a choice's options.
func cards(choice clientmodels.DisclosureChoice) []*clientmodels.SelectableCredentialInstance {
	var out []*clientmodels.SelectableCredentialInstance
	for _, option := range choice.Options {
		for _, slot := range option.Slots {
			for _, c := range slot.Candidates {
				if c.Usable {
					out = append(out, c)
				}
			}
		}
	}
	return out
}

func obtainable(choice clientmodels.DisclosureChoice) []*clientmodels.CredentialDescriptor {
	var out []*clientmodels.CredentialDescriptor
	for _, option := range choice.Options {
		for _, slot := range option.Slots {
			out = append(out, slot.Obtainable...)
		}
	}
	return out
}

// complete reports whether every slot of the option has a usable card.
func complete(option clientmodels.DisclosureOption) bool {
	for _, slot := range option.Slots {
		if !slices.ContainsFunc(slot.Candidates, func(c *clientmodels.SelectableCredentialInstance) bool { return c.Usable }) {
			return false
		}
	}
	return true
}

// unsatisfied lists the required choices that no option can answer yet.
func unsatisfied(plan *clientmodels.DisclosurePlan) []clientmodels.DisclosureChoice {
	var out []clientmodels.DisclosureChoice
	for _, choice := range plan.Choices {
		if !choice.Optional && !slices.ContainsFunc(choice.Options, complete) {
			out = append(out, choice)
		}
	}
	return out
}

func requireSatisfiable(t *testing.T, plan *clientmodels.DisclosurePlan, expected ...expectChoice) {
	t.Helper()
	assert.Empty(t, unsatisfied(plan))
	require.Len(t, plan.Choices, len(expected))
	for i, exp := range expected {
		choice := plan.Choices[i]
		assert.Equal(t, exp.optional, choice.Optional, "choice[%d].Optional", i)
		assert.Len(t, cards(choice), exp.cards, "choice[%d] cards", i)
		assert.Len(t, obtainable(choice), exp.obtainable, "choice[%d] obtainable", i)
	}
}

// requireUnsatisfiable checks that the required choices that cannot be
// answered yet have the given numbers of options.
func requireUnsatisfiable(t *testing.T, plan *clientmodels.DisclosurePlan, optionCounts ...int) {
	t.Helper()
	missing := unsatisfied(plan)
	require.Len(t, missing, len(optionCounts))
	for i, count := range optionCounts {
		assert.Len(t, missing[i].Options, count, "unsatisfied choice[%d].Options", i)
	}
}

// firstMissing is the first descriptor offered for a slot without a usable
// card in the first unsatisfied choice.
func firstMissing(t *testing.T, plan *clientmodels.DisclosurePlan) *clientmodels.CredentialDescriptor {
	t.Helper()
	missing := unsatisfied(plan)
	require.NotEmpty(t, missing)
	for _, slot := range missing[0].Options[0].Slots {
		if !slices.ContainsFunc(slot.Candidates, func(c *clientmodels.SelectableCredentialInstance) bool { return c.Usable }) {
			require.NotEmpty(t, slot.Obtainable)
			return slot.Obtainable[0]
		}
	}
	require.FailNow(t, "no slot without a card")
	return nil
}

type cardBundle struct {
	Credentials []*clientmodels.SelectableCredentialInstance
}

// firstCard is the first usable card of a choice, as a one-card bundle.
func firstCard(t *testing.T, choice clientmodels.DisclosureChoice) cardBundle {
	t.Helper()
	all := cards(choice)
	require.NotEmpty(t, all)
	return cardBundle{Credentials: all[:1]}
}

func ownedHashes(choice clientmodels.DisclosureChoice) []string {
	var hashes []string
	for _, c := range cards(choice) {
		hashes = append(hashes, c.Hash)
	}
	return hashes
}

func ownedByHash(choice clientmodels.DisclosureChoice) map[string]*clientmodels.SelectableCredentialInstance {
	m := make(map[string]*clientmodels.SelectableCredentialInstance)
	for _, c := range cards(choice) {
		m[c.Hash] = c
	}
	return m
}

func createTestDcqlHandler(t *testing.T) (*dcql.DcqlHandler, *irmaclient.InMemorySdJwtVcStorage) {
	t.Helper()
	testdataPath := test.FindTestdataFolder(t)
	conf, err := irma.NewConfiguration(
		filepath.Join(t.TempDir(), "irma_configuration"),
		irma.ConfigurationOptions{Assets: filepath.Join(testdataPath, "irma_configuration"), IgnorePrivateKeys: true},
	)
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	storage, err := irmaclient.NewInMemorySdJwtVcStorage()
	require.NoError(t, err)
	keyBinder := sdjwt.NewDefaultKeyBinderWithInMemoryStorage()
	return dcql.NewDcqlHandler([]dcql.DcqlCredentialQueryHandler{
		irma_sdjwt_dcql.New(storage, conf, keyBinder, nil),
	}), storage
}

func storeTestCred(t *testing.T, storage *irmaclient.InMemorySdJwtVcStorage, vct string, claims map[string]string) irmaclient.SdJwtVcBatchMetadata {
	t.Helper()
	keyBinder := sdjwt.NewDefaultKeyBinderWithInMemoryStorage()
	info, sdjwts := irmaclient.CreateMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, vct, "https://openid4vc.staging.yivi.app", claims, 1)
	require.NoError(t, storage.StoreCredential(info, sdjwts))
	return info
}

func parseDcqlQuery(t *testing.T, query string) dcql.DcqlQuery {
	t.Helper()
	var result dcql.DcqlQuery
	require.NoError(t, json.Unmarshal([]byte(query), &result))
	return result
}
