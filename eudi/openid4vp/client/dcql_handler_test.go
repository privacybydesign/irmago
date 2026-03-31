package client

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDcqlCandidateSelection(t *testing.T) {
	// Basic single/multi credential tests
	t.Run("satisfiable single credential single option", testDcqlSatisfiableSingleCredentialSingleOption)
	t.Run("satisfiable single credential multiple options", testDcqlSatisfiableSingleCredentialMultipleOptions)
	t.Run("unsatisfiable single credential", testDcqlUnsatisfiableSingleCredential)
	t.Run("satisfiable multiple credentials single option", testDcqlSatisfiableMultipleCredentialsSingleOption)
	t.Run("unsatisfiable multiple credentials single available", testDcqlUnsatisfiableMultipleCredentialsSingleAvailable)
	t.Run("unsatisfiable multiple credentials none available", testDcqlUnsatisfiableMultipleCredentialsNoneAvailable)
	t.Run("satisfiable multiple attributes single credential", testDcqlSatisfiableMultipleAttributesSingleCredential)
	t.Run("multiple attributes single credential partially available", testDcqlMultipleAttributesSingleCredentialPartiallyAvailable)

	// Credential sets tests
	t.Run("satisfiable credential sets all required different purpose", testDcqlSatisfiableCredentialSetsAllRequiredDifferentPurpose)
	t.Run("satisfiable credential set two options for same purpose", testDcqlSatisfiableTwoOptionsSamePurpose)
	t.Run("satisfiable credential set two options multiple claims single candidate each", testDcqlSatisfiableTwoOptionsMultipleClaimsSingleCandidate)
	t.Run("satisfiable credential set two options multiple claims multiple candidates", testDcqlSatisfiableTwoOptionsMultipleClaimsMultipleCandidates)
	t.Run("multiple credential queries in option", testDcqlMultipleCredentialQueriesInOption)
	t.Run("invalid format", testDcqlInvalidFormat)

	// Value-matching tests
	t.Run("single satisfiable expected value for claim", testDcqlSingleSatisfiableExpectedValueForClaim)
	t.Run("single unsatisfiable expected value for claim", testDcqlSingleUnsatisfiableExpectedValueForClaim)
	t.Run("multiple value options single claim satisfiable", testDcqlMultipleValueOptionsSingleClaimSatisfiable)
	t.Run("multiple value options single claim satisfiable multiple options", testDcqlMultipleValueOptionsSingleClaimSatisfiableMultipleOptions)

	// Claim sets tests
	t.Run("claim sets two options one satisfiable", testDcqlClaimSetsTwoOptionsOneSatisfiable)
	t.Run("claim sets two options both satisfiable pick first claim", testDcqlClaimSetsTwoOptionsBothSatisfiablePickFirstClaim)
	t.Run("claim sets two options both satisfiable by different instances", testDcqlClaimSetsTwoOptionsBothSatisfiableByDifferentInstances)
	t.Run("claim sets two options not satisfiable", testDcqlClaimSetsTwoOptionsNotSatisfiable)

	// Non-required credential set
	t.Run("non-required credential set", testDcqlNonRequiredCredentialSet)
}

// ========================================================================
// 1. Satisfiable single credential single option
// ========================================================================

func testDcqlSatisfiableSingleCredentialSingleOption(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "12345",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.email"]},
			"claims": [{"id": "9876", "path": ["email"]}]
		}]
	}`)

	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@email.com"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	// Satisfiable: no issuance needed
	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	assert.False(t, pickOne.Optional)
	require.Len(t, pickOne.OwnedOptions, 1)
	assert.Equal(t, "test.test.email", pickOne.OwnedOptions[0].CredentialId)
	require.Len(t, pickOne.OwnedOptions[0].Attributes, 1)
	assert.Equal(t, "email", pickOne.OwnedOptions[0].Attributes[0].Id)
	assert.NotNil(t, pickOne.OwnedOptions[0].Attributes[0].Value)
	require.Len(t, pickOne.ObtainableOptions, 1)
	assert.Equal(t, "test.test.email", pickOne.ObtainableOptions[0].CredentialId)
}

// ========================================================================
// 2. Satisfiable single credential multiple options (two instances)
// ========================================================================

func testDcqlSatisfiableSingleCredentialMultipleOptions(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "identifier",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "id": "email-claim-id", "path": ["email"]}]
		}]
	}`)

	info1 := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@email.com"})
	info2 := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test2@email.com"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	require.Len(t, pickOne.OwnedOptions, 2)
	hashes := []string{pickOne.OwnedOptions[0].Hash, pickOne.OwnedOptions[1].Hash}
	assert.Contains(t, hashes, info1.Hash)
	assert.Contains(t, hashes, info2.Hash)
	assert.NotEqual(t, pickOne.OwnedOptions[0].Hash, pickOne.OwnedOptions[1].Hash)
	require.Len(t, pickOne.ObtainableOptions, 1)
}

// ========================================================================
// 3. Unsatisfiable single credential (nothing stored)
// ========================================================================

func testDcqlUnsatisfiableSingleCredential(t *testing.T) {
	handler, _ := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "12345",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.email"]},
			"claims": [{"id": "9876", "path": ["email"]}]
		}]
	}`)

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	// Unsatisfiable: issuance needed, no disclosure choices
	assert.Nil(t, plan.DisclosureChoicesOverview)
	require.NotNil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	assert.Equal(t, "test.test.email", plan.IssueDuringDislosure.Steps[0].Options[0].CredentialId)
}

// ========================================================================
// 4. Satisfiable multiple credentials single option (two queries, each matched)
// ========================================================================

func testDcqlSatisfiableMultipleCredentialsSingleOption(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"]}]
		}, {
			"id": "789",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.mijnirma"]},
			"claims": [{"id": "191112", "path": ["email"]}]
		}]
	}`)

	emailInfo := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "yivi@test.com"})
	mijnirmaInfo := storeTestCred(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 2)

	// First pick-one: email
	pickOne0 := plan.DisclosureChoicesOverview[0]
	require.Len(t, pickOne0.OwnedOptions, 1)
	assert.Equal(t, "test.test.email", pickOne0.OwnedOptions[0].CredentialId)
	assert.Equal(t, emailInfo.Hash, pickOne0.OwnedOptions[0].Hash)
	require.Len(t, pickOne0.ObtainableOptions, 1)

	// Second pick-one: mijnirma
	pickOne1 := plan.DisclosureChoicesOverview[1]
	require.Len(t, pickOne1.OwnedOptions, 1)
	assert.Equal(t, "test.test.mijnirma", pickOne1.OwnedOptions[0].CredentialId)
	assert.Equal(t, mijnirmaInfo.Hash, pickOne1.OwnedOptions[0].Hash)
	require.Len(t, pickOne1.ObtainableOptions, 1)
}

// ========================================================================
// 5. Unsatisfiable multiple credentials single available
// ========================================================================

func testDcqlUnsatisfiableMultipleCredentialsSingleAvailable(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"]}]
		}, {
			"id": "789",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.mijnirma"]},
			"claims": [{"id": "191112", "path": ["email"]}]
		}]
	}`)

	// Only store mijnirma, not email
	storeTestCred(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	// Unsatisfiable: email query has no owned options
	assert.Nil(t, plan.DisclosureChoicesOverview)
	require.NotNil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	assert.Equal(t, "test.test.email", plan.IssueDuringDislosure.Steps[0].Options[0].CredentialId)
}

// ========================================================================
// 6. Unsatisfiable multiple credentials none available
// ========================================================================

func testDcqlUnsatisfiableMultipleCredentialsNoneAvailable(t *testing.T) {
	handler, _ := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"]}]
		}, {
			"id": "789",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.mijnirma"]},
			"claims": [{"id": "191112", "path": ["email"]}]
		}]
	}`)

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	// Unsatisfiable: both queries have no owned options
	assert.Nil(t, plan.DisclosureChoicesOverview)
	require.NotNil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.IssueDuringDislosure.Steps, 2)
	assert.Equal(t, "test.test.email", plan.IssueDuringDislosure.Steps[0].Options[0].CredentialId)
	assert.Equal(t, "test.test.mijnirma", plan.IssueDuringDislosure.Steps[1].Options[0].CredentialId)
}

// ========================================================================
// 7. Satisfiable multiple attributes single credential
// ========================================================================

func testDcqlSatisfiableMultipleAttributesSingleCredential(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [
				{ "id": "456", "path": ["email"]},
				{ "id": "789", "path": ["domain"]}
			]
		}]
	}`)

	storeTestCred(t, storage, "test.test.email", map[string]string{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	require.Len(t, pickOne.OwnedOptions, 1)
	assert.Len(t, pickOne.OwnedOptions[0].Attributes, 2)
	require.Len(t, pickOne.ObtainableOptions, 1)
}

// ========================================================================
// 8. Multiple attributes single credential partially available
// ========================================================================

func testDcqlMultipleAttributesSingleCredentialPartiallyAvailable(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [
				{ "id": "456", "path": ["email"]},
				{ "id": "789", "path": ["domain"]}
			]
		}]
	}`)

	// Only store email, not domain
	storeTestCred(t, storage, "test.test.email", map[string]string{
		"email": "test@gmail.com",
	})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	// Credential has email but not domain, so it should not match -> unsatisfiable
	assert.Nil(t, plan.DisclosureChoicesOverview)
	require.NotNil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
}

// ========================================================================
// 9. Credential sets: all required, different purpose
// ========================================================================

func testDcqlSatisfiableCredentialSetsAllRequiredDifferentPurpose(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"]}]
		}, {
			"id": "789",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.mijnirma"]},
			"claims": [{"id": "191112", "path": ["email"]}]
		}],
		"credential_sets": [{
			"options": [["123"]]
		}, {
			"options": [["789"]]
		}]
	}`)

	emailInfo := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com"})
	mijnirmaInfo := storeTestCred(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 2)

	// First credential set: email
	pickOne0 := plan.DisclosureChoicesOverview[0]
	assert.False(t, pickOne0.Optional)
	require.Len(t, pickOne0.OwnedOptions, 1)
	assert.Equal(t, emailInfo.Hash, pickOne0.OwnedOptions[0].Hash)
	require.Len(t, pickOne0.ObtainableOptions, 1)

	// Second credential set: mijnirma
	pickOne1 := plan.DisclosureChoicesOverview[1]
	assert.False(t, pickOne1.Optional)
	require.Len(t, pickOne1.OwnedOptions, 1)
	assert.Equal(t, mijnirmaInfo.Hash, pickOne1.OwnedOptions[0].Hash)
	require.Len(t, pickOne1.ObtainableOptions, 1)
}

// ========================================================================
// 10. Credential set: two options for same purpose
// ========================================================================

func testDcqlSatisfiableTwoOptionsSamePurpose(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "123",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"]}]
		}, {
			"id": "789",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.mijnirma"]},
			"claims": [{"id": "191112", "path": ["email"]}]
		}],
		"credential_sets": [{
			"options": [["123"], ["789"]]
		}]
	}`)

	emailInfo := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com"})
	mijnirmaInfo := storeTestCred(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	// credential_set groups both options into 1 DisclosurePickOne
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	assert.False(t, pickOne.Optional)
	// Both queries contribute owned options to the same pick-one
	require.Len(t, pickOne.OwnedOptions, 2)
	hashes := []string{pickOne.OwnedOptions[0].Hash, pickOne.OwnedOptions[1].Hash}
	assert.Contains(t, hashes, emailInfo.Hash)
	assert.Contains(t, hashes, mijnirmaInfo.Hash)
}

// ========================================================================
// 11. Credential set: two options, multiple claims, single candidate each
// ========================================================================

func testDcqlSatisfiableTwoOptionsMultipleClaimsSingleCandidate(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"]}]
		}, {
			"id": "login",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.mijnirma"]},
			"claims": [{"id": "191112", "path": ["email"]}]
		}],
		"credential_sets": [{
			"options": [["email"], ["login"]]
		}]
	}`)

	emailInfo := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	loginInfo := storeTestCred(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	require.Len(t, pickOne.OwnedOptions, 2)
	hashes := []string{pickOne.OwnedOptions[0].Hash, pickOne.OwnedOptions[1].Hash}
	assert.Contains(t, hashes, emailInfo.Hash)
	assert.Contains(t, hashes, loginInfo.Hash)

	// Find the email candidate and check it has 2 attributes
	for _, owned := range pickOne.OwnedOptions {
		if owned.Hash == emailInfo.Hash {
			assert.Len(t, owned.Attributes, 2)
		}
		if owned.Hash == loginInfo.Hash {
			assert.Len(t, owned.Attributes, 1)
		}
	}
}

// ========================================================================
// 12. Credential set: two options, multiple claims, multiple candidates
// ========================================================================

func testDcqlSatisfiableTwoOptionsMultipleClaimsMultipleCandidates(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"]}]
		}, {
			"id": "login",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.mijnirma"]},
			"claims": [{"id": "191112", "path": ["email"]}]
		}],
		"credential_sets": [{
			"options": [["email"], ["login"]]
		}]
	}`)

	emailInfo1 := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	emailInfo2 := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "contact@yivi.app", "domain": "yivi.app"})
	loginInfo := storeTestCred(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	// 2 email instances + 1 login instance = 3 owned options
	require.Len(t, pickOne.OwnedOptions, 3)
	hashes := make([]string, 3)
	for i, owned := range pickOne.OwnedOptions {
		hashes[i] = owned.Hash
	}
	assert.Contains(t, hashes, emailInfo1.Hash)
	assert.Contains(t, hashes, emailInfo2.Hash)
	assert.Contains(t, hashes, loginInfo.Hash)
}

// ========================================================================
// 13. Multiple credential queries in option -> error from BuildDisclosurePlan
// ========================================================================

func testDcqlMultipleCredentialQueriesInOption(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"]}]
		}, {
			"id": "login",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.mijnirma"]},
			"claims": [{"id": "191112", "path": ["email"]}]
		}],
		"credential_sets": [{
			"options": [["email", "login"]]
		}]
	}`)

	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	storeTestCred(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	// BuildDisclosurePlan should return an error for multi-query options
	_, err = handler.BuildDisclosurePlan(query, result, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

// ========================================================================
// 14. Invalid format -> error from FindCandidates
// ========================================================================

func testDcqlInvalidFormat(t *testing.T) {
	handler, _ := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "12345",
			"format": "mso_mdoc",
			"meta": {"vct_values": ["test.test.email"]},
			"claims": [{"id": "9876", "path": ["email"]}]
		}]
	}`)

	_, err := handler.FindCandidates(query)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential query handler for format")
}

// ========================================================================
// 15. Single satisfiable expected value for claim
// ========================================================================

func testDcqlSingleSatisfiableExpectedValueForClaim(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"], "values": ["test@gmail.com"]}]
		}]
	}`)

	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com"})
	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	// Only the gmail credential matches the email value constraint
	require.Len(t, pickOne.OwnedOptions, 1)
	assert.Equal(t, "email", pickOne.OwnedOptions[0].Attributes[0].Id)
	assert.NotNil(t, pickOne.OwnedOptions[0].Attributes[0].RequestedValue)
}

// ========================================================================
// 16. Single unsatisfiable expected value for claim
// ========================================================================

func testDcqlSingleUnsatisfiableExpectedValueForClaim(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"], "values": ["nope@nowhere.com"]}]
		}]
	}`)

	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "user@live.com"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	// Neither credential matches -> unsatisfiable
	assert.Nil(t, plan.DisclosureChoicesOverview)
	require.NotNil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
}

// ========================================================================
// 17. Multiple value options single claim satisfiable
// ========================================================================

func testDcqlMultipleValueOptionsSingleClaimSatisfiable(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"], "values": ["test@gmail.com", "test@hotmail.com", "test@yahoo.com"]}]
		}]
	}`)

	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "user@live.com"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	// Only the hotmail credential matches (email in allowed values)
	require.Len(t, pickOne.OwnedOptions, 1)
	assert.NotNil(t, pickOne.OwnedOptions[0].Attributes[0].RequestedValue)
}

// ========================================================================
// 18. Multiple value options single claim satisfiable multiple options
// ========================================================================

func testDcqlMultipleValueOptionsSingleClaimSatisfiableMultipleOptions(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"], "values": ["user@gmail.com", "test@hotmail.com", "test@yahoo.com"]}]
		}]
	}`)

	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "user@gmail.com"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	// Both credentials match (their emails are in allowed values)
	require.Len(t, pickOne.OwnedOptions, 2)
	for _, owned := range pickOne.OwnedOptions {
		require.Len(t, owned.Attributes, 1)
		assert.NotNil(t, owned.Attributes[0].RequestedValue)
	}
}

// ========================================================================
// 19. Claim sets: two options, one satisfiable
// ========================================================================

func testDcqlClaimSetsTwoOptionsOneSatisfiable(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["not@available.com"]}, {"id": "do", "path": ["domain"], "values": ["gmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "user@gmail.com", "domain": "gmail.com"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	require.Len(t, pickOne.OwnedOptions, 1)
	assert.Equal(t, infoGmail.Hash, pickOne.OwnedOptions[0].Hash)

	// Matched via claim_set ["do"] -> only domain attribute
	require.Len(t, pickOne.OwnedOptions[0].Attributes, 1)
	assert.Equal(t, "domain", pickOne.OwnedOptions[0].Attributes[0].Id)
}

// ========================================================================
// 20. Claim sets: two options, both satisfiable, pick first claim set
// ========================================================================

func testDcqlClaimSetsTwoOptionsBothSatisfiablePickFirstClaim(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["gmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "hello@gmail.com", "domain": "gmail.com"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	require.Len(t, pickOne.OwnedOptions, 1)
	assert.Equal(t, infoGmail.Hash, pickOne.OwnedOptions[0].Hash)

	// First claim_set ["em"] means only the "email" attribute
	require.Len(t, pickOne.OwnedOptions[0].Attributes, 1)
	assert.Equal(t, "email", pickOne.OwnedOptions[0].Attributes[0].Id)
	assert.NotNil(t, pickOne.OwnedOptions[0].Attributes[0].RequestedValue)
}

// ========================================================================
// 21. Claim sets: two options, both satisfiable by different instances
// ========================================================================

func testDcqlClaimSetsTwoOptionsBothSatisfiableByDifferentInstances(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["hotmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	infoHotmail := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "hello@gmail.com", "domain": "gmail.com"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	require.Len(t, pickOne.OwnedOptions, 2)

	// Find each candidate by hash
	candidateByHash := make(map[string]*clientmodels.SelectableCredentialInstance)
	for _, c := range pickOne.OwnedOptions {
		candidateByHash[c.Hash] = c
	}

	// Gmail matches via claim_set ["em"] (first claim_set) -> email attribute
	gmailCandidate := candidateByHash[infoGmail.Hash]
	require.NotNil(t, gmailCandidate)
	require.Len(t, gmailCandidate.Attributes, 1)
	assert.Equal(t, "email", gmailCandidate.Attributes[0].Id)
	assert.NotNil(t, gmailCandidate.Attributes[0].RequestedValue)

	// Hotmail matches via claim_set ["do"] (second claim_set) -> domain attribute
	hotmailCandidate := candidateByHash[infoHotmail.Hash]
	require.NotNil(t, hotmailCandidate)
	require.Len(t, hotmailCandidate.Attributes, 1)
	assert.Equal(t, "domain", hotmailCandidate.Attributes[0].Id)
}

// ========================================================================
// 22. Claim sets: two options, not satisfiable
// ========================================================================

func testDcqlClaimSetsTwoOptionsNotSatisfiable(t *testing.T) {
	handler, _ := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["hotmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	// No credentials stored -> unsatisfiable
	assert.Nil(t, plan.DisclosureChoicesOverview)
	require.NotNil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	assert.Equal(t, "test.test.email", plan.IssueDuringDislosure.Steps[0].Options[0].CredentialId)
}

// ========================================================================
// 23. Non-required credential set
// ========================================================================

func testDcqlNonRequiredCredentialSet(t *testing.T) {
	handler, storage := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"]}, {"id": "1111", "path": ["domain"]}]
		}, {
			"id": "login",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.mijnirma"]},
			"claims": [{"id": "191112", "path": ["email"]}]
		}],
		"credential_sets": [{
			"options": [["email"], ["login"]],
			"required": false
		}]
	}`)

	emailInfo1 := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	emailInfo2 := storeTestCred(t, storage, "test.test.email", map[string]string{"email": "contact@yivi.app", "domain": "yivi.app"})
	loginInfo := storeTestCred(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	result, err := handler.FindCandidates(query)
	require.NoError(t, err)

	plan, err := handler.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	assert.True(t, pickOne.Optional)
	// 2 email instances + 1 login instance = 3 owned options
	require.Len(t, pickOne.OwnedOptions, 3)
	hashes := make([]string, 3)
	for i, owned := range pickOne.OwnedOptions {
		hashes[i] = owned.Hash
	}
	assert.Contains(t, hashes, emailInfo1.Hash)
	assert.Contains(t, hashes, emailInfo2.Hash)
	assert.Contains(t, hashes, loginInfo.Hash)

	// Email instances should have 2 attributes each
	for _, owned := range pickOne.OwnedOptions {
		if owned.CredentialId == "test.test.email" {
			assert.Len(t, owned.Attributes, 2)
		}
	}
}

// ========================================================================
// Test helpers
// ========================================================================

func createTestDcqlHandler(t *testing.T) (*DcqlHandler, *irmaclient.InMemorySdJwtVcStorage) {
	t.Helper()

	testdataPath := test.FindTestdataFolder(t)
	conf, err := irma.NewConfiguration(
		filepath.Join(t.TempDir(), "irma_configuration"),
		irma.ConfigurationOptions{
			Assets:            filepath.Join(testdataPath, "irma_configuration"),
			IgnorePrivateKeys: true,
		},
	)
	require.NoError(t, err)
	require.NoError(t, conf.ParseFolder())

	storage, err := irmaclient.NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	sdJwtHandler := irmaclient.NewSdJwtVcDcqlHandler(storage, conf, keyBinder)

	handler := NewDcqlHandler([]clientmodels.DcqlCredentialQueryHandler{sdJwtHandler})
	return handler, storage
}

func storeTestCred(t *testing.T, storage *irmaclient.InMemorySdJwtVcStorage, vct string, claims map[string]string) irmaclient.SdJwtVcBatchMetadata {
	t.Helper()
	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
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
