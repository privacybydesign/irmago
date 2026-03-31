package irmaclient

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
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

	// Credential sets tests (per-query results; aggregation tested in eudi/openid4vp/client)
	t.Run("satisfiable credential sets all required different purpose", testDcqlSatisfiableCredentialSetsAllRequiredDifferentPurpose)
	t.Run("satisfiable credential set two options for same purpose", testDcqlSatisfiableTwoOptionsSamePurpose)
	t.Run("satisfiable credential set two options multiple claims single candidate each", testDcqlSatisfiableTwoOptionsMultipleClaimsSingleCandidate)
	t.Run("satisfiable credential set two options multiple claims multiple candidates", testDcqlSatisfiableTwoOptionsMultipleClaimsMultipleCandidates)
	t.Run("multiple credential queries in option is plan builder concern", testDcqlMultipleCredentialQueriesInOptionIsPlanBuilderConcern)
	t.Run("handler format is dc+sd-jwt", testDcqlHandlerFormatIsSdJwtVc)

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

	// Non-required credential set (per-query; required flag is plan builder concern)
	t.Run("non-required credential set per-query results", testDcqlNonRequiredCredentialSetPerQuery)
}

// ========================================================================
// 1. Satisfiable single credential single option
// ========================================================================

func testDcqlSatisfiableSingleCredentialSingleOption(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "12345",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.email"]},
			"claims": [{"id": "9876", "path": ["email"]}]
		}]
	}`)

	info := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@email.com"})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	require.Len(t, result.OwnedCandidates, 1)
	owned := result.OwnedCandidates[0]
	assert.Equal(t, "test.test.email", owned.CredentialId)
	assert.Equal(t, info.Hash, owned.Hash)
	require.Len(t, owned.Attributes, 1)
	assert.Equal(t, "email", owned.Attributes[0].Id)
	assert.NotNil(t, owned.Attributes[0].Value)

	require.Len(t, result.ObtainableDescriptors, 1)
	assert.Equal(t, "test.test.email", result.ObtainableDescriptors[0].CredentialId)
}

// ========================================================================
// 2. Satisfiable single credential multiple options (two instances)
// ========================================================================

func testDcqlSatisfiableSingleCredentialMultipleOptions(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "identifier",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [{ "id": "email-claim-id", "path": ["email"]}]
		}]
	}`)

	info1 := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@email.com"})
	info2 := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test2@email.com"})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	require.Len(t, result.OwnedCandidates, 2)
	assert.Equal(t, "test.test.email", result.OwnedCandidates[0].CredentialId)
	assert.Equal(t, "test.test.email", result.OwnedCandidates[1].CredentialId)
	hashes := []string{result.OwnedCandidates[0].Hash, result.OwnedCandidates[1].Hash}
	assert.Contains(t, hashes, info1.Hash)
	assert.Contains(t, hashes, info2.Hash)
	assert.NotEqual(t, result.OwnedCandidates[0].Hash, result.OwnedCandidates[1].Hash)

	require.Len(t, result.ObtainableDescriptors, 1)
}

// ========================================================================
// 3. Unsatisfiable single credential (nothing stored)
// ========================================================================

func testDcqlUnsatisfiableSingleCredential(t *testing.T) {
	handler, _ := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "12345",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["test.test.email"]},
			"claims": [{"id": "9876", "path": ["email"]}]
		}]
	}`)

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	assert.Empty(t, result.OwnedCandidates)
	require.Len(t, result.ObtainableDescriptors, 1)
	assert.Equal(t, "test.test.email", result.ObtainableDescriptors[0].CredentialId)
}

// ========================================================================
// 4. Satisfiable multiple credentials single option (two queries, each matched)
//    Uses test.test.email and test.test.mijnirma as separate credential types.
// ========================================================================

func testDcqlSatisfiableMultipleCredentialsSingleOption(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	emailInfo := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "yivi@test.com"})
	mijnirmaInfo := storeTestCredential(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	// Query 1: email
	result1, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)
	require.Len(t, result1.OwnedCandidates, 1)
	assert.Equal(t, "test.test.email", result1.OwnedCandidates[0].CredentialId)
	assert.Equal(t, emailInfo.Hash, result1.OwnedCandidates[0].Hash)
	require.Len(t, result1.ObtainableDescriptors, 1)

	// Query 2: mijnirma
	result2, err := handler.FindCandidates(dcqlQuery.Credentials[1])
	require.NoError(t, err)
	require.Len(t, result2.OwnedCandidates, 1)
	assert.Equal(t, "test.test.mijnirma", result2.OwnedCandidates[0].CredentialId)
	assert.Equal(t, mijnirmaInfo.Hash, result2.OwnedCandidates[0].Hash)
	require.Len(t, result2.ObtainableDescriptors, 1)
}

// ========================================================================
// 5. Unsatisfiable multiple credentials single available
// ========================================================================

func testDcqlUnsatisfiableMultipleCredentialsSingleAvailable(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	mijnirmaInfo := storeTestCredential(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	// Query 1: email - not satisfiable
	result1, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)
	assert.Empty(t, result1.OwnedCandidates)
	require.Len(t, result1.ObtainableDescriptors, 1)

	// Query 2: mijnirma - satisfiable
	result2, err := handler.FindCandidates(dcqlQuery.Credentials[1])
	require.NoError(t, err)
	require.Len(t, result2.OwnedCandidates, 1)
	assert.Equal(t, mijnirmaInfo.Hash, result2.OwnedCandidates[0].Hash)
	require.Len(t, result2.ObtainableDescriptors, 1)
}

// ========================================================================
// 6. Unsatisfiable multiple credentials none available
// ========================================================================

func testDcqlUnsatisfiableMultipleCredentialsNoneAvailable(t *testing.T) {
	handler, _ := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	// Query 1: email - not satisfiable
	result1, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)
	assert.Empty(t, result1.OwnedCandidates)
	require.Len(t, result1.ObtainableDescriptors, 1)
	assert.Equal(t, "test.test.email", result1.ObtainableDescriptors[0].CredentialId)

	// Query 2: mijnirma - not satisfiable
	result2, err := handler.FindCandidates(dcqlQuery.Credentials[1])
	require.NoError(t, err)
	assert.Empty(t, result2.OwnedCandidates)
	require.Len(t, result2.ObtainableDescriptors, 1)
	assert.Equal(t, "test.test.mijnirma", result2.ObtainableDescriptors[0].CredentialId)
}

// ========================================================================
// 7. Satisfiable multiple attributes single credential
//    Note: "domain" is not in the irma schema for test.test.email, but the
//    handler still exposes it as a basic attribute from the SD-JWT claims.
// ========================================================================

func testDcqlSatisfiableMultipleAttributesSingleCredential(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	info := storeTestCredential(t, storage, "test.test.email", map[string]string{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	require.Len(t, result.OwnedCandidates, 1)
	owned := result.OwnedCandidates[0]
	assert.Equal(t, info.Hash, owned.Hash)
	assert.Len(t, owned.Attributes, 2)
	require.Len(t, result.ObtainableDescriptors, 1)
}

// ========================================================================
// 8. Multiple attributes single credential partially available
// ========================================================================

func testDcqlMultipleAttributesSingleCredentialPartiallyAvailable(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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
	storeTestCredential(t, storage, "test.test.email", map[string]string{
		"email": "test@gmail.com",
	})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	// Credential has email but not domain, so it should not match
	assert.Empty(t, result.OwnedCandidates)
	require.Len(t, result.ObtainableDescriptors, 1)
}

// ========================================================================
// 9. Credential sets: all required, different purpose
//    (Per-query: each credential query independently satisfiable)
// ========================================================================

func testDcqlSatisfiableCredentialSetsAllRequiredDifferentPurpose(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	emailInfo := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com"})
	mijnirmaInfo := storeTestCredential(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	// Query 1: email
	result1, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)
	require.Len(t, result1.OwnedCandidates, 1)
	assert.Equal(t, emailInfo.Hash, result1.OwnedCandidates[0].Hash)
	require.Len(t, result1.ObtainableDescriptors, 1)

	// Query 2: mijnirma
	result2, err := handler.FindCandidates(dcqlQuery.Credentials[1])
	require.NoError(t, err)
	require.Len(t, result2.OwnedCandidates, 1)
	assert.Equal(t, mijnirmaInfo.Hash, result2.OwnedCandidates[0].Hash)
	require.Len(t, result2.ObtainableDescriptors, 1)
}

// ========================================================================
// 10. Credential set: two options for same purpose
//     (Per-query: each query independently satisfiable)
// ========================================================================

func testDcqlSatisfiableTwoOptionsSamePurpose(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	emailInfo := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com"})
	mijnirmaInfo := storeTestCredential(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	// Query 1: email
	result1, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)
	require.Len(t, result1.OwnedCandidates, 1)
	assert.Equal(t, emailInfo.Hash, result1.OwnedCandidates[0].Hash)

	// Query 2: mijnirma
	result2, err := handler.FindCandidates(dcqlQuery.Credentials[1])
	require.NoError(t, err)
	require.Len(t, result2.OwnedCandidates, 1)
	assert.Equal(t, mijnirmaInfo.Hash, result2.OwnedCandidates[0].Hash)
}

// ========================================================================
// 11. Credential set: two options, multiple claims, single candidate each
// ========================================================================

func testDcqlSatisfiableTwoOptionsMultipleClaimsSingleCandidate(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	emailInfo := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	loginInfo := storeTestCredential(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	// Query: email credential (multiple claims)
	result1, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)
	require.Len(t, result1.OwnedCandidates, 1)
	assert.Equal(t, emailInfo.Hash, result1.OwnedCandidates[0].Hash)
	assert.Len(t, result1.OwnedCandidates[0].Attributes, 2)

	// Query: login credential
	result2, err := handler.FindCandidates(dcqlQuery.Credentials[1])
	require.NoError(t, err)
	require.Len(t, result2.OwnedCandidates, 1)
	assert.Equal(t, loginInfo.Hash, result2.OwnedCandidates[0].Hash)
}

// ========================================================================
// 12. Credential set: two options, multiple claims, multiple candidates
// ========================================================================

func testDcqlSatisfiableTwoOptionsMultipleClaimsMultipleCandidates(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	emailInfo1 := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	emailInfo2 := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "contact@yivi.app", "domain": "yivi.app"})
	loginInfo := storeTestCredential(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	// Query: email credential - should have 2 candidates
	result1, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)
	require.Len(t, result1.OwnedCandidates, 2)
	hashes := []string{result1.OwnedCandidates[0].Hash, result1.OwnedCandidates[1].Hash}
	assert.Contains(t, hashes, emailInfo1.Hash)
	assert.Contains(t, hashes, emailInfo2.Hash)
	assert.Len(t, result1.OwnedCandidates[0].Attributes, 2)
	assert.Len(t, result1.OwnedCandidates[1].Attributes, 2)

	// Query: login credential
	result2, err := handler.FindCandidates(dcqlQuery.Credentials[1])
	require.NoError(t, err)
	require.Len(t, result2.OwnedCandidates, 1)
	assert.Equal(t, loginInfo.Hash, result2.OwnedCandidates[0].Hash)
}

// ========================================================================
// 13. Multiple credential queries in option is a plan builder concern
//     The handler only handles individual credential queries; multi-query
//     options in credential_sets are validated by the plan builder.
// ========================================================================

func testDcqlMultipleCredentialQueriesInOptionIsPlanBuilderConcern(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	storeTestCredential(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	// The handler processes each credential query independently.
	// Multi-query options (["email", "login"]) are a plan builder concern.
	// Each individual query should still work fine.
	result1, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)
	require.Len(t, result1.OwnedCandidates, 1)

	result2, err := handler.FindCandidates(dcqlQuery.Credentials[1])
	require.NoError(t, err)
	require.Len(t, result2.OwnedCandidates, 1)
}

// ========================================================================
// 14. Handler format check
//     The old test checked that a non-sd-jwt format returns an error.
//     In the new architecture, the format check is done by the openid4vp
//     client (which selects the right handler by format). The handler's
//     Format() returns "dc+sd-jwt".
// ========================================================================

func testDcqlHandlerFormatIsSdJwtVc(t *testing.T) {
	handler, _ := createTestHandler(t)

	assert.Equal(t, "dc+sd-jwt", handler.Format())
}

// ========================================================================
// 15. Single satisfiable expected value for claim
//     Uses "email" attribute which is in the irma schema, so RequestedValue
//     is properly set when a values constraint is specified.
// ========================================================================

func testDcqlSingleSatisfiableExpectedValueForClaim(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"], "values": ["test@gmail.com"]}]
		}]
	}`)

	emailInfo := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com"})
	storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com"})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	// Only the gmail credential matches the email value constraint
	require.Len(t, result.OwnedCandidates, 1)
	owned := result.OwnedCandidates[0]
	assert.Equal(t, emailInfo.Hash, owned.Hash)
	require.Len(t, owned.Attributes, 1)

	// The email attribute should have a RequestedValue since values was specified
	assert.Equal(t, "email", owned.Attributes[0].Id)
	assert.NotNil(t, owned.Attributes[0].RequestedValue)
}

// ========================================================================
// 16. Single unsatisfiable expected value for claim
// ========================================================================

func testDcqlSingleUnsatisfiableExpectedValueForClaim(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"], "values": ["nope@nowhere.com"]}]
		}]
	}`)

	storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "user@live.com"})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	// Neither credential matches the email value constraint
	assert.Empty(t, result.OwnedCandidates)
	require.Len(t, result.ObtainableDescriptors, 1)
}

// ========================================================================
// 17. Multiple value options single claim satisfiable
// ========================================================================

func testDcqlMultipleValueOptionsSingleClaimSatisfiable(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"], "values": ["test@gmail.com", "test@hotmail.com", "test@yahoo.com"]}]
		}]
	}`)

	info := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "user@live.com"})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	// Only the hotmail credential matches (email in allowed values)
	require.Len(t, result.OwnedCandidates, 1)
	assert.Equal(t, info.Hash, result.OwnedCandidates[0].Hash)

	// The email attribute should have RequestedValue
	assert.NotNil(t, result.OwnedCandidates[0].Attributes[0].RequestedValue)
}

// ========================================================================
// 18. Multiple value options single claim satisfiable multiple options
// ========================================================================

func testDcqlMultipleValueOptionsSingleClaimSatisfiableMultipleOptions(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "456", "path": ["email"], "values": ["user@gmail.com", "test@hotmail.com", "test@yahoo.com"]}]
		}]
	}`)

	infoHotmail := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	infoGmail := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "user@gmail.com"})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	// Both credentials match (their emails are in allowed values)
	require.Len(t, result.OwnedCandidates, 2)
	hashes := []string{result.OwnedCandidates[0].Hash, result.OwnedCandidates[1].Hash}
	assert.Contains(t, hashes, infoHotmail.Hash)
	assert.Contains(t, hashes, infoGmail.Hash)

	// Both should have RequestedValue on the email attribute
	for _, owned := range result.OwnedCandidates {
		require.Len(t, owned.Attributes, 1)
		assert.NotNil(t, owned.Attributes[0].RequestedValue)
	}
}

// ========================================================================
// 19. Claim sets: two options, one satisfiable
//     claim_sets: [["em"], ["do"]] where "em" has values constraint on email,
//     "do" has values constraint on domain (non-schema attribute).
//     The handler's claim_sets logic selects the first matching claim_set per
//     credential. We use email attribute for the value constraint that we
//     verify has RequestedValue.
// ========================================================================

func testDcqlClaimSetsTwoOptionsOneSatisfiable(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["not@available.com"]}, {"id": "do", "path": ["domain"], "values": ["gmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "user@gmail.com", "domain": "gmail.com"})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	// The first claim_set ["em"] requires email="not@available.com" - no match
	// The second claim_set ["do"] requires domain="gmail.com" - gmail credential matches
	require.Len(t, result.OwnedCandidates, 1)
	assert.Equal(t, infoGmail.Hash, result.OwnedCandidates[0].Hash)

	// The matched candidate should have only the "domain" attribute (from claim_set ["do"])
	require.Len(t, result.OwnedCandidates[0].Attributes, 1)
	assert.Equal(t, "domain", result.OwnedCandidates[0].Attributes[0].Id)
}

// ========================================================================
// 20. Claim sets: two options, both satisfiable, pick first claim set
// ========================================================================

func testDcqlClaimSetsTwoOptionsBothSatisfiablePickFirstClaim(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["gmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "hello@gmail.com", "domain": "gmail.com"})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	// The gmail credential satisfies both claim_sets: ["em"] (email=hello@gmail.com)
	// and ["do"] (domain=gmail.com). The handler picks the first matching claim_set.
	// So the gmail credential matches with claim_set ["em"].
	require.Len(t, result.OwnedCandidates, 1)
	assert.Equal(t, infoGmail.Hash, result.OwnedCandidates[0].Hash)

	// First claim_set ["em"] means only the "email" attribute
	require.Len(t, result.OwnedCandidates[0].Attributes, 1)
	assert.Equal(t, "email", result.OwnedCandidates[0].Attributes[0].Id)
	assert.NotNil(t, result.OwnedCandidates[0].Attributes[0].RequestedValue)
}

// ========================================================================
// 21. Claim sets: two options, both satisfiable by different instances
// ========================================================================

func testDcqlClaimSetsTwoOptionsBothSatisfiableByDifferentInstances(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["hotmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	infoHotmail := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "hello@gmail.com", "domain": "gmail.com"})

	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	// hotmail instance: email != "hello@gmail.com", so claim_set ["em"] fails.
	//   domain = "hotmail.com", so claim_set ["do"] succeeds -> matched with domain attribute.
	// gmail instance: email = "hello@gmail.com", so claim_set ["em"] succeeds -> matched with email attribute.
	require.Len(t, result.OwnedCandidates, 2)

	// Find each candidate by hash
	candidateByHash := make(map[string]*clientmodels.SelectableCredentialInstance)
	for _, c := range result.OwnedCandidates {
		candidateByHash[c.Hash] = c
	}

	// Gmail matches via claim_set ["em"] (first claim_set) -> email attribute
	gmailCandidate := candidateByHash[infoGmail.Hash]
	require.NotNil(t, gmailCandidate)
	require.Len(t, gmailCandidate.Attributes, 1)
	assert.Equal(t, "email", gmailCandidate.Attributes[0].Id)
	// email is in the irma schema, so RequestedValue is set
	assert.NotNil(t, gmailCandidate.Attributes[0].RequestedValue)

	// Hotmail matches via claim_set ["do"] (second claim_set) -> domain attribute
	hotmailCandidate := candidateByHash[infoHotmail.Hash]
	require.NotNil(t, hotmailCandidate)
	require.Len(t, hotmailCandidate.Attributes, 1)
	assert.Equal(t, "domain", hotmailCandidate.Attributes[0].Id)
	// domain is NOT in the irma schema, so RequestedValue is not set by the handler
	// (this is expected behavior - non-schema attributes get basic attribute treatment)
}

// ========================================================================
// 22. Claim sets: two options, not satisfiable
// ========================================================================

func testDcqlClaimSetsTwoOptionsNotSatisfiable(t *testing.T) {
	handler, _ := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
		"credentials": [{
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ {"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["hotmail.com"]}],
			"claim_sets": [["em"], ["do"]]
		}]
	}`)

	// No credentials stored
	result, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)

	assert.Empty(t, result.OwnedCandidates)
	require.Len(t, result.ObtainableDescriptors, 1)
	assert.Equal(t, "test.test.email", result.ObtainableDescriptors[0].CredentialId)
}

// ========================================================================
// 23. Non-required credential set (per-query results)
//     The "required" flag on credential_sets is a plan builder concern.
//     Here we test that each credential query independently returns results.
// ========================================================================

func testDcqlNonRequiredCredentialSetPerQuery(t *testing.T) {
	handler, storage := createTestHandler(t)

	dcqlQuery := parseTestDcqlQuery(t, `{
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

	emailInfo1 := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "test@gmail.com", "domain": "gmail.com"})
	emailInfo2 := storeTestCredential(t, storage, "test.test.email", map[string]string{"email": "contact@yivi.app", "domain": "yivi.app"})
	loginInfo := storeTestCredential(t, storage, "test.test.mijnirma", map[string]string{"email": "myuser@irma.app"})

	// Query 1: email - should have 2 candidates
	result1, err := handler.FindCandidates(dcqlQuery.Credentials[0])
	require.NoError(t, err)
	require.Len(t, result1.OwnedCandidates, 2)
	hashes := []string{result1.OwnedCandidates[0].Hash, result1.OwnedCandidates[1].Hash}
	assert.Contains(t, hashes, emailInfo1.Hash)
	assert.Contains(t, hashes, emailInfo2.Hash)
	for _, owned := range result1.OwnedCandidates {
		assert.Len(t, owned.Attributes, 2)
	}
	require.Len(t, result1.ObtainableDescriptors, 1)

	// Query 2: login
	result2, err := handler.FindCandidates(dcqlQuery.Credentials[1])
	require.NoError(t, err)
	require.Len(t, result2.OwnedCandidates, 1)
	assert.Equal(t, loginInfo.Hash, result2.OwnedCandidates[0].Hash)
	require.Len(t, result2.ObtainableDescriptors, 1)
}

// ========================================================================
// Test helpers
// ========================================================================

func createTestHandler(t *testing.T) (*SdJwtVcDcqlHandler, *InMemorySdJwtVcStorage) {
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

	storage, err := NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	handler := NewSdJwtVcDcqlHandler(storage, conf, keyBinder)

	return handler, storage
}

func storeTestCredential(t *testing.T, storage *InMemorySdJwtVcStorage, vct string, claims map[string]string) SdJwtVcBatchMetadata {
	t.Helper()
	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	info, sdjwts := CreateMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, vct, "https://openid4vc.staging.yivi.app", claims, 1)
	require.NoError(t, storage.StoreCredential(info, sdjwts))
	return info
}

func parseTestDcqlQuery(t *testing.T, query string) dcql.DcqlQuery {
	t.Helper()
	var result dcql.DcqlQuery
	require.NoError(t, json.Unmarshal([]byte(query), &result))
	return result
}

// findAttribute finds an attribute by ID in a slice of attributes.
func findAttribute(attrs []clientmodels.Attribute, id string) *clientmodels.Attribute {
	for i := range attrs {
		if attrs[i].Id == id {
			return &attrs[i]
		}
	}
	return nil
}

// Compile-time check
var _ clientmodels.DcqlCredentialQueryHandler = (*SdJwtVcDcqlHandler)(nil)
