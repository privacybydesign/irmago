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
	t.Run("multiple credential queries in option is unsupported", testMultipleCredentialQueriesInOptionIsUnsupported)
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
}

func testSatisfiableSingleCredentialSingleOption(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@email.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 1, obtainable: 1})
	assert.Equal(t, "test.test.email", plan.DisclosureChoicesOverview[0].OwnedOptions[0].CredentialId)
	assert.Equal(t, "email", plan.DisclosureChoicesOverview[0].OwnedOptions[0].Attributes[0].Id)
}

func testSatisfiableSingleCredentialMultipleInstances(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	info1 := storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@test.com"})
	info2 := storeTestCred(t, s, "test.test.email", map[string]string{"email": "b@test.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 2, obtainable: 1})
	hashes := ownedHashes(plan.DisclosureChoicesOverview[0])
	assert.Contains(t, hashes, info1.Hash)
	assert.Contains(t, hashes, info2.Hash)
}

func testUnsatisfiableSingleCredential(t *testing.T) {
	h, _ := createTestDcqlHandler(t)

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]}]}`)

	requireUnsatisfiable(t, plan, 1)
	assert.Equal(t, "test.test.email", plan.IssueDuringDislosure.Steps[0].Options[0].CredentialId)
}

func testSatisfiableMultipleCredentialsSingleOptionEach(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@test.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@test.com"})

	plan := buildPlan(t, h, `{"credentials": [
		{"id": "q1", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]},
		{"id": "q2", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.mijnirma"]}, "claims": [{"path": ["email"]}]}
	]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 1, obtainable: 1}, expectPickOne{owned: 1, obtainable: 1})
}

func testUnsatisfiableMultipleCredentialsOneAvailable(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@test.com"})

	plan := buildPlan(t, h, `{"credentials": [
		{"id": "q1", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]},
		{"id": "q2", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.mijnirma"]}, "claims": [{"path": ["email"]}]}
	]}`)

	requireUnsatisfiable(t, plan, 1)
	assert.Equal(t, "test.test.email", plan.IssueDuringDislosure.Steps[0].Options[0].CredentialId)
}

func testUnsatisfiableMultipleCredentialsNoneAvailable(t *testing.T) {
	h, _ := createTestDcqlHandler(t)

	plan := buildPlan(t, h, `{"credentials": [
		{"id": "q1", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]},
		{"id": "q2", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.mijnirma"]}, "claims": [{"path": ["email"]}]}
	]}`)

	requireUnsatisfiable(t, plan, 1, 1)
}

func testSatisfiableMultipleAttributes(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}, {"path": ["domain"]}]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 1, obtainable: 1})
	assert.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions[0].Attributes, 2)
}

func testUnsatisfiablePartialAttributes(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}, {"path": ["domain"]}]}]}`)

	requireUnsatisfiable(t, plan, 1)
}

func testCredentialSetsAllRequiredDifferentPurpose(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@t.com"})

	plan := buildPlan(t, h, `{"credentials": [
		{"id": "q1", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]},
		{"id": "q2", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.mijnirma"]}, "claims": [{"path": ["email"]}]}
	], "credential_sets": [{"options": [["q1"]]}, {"options": [["q2"]]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 1, obtainable: 1}, expectPickOne{owned: 1, obtainable: 1})
}

func testCredentialSetTwoOptionsSamePurpose(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@t.com"})

	plan := buildPlan(t, h, `{"credentials": [
		{"id": "q1", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]},
		{"id": "q2", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.mijnirma"]}, "claims": [{"path": ["email"]}]}
	], "credential_sets": [{"options": [["q1"], ["q2"]]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 2, obtainable: 2})
}

func testCredentialSetTwoOptionsMultipleClaimsSingleCandidateEach(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	emailInfo := storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})
	loginInfo := storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "b@t.com"})

	plan := buildPlan(t, h, `{"credentials": [
		{"id": "email", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}, {"path": ["domain"]}]},
		{"id": "login", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.mijnirma"]}, "claims": [{"path": ["email"]}]}
	], "credential_sets": [{"options": [["email"], ["login"]]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 2, obtainable: 2})
	byHash := ownedByHash(plan.DisclosureChoicesOverview[0])
	assert.Len(t, byHash[emailInfo.Hash].Attributes, 2)
	assert.Len(t, byHash[loginInfo.Hash].Attributes, 1)
}

func testCredentialSetTwoOptionsMultipleClaimsMultipleCandidates(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "b@t.com", "domain": "t2.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "c@t.com"})

	plan := buildPlan(t, h, `{"credentials": [
		{"id": "email", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}, {"path": ["domain"]}]},
		{"id": "login", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.mijnirma"]}, "claims": [{"path": ["email"]}]}
	], "credential_sets": [{"options": [["email"], ["login"]]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 3, obtainable: 2})
}

func testMultipleCredentialQueriesInOptionIsUnsupported(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})

	query := parseDcqlQuery(t, `{"credentials": [
		{"id": "q1", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]},
		{"id": "q2", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.mijnirma"]}, "claims": [{"path": ["email"]}]}
	], "credential_sets": [{"options": [["q1", "q2"]]}]}`)

	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	_, err = h.BuildDisclosurePlan(query, result, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func testInvalidFormatReturnsError(t *testing.T) {
	h, _ := createTestDcqlHandler(t)

	query := parseDcqlQuery(t, `{"credentials": [{"id": "q1", "format": "mso_mdoc",
		"meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}]}]}`)

	_, err := h.FindCandidates(query)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential query handler")
}

func testSatisfiablePredefinedValue(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@gmail.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@hotmail.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]},
		"claims": [{"path": ["email"], "values": ["test@gmail.com"]}]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 1, obtainable: 1})
	assert.NotNil(t, plan.DisclosureChoicesOverview[0].OwnedOptions[0].Attributes[0].RequestedValue)
}

func testUnsatisfiablePredefinedValue(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "user@live.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]},
		"claims": [{"path": ["email"], "values": ["nope@nowhere.com"]}]}]}`)

	requireUnsatisfiable(t, plan, 1)
}

func testMultipleAllowedValuesSingleMatch(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "user@live.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]},
		"claims": [{"path": ["email"], "values": ["test@gmail.com", "test@hotmail.com", "test@yahoo.com"]}]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 1, obtainable: 1})
}

func testMultipleAllowedValuesMultipleMatches(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "test@hotmail.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "user@gmail.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]},
		"claims": [{"path": ["email"], "values": ["user@gmail.com", "test@hotmail.com"]}]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 2, obtainable: 1})
}

func testClaimSetsOneOptionSatisfiable(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "t@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCred(t, s, "test.test.email", map[string]string{"email": "u@gmail.com", "domain": "gmail.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]},
		"claims": [{"id": "em", "path": ["email"], "values": ["not@available.com"]}, {"id": "do", "path": ["domain"], "values": ["gmail.com"]}],
		"claim_sets": [["em"], ["do"]]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 1, obtainable: 1})
	owned := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	assert.Equal(t, infoGmail.Hash, owned.Hash)
	require.Len(t, owned.Attributes, 1)
	assert.Equal(t, "domain", owned.Attributes[0].Id)
}

func testClaimSetsBothSatisfiablePicksFirst(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "t@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCred(t, s, "test.test.email", map[string]string{"email": "hello@gmail.com", "domain": "gmail.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]},
		"claims": [{"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["gmail.com"]}],
		"claim_sets": [["em"], ["do"]]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 1, obtainable: 1})
	owned := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	assert.Equal(t, infoGmail.Hash, owned.Hash)
	require.Len(t, owned.Attributes, 1)
	assert.Equal(t, "email", owned.Attributes[0].Id) // first claim_set wins
}

func testClaimSetsBothSatisfiableByDifferentInstances(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	infoHotmail := storeTestCred(t, s, "test.test.email", map[string]string{"email": "t@hotmail.com", "domain": "hotmail.com"})
	infoGmail := storeTestCred(t, s, "test.test.email", map[string]string{"email": "hello@gmail.com", "domain": "gmail.com"})

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]},
		"claims": [{"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["hotmail.com"]}],
		"claim_sets": [["em"], ["do"]]}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 2, obtainable: 1})
	byHash := ownedByHash(plan.DisclosureChoicesOverview[0])

	gmail := byHash[infoGmail.Hash]
	require.Len(t, gmail.Attributes, 1)
	assert.Equal(t, "email", gmail.Attributes[0].Id)

	hotmail := byHash[infoHotmail.Hash]
	require.Len(t, hotmail.Attributes, 1)
	assert.Equal(t, "domain", hotmail.Attributes[0].Id)
}

func testClaimSetsNotSatisfiable(t *testing.T) {
	h, _ := createTestDcqlHandler(t)

	plan := buildPlan(t, h, `{"credentials": [{"id": "q1", "format": "dc+sd-jwt",
		"meta": {"vct_values": ["test.test.email"]},
		"claims": [{"id": "em", "path": ["email"], "values": ["hello@gmail.com"]}, {"id": "do", "path": ["domain"], "values": ["hotmail.com"]}],
		"claim_sets": [["em"], ["do"]]}]}`)

	requireUnsatisfiable(t, plan, 1)
}

func testNonRequiredCredentialSet(t *testing.T) {
	h, s := createTestDcqlHandler(t)
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "a@t.com", "domain": "t.com"})
	storeTestCred(t, s, "test.test.email", map[string]string{"email": "b@t.com", "domain": "t2.com"})
	storeTestCred(t, s, "test.test.mijnirma", map[string]string{"email": "c@t.com"})

	plan := buildPlan(t, h, `{"credentials": [
		{"id": "email", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.email"]}, "claims": [{"path": ["email"]}, {"path": ["domain"]}]},
		{"id": "login", "format": "dc+sd-jwt", "meta": {"vct_values": ["test.test.mijnirma"]}, "claims": [{"path": ["email"]}]}
	], "credential_sets": [{"options": [["email"], ["login"]], "required": false}]}`)

	requireSatisfiable(t, plan, expectPickOne{owned: 3, obtainable: 2, optional: true})
}

// ========================================================================
// Test helpers
// ========================================================================

type expectPickOne struct {
	owned      int
	obtainable int
	optional   bool
}

func buildPlan(t *testing.T, h *DcqlHandler, rawQuery string) *clientmodels.DisclosurePlan {
	t.Helper()
	query := parseDcqlQuery(t, rawQuery)
	result, err := h.FindCandidates(query)
	require.NoError(t, err)
	plan, err := h.BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)
	return plan
}

func requireSatisfiable(t *testing.T, plan *clientmodels.DisclosurePlan, expected ...expectPickOne) {
	t.Helper()
	assert.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, len(expected))
	for i, exp := range expected {
		po := plan.DisclosureChoicesOverview[i]
		assert.Equal(t, exp.optional, po.Optional, "pickOne[%d].Optional", i)
		assert.Len(t, po.OwnedOptions, exp.owned, "pickOne[%d].OwnedOptions", i)
		assert.Len(t, po.ObtainableOptions, exp.obtainable, "pickOne[%d].ObtainableOptions", i)
	}
}

func requireUnsatisfiable(t *testing.T, plan *clientmodels.DisclosurePlan, stepOptionCounts ...int) {
	t.Helper()
	assert.Nil(t, plan.DisclosureChoicesOverview)
	require.NotNil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.IssueDuringDislosure.Steps, len(stepOptionCounts))
	for i, count := range stepOptionCounts {
		assert.Len(t, plan.IssueDuringDislosure.Steps[i].Options, count, "step[%d].Options", i)
	}
}

func ownedHashes(po clientmodels.DisclosurePickOne) []string {
	hashes := make([]string, len(po.OwnedOptions))
	for i, o := range po.OwnedOptions {
		hashes[i] = o.Hash
	}
	return hashes
}

func ownedByHash(po clientmodels.DisclosurePickOne) map[string]*clientmodels.SelectableCredentialInstance {
	m := make(map[string]*clientmodels.SelectableCredentialInstance)
	for _, o := range po.OwnedOptions {
		m[o.Hash] = o
	}
	return m
}

func createTestDcqlHandler(t *testing.T) (*DcqlHandler, *irmaclient.InMemorySdJwtVcStorage) {
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
	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	return NewDcqlHandler([]clientmodels.DcqlCredentialQueryHandler{
		irmaclient.NewSdJwtVcDcqlHandler(storage, conf, keyBinder),
	}), storage
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
