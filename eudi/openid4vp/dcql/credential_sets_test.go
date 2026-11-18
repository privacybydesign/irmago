package dcql

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An option of a credential set is a list of credential query ids, and it is
// satisfied only by answering all of them together (OpenID4VP 1.0 § 6.2).
// `"options": [["pid", "eec"]]` is how a verifier asks for two credentials as
// one unit. These tests pin how such an option becomes a pick-one: one bundle
// per combination of owned candidates, and an issuance step for exactly the
// credentials an option is still missing. That mirrors what an IRMA conjunction
// across credential types already produces.

// eduwalletExamCheckInQuery is the query eduwallet's exam check-in sends: an
// identity credential and an exam enrolment, required together through one
// credential set option. It also carries a `purpose` on the set, which
// OpenID4VP 1.0 does not define and wallets must ignore.
const eduwalletExamCheckInQuery = `{
	"credentials": [
		{
			"id": "PID",
			"format": "dc+sd-jwt",
			"meta": {"vct_values": ["https://nl.gov.issuer.dev.eduwallet.nl/vct/pid"]},
			"claims": [
				{"path": ["given_name"]},
				{"path": ["family_name"]},
				{"path": ["portrait"]}
			]
		},
		{
			"id": "EEC",
			"format": "vc+sd-jwt",
			"meta": {"type_values": [["ExamEnrollmentCredential"]]},
			"claims": [
				{"id": "eduId", "path": ["credentialSubject", "eduId"]},
				{"id": "code", "path": ["credentialSubject", "code"]},
				{"id": "holder", "path": ["credentialSubject", "id"]}
			],
			"claim_sets": [["eduId", "code", "holder"], ["eduId", "code"]]
		}
	],
	"credential_sets": [
		{
			"required": true,
			"options": [["PID", "EEC"]],
			"purpose": "Check your identity and your exam enrolment."
		}
	]
}`

func TestEduwalletExamCheckInQueryBuildsOneBundleOfBoth(t *testing.T) {
	var query DcqlQuery
	require.NoError(t, json.Unmarshal([]byte(eduwalletExamCheckInQuery), &query))
	require.NoError(t, query.Validate())

	result := &DcqlResult{QueryResults: map[string]*CredentialQueryResult{
		"PID": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
		"EEC": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("eec", "eec-hash", "code")}},
	}}

	plan, _, err := NewDcqlHandler(nil).BuildDisclosurePlan(query, result, nil, nil)
	require.NoError(t, err)

	require.Len(t, plan.DisclosureChoicesOverview, 1, "one credential set is one choice")
	choice := plan.DisclosureChoicesOverview[0]
	assert.False(t, choice.Optional)
	require.Len(t, choice.OwnedOptions, 1)
	assert.Equal(t, []string{"pid-hash", "eec-hash"}, bundleHashes(choice.OwnedOptions[0]))
	assert.Nil(t, plan.IssueDuringDisclosure)
}

func TestBuildPlanFromCredentialSetsWithMultiQueryOptions(t *testing.T) {
	t.Run("an option naming two queries is one bundle holding both credentials", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
			"eec": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("eec", "eec-hash", "code")}},
		}
		credSets := []CredentialSetQuery{{Options: [][]string{{"pid", "eec"}}}}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		require.Len(t, plan.DisclosureChoicesOverview, 1)
		choice := plan.DisclosureChoicesOverview[0]
		assert.False(t, choice.Optional)
		require.Len(t, choice.OwnedOptions, 1,
			"the two credentials answer one option together, so they are one bundle, not two alternatives")
		assert.Equal(t, []string{"pid-hash", "eec-hash"}, bundleHashes(choice.OwnedOptions[0]),
			"the bundle holds the credentials in the order the option names their queries")
		assert.Nil(t, plan.IssueDuringDisclosure)
	})

	t.Run("every combination of candidates is offered", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
				owned("pid", "pid-1", "family_name"),
				owned("pid", "pid-2", "family_name"),
			}},
			"eec": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
				owned("eec", "eec-1", "code"),
				owned("eec", "eec-2", "code"),
			}},
		}
		credSets := []CredentialSetQuery{{Options: [][]string{{"pid", "eec"}}}}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		require.Len(t, plan.DisclosureChoicesOverview, 1)
		var bundles [][]string
		for _, bundle := range plan.DisclosureChoicesOverview[0].OwnedOptions {
			bundles = append(bundles, bundleHashes(bundle))
		}
		assert.Equal(t, [][]string{
			{"pid-1", "eec-1"},
			{"pid-1", "eec-2"},
			{"pid-2", "eec-1"},
			{"pid-2", "eec-2"},
		}, bundles)
	})

	t.Run("options of different sizes sit side by side in one choice", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"pid":      {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
			"eec":      {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("eec", "eec-hash", "code")}},
			"passport": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("passport", "passport-hash", "document_number")}},
		}
		credSets := []CredentialSetQuery{{Options: [][]string{{"pid", "eec"}, {"passport"}}}}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		require.Len(t, plan.DisclosureChoicesOverview, 1)
		bundles := plan.DisclosureChoicesOverview[0].OwnedOptions
		require.Len(t, bundles, 2)
		assert.Equal(t, []string{"pid-hash", "eec-hash"}, bundleHashes(bundles[0]))
		assert.Equal(t, []string{"passport-hash"}, bundleHashes(bundles[1]))
	})

	t.Run("an option missing one credential asks to issue only that one", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"pid": {
				OwnedCandidates:       []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")},
				ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "pid"}},
			},
			"eec": {
				ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}},
			},
		}
		credSets := []CredentialSetQuery{{Options: [][]string{{"pid", "eec"}}}}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		assert.Nil(t, plan.DisclosureChoicesOverview,
			"the only option cannot be answered yet, so the choices wait for issuance")
		require.NotNil(t, plan.IssueDuringDisclosure)
		require.Len(t, plan.IssueDuringDisclosure.Steps, 1)
		step := plan.IssueDuringDisclosure.Steps[0]
		require.Len(t, step.Options, 1)
		assert.Equal(t, []string{"eec"}, descriptorIds(step.Options[0]),
			"the credential the user already holds is not asked for again")
	})

	t.Run("an option missing both credentials asks for both together", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"pid": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "pid"}}},
			"eec": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
		}
		credSets := []CredentialSetQuery{{Options: [][]string{{"pid", "eec"}}}}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		require.NotNil(t, plan.IssueDuringDisclosure)
		require.Len(t, plan.IssueDuringDisclosure.Steps, 1)
		step := plan.IssueDuringDisclosure.Steps[0]
		require.Len(t, step.Options, 1,
			"one option needs both credentials, so issuing either one alone must not be offered as a way out")
		assert.Equal(t, []string{"pid", "eec"}, descriptorIds(step.Options[0]))
	})

	t.Run("an option that can be issued in several ways offers each way", func(t *testing.T) {
		// A query's obtainable descriptors are alternatives (for instance one per
		// vct value), so each of them pairs with the other query's descriptor.
		queryResults := map[string]*CredentialQueryResult{
			"pid": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "pid-a"}, {CredentialId: "pid-b"}}},
			"eec": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
		}
		credSets := []CredentialSetQuery{{Options: [][]string{{"pid", "eec"}}}}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		require.NotNil(t, plan.IssueDuringDisclosure)
		require.Len(t, plan.IssueDuringDisclosure.Steps, 1)
		var options [][]string
		for _, option := range plan.IssueDuringDisclosure.Steps[0].Options {
			options = append(options, descriptorIds(option))
		}
		assert.Equal(t, [][]string{{"pid-a", "eec"}, {"pid-b", "eec"}}, options)
	})

	t.Run("an incomplete option does not hide a complete one", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"pid":      {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
			"eec":      {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
			"passport": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("passport", "passport-hash", "document_number")}},
		}
		credSets := []CredentialSetQuery{{Options: [][]string{{"pid", "eec"}, {"passport"}}}}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		require.Len(t, plan.DisclosureChoicesOverview, 1)
		choice := plan.DisclosureChoicesOverview[0]
		require.Len(t, choice.OwnedOptions, 1,
			"a pid alone does not answer the first option, so it is not offered as a bundle")
		assert.Equal(t, []string{"passport-hash"}, bundleHashes(choice.OwnedOptions[0]))
		assert.Equal(t, []string{"eec"}, descriptorIdsOf(choice.ObtainableOptions),
			"the credential that would complete the first option is offered for issuance")
		assert.Nil(t, plan.IssueDuringDisclosure, "the set can already be answered with the passport")
	})

	t.Run("after the missing credential is issued the bundle is offered", func(t *testing.T) {
		credSets := []CredentialSetQuery{{Options: [][]string{{"pid", "eec"}}}}
		before := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
			"eec": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
		}
		firstPlan, _, err := buildPlanFromCredentialSets(before, credSets, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, firstPlan.IssueDuringDisclosure)

		after := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
			"eec": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("eec", "eec-hash", "code")}},
		}
		plan, _, err := buildPlanFromCredentialSets(after, credSets, firstPlan, map[string]struct{}{"pid-hash": {}})
		require.NoError(t, err)

		require.Len(t, plan.DisclosureChoicesOverview, 1)
		require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 1)
		assert.Equal(t, []string{"pid-hash", "eec-hash"}, bundleHashes(plan.DisclosureChoicesOverview[0].OwnedOptions[0]))
		require.NotNil(t, plan.IssueDuringDisclosure)
		assert.Contains(t, plan.IssueDuringDisclosure.IssuedCredentialIds, "eec")
	})
}

// Each credential in a bundle answers its own query, and the app sends the
// bundle back as one choice holding both. The query ids for that choice must
// resolve each credential to the query it answers, or one of them is presented
// under the wrong id and the verifier sees a query left unanswered.
func TestChoiceQueryIdsForAMultiQueryOption(t *testing.T) {
	queryResults := map[string]*CredentialQueryResult{
		"pid": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
		"eec": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("eec", "eec-hash", "code")}},
	}
	credSets := []CredentialSetQuery{{Options: [][]string{{"pid", "eec"}}}}

	plan, queryIds, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
	require.NoError(t, err)

	require.Len(t, queryIds, len(plan.DisclosureChoicesOverview))
	assert.Equal(t, "pid", queryIds[0].QueryIdFor("pid-hash", pathsOf("family_name")))
	assert.Equal(t, "eec", queryIds[0].QueryIdFor("eec-hash", pathsOf("code")))
}

// owned is a stored credential offered as a candidate, disclosing one element.
func owned(credentialId, hash, element string) *clientmodels.SelectableCredentialInstance {
	return &clientmodels.SelectableCredentialInstance{
		CredentialId: credentialId,
		Hash:         hash,
		Attributes:   []clientmodels.Attribute{attrAt(element)},
	}
}

func bundleHashes(bundle *clientmodels.DisclosureBundle) []string {
	hashes := make([]string, 0, len(bundle.Credentials))
	for _, credential := range bundle.Credentials {
		hashes = append(hashes, credential.Hash)
	}
	return hashes
}

func descriptorIds(bundle *clientmodels.IssuanceBundle) []string {
	return descriptorIdsOf(bundle.Credentials)
}

func descriptorIdsOf(descriptors []*clientmodels.CredentialDescriptor) []string {
	ids := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		ids = append(ids, descriptor.CredentialId)
	}
	return ids
}

// Several credential sets are several choices, in the order the sets appear,
// each with its own required flag and its own query ids.
func TestBuildPlanFromSeveralCredentialSets(t *testing.T) {
	notRequired := false

	t.Run("single-query options in two sets are two choices", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"email": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("email", "email-hash", "email")}},
			"sc":    {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("sc", "sc-hash", "studentcardnumber")}},
			"name":  {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("name", "name-hash", "fullname")}},
		}
		credSets := []CredentialSetQuery{
			{Options: [][]string{{"email"}, {"sc"}}},
			{Options: [][]string{{"name"}}},
		}

		plan, queryIds, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		require.Len(t, plan.DisclosureChoicesOverview, 2)
		require.Len(t, queryIds, 2, "the query ids must stay parallel to the choices")
		first, second := plan.DisclosureChoicesOverview[0], plan.DisclosureChoicesOverview[1]
		require.Len(t, first.OwnedOptions, 2)
		assert.Equal(t, []string{"email-hash"}, bundleHashes(first.OwnedOptions[0]))
		assert.Equal(t, []string{"sc-hash"}, bundleHashes(first.OwnedOptions[1]))
		require.Len(t, second.OwnedOptions, 1)
		assert.Equal(t, []string{"name-hash"}, bundleHashes(second.OwnedOptions[0]))
		assert.Equal(t, "sc", queryIds[0].QueryIdFor("sc-hash", pathsOf("studentcardnumber")))
		assert.Equal(t, "name", queryIds[1].QueryIdFor("name-hash", pathsOf("fullname")))
	})

	t.Run("a required combined set and an optional set keep their own choices", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"pid":   {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
			"eec":   {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("eec", "eec-hash", "code")}},
			"email": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("email", "email-hash", "email")}},
		}
		credSets := []CredentialSetQuery{
			{Options: [][]string{{"pid", "eec"}}},
			{Options: [][]string{{"email"}}, Required: &notRequired},
		}

		plan, queryIds, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		require.Len(t, plan.DisclosureChoicesOverview, 2)
		combined, optional := plan.DisclosureChoicesOverview[0], plan.DisclosureChoicesOverview[1]
		assert.False(t, combined.Optional)
		require.Len(t, combined.OwnedOptions, 1)
		assert.Equal(t, []string{"pid-hash", "eec-hash"}, bundleHashes(combined.OwnedOptions[0]))
		assert.True(t, optional.Optional)
		require.Len(t, optional.OwnedOptions, 1)
		assert.Equal(t, []string{"email-hash"}, bundleHashes(optional.OwnedOptions[0]))

		require.Len(t, queryIds, 2)
		assert.Equal(t, "pid", queryIds[0].QueryIdFor("pid-hash", pathsOf("family_name")))
		assert.Equal(t, "eec", queryIds[0].QueryIdFor("eec-hash", pathsOf("code")))
		assert.Equal(t, "email", queryIds[1].QueryIdFor("email-hash", pathsOf("email")))
		assert.Empty(t, queryIds[1].QueryIdFor("pid-hash", pathsOf("family_name")),
			"a credential the optional choice never offered resolves to no query in it")
	})

	t.Run("an optional set with an incomplete combined option asks for no issuance", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
			"eec": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
		}
		credSets := []CredentialSetQuery{
			{Options: [][]string{{"pid", "eec"}}, Required: &notRequired},
		}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		assert.Nil(t, plan.IssueDuringDisclosure, "the user can skip an optional set, so nothing has to be issued first")
		require.Len(t, plan.DisclosureChoicesOverview, 1)
		choice := plan.DisclosureChoicesOverview[0]
		assert.True(t, choice.Optional)
		assert.Empty(t, choice.OwnedOptions, "a pid alone does not answer the option")
		assert.Equal(t, []string{"eec"}, descriptorIdsOf(choice.ObtainableOptions),
			"the credential that would complete the option can still be issued by choice")
	})

	t.Run("only the incomplete required set asks for issuance", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"pid":   {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("pid", "pid-hash", "family_name")}},
			"eec":   {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
			"email": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{owned("email", "email-hash", "email")}},
		}
		credSets := []CredentialSetQuery{
			{Options: [][]string{{"pid", "eec"}}},
			{Options: [][]string{{"email"}}},
		}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)

		require.NotNil(t, plan.IssueDuringDisclosure)
		require.Len(t, plan.IssueDuringDisclosure.Steps, 1, "the email set is already answered")
		step := plan.IssueDuringDisclosure.Steps[0]
		require.Len(t, step.Options, 1)
		assert.Equal(t, []string{"eec"}, descriptorIds(step.Options[0]))
	})
}
