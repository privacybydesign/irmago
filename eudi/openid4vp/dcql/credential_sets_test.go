package dcql

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An option of a credential set is a list of credential query ids, satisfied
// only by answering all of them together (OpenID4VP 1.0 § 6.2). In the plan an
// option is a list of slots, one per query, each with its own candidates: the
// app picks a card per slot, so no combination of candidates is ever built.
// These are the scenarios of the #803 fix, stated in slots.

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

func TestEduwalletExamCheckInIsOneOptionOfTwoSlots(t *testing.T) {
	var query DcqlQuery
	require.NoError(t, json.Unmarshal([]byte(eduwalletExamCheckInQuery), &query))
	require.NoError(t, query.Validate())

	results := map[string]*CredentialQueryResult{
		"PID": {OwnedCandidates: cands(usable("pid", "pid-hash", "family_name"))},
		"EEC": {OwnedCandidates: cands(usable("eec", "eec-hash", "code"))},
	}
	choices, err := buildChoices(query, results)
	require.NoError(t, err)

	require.Len(t, choices, 1, "one credential set is one choice")
	assert.False(t, choices[0].Optional)
	require.Len(t, choices[0].Options, 1)
	assert.Equal(t, []string{"PID", "EEC"}, slotIds(choices[0].Options[0]))
	assert.Equal(t, [][]string{{"pid-hash"}, {"eec-hash"}}, slotHashes(choices[0].Options[0]))
}

func TestChoicesFromCredentialSetsWithMultiQueryOptions(t *testing.T) {
	t.Run("an option naming two queries is one option of two slots", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: cands(usable("pid", "pid-hash", "family_name"))},
			"eec": {OwnedCandidates: cands(usable("eec", "eec-hash", "code"))},
		}
		choices := mustBuild(t, setsQuery([][]string{{"pid", "eec"}}), results)

		require.Len(t, choices, 1)
		require.Len(t, choices[0].Options, 1,
			"the two credentials answer one option together, not two alternatives")
		assert.Equal(t, []string{"pid", "eec"}, slotIds(choices[0].Options[0]),
			"the slots follow the order the option names their queries")
	})

	t.Run("several candidates per slot are listed per slot, not combined", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: cands(usable("pid", "pid-1", "family_name"), usable("pid", "pid-2", "family_name"))},
			"eec": {OwnedCandidates: cands(usable("eec", "eec-1", "code"), usable("eec", "eec-2", "code"))},
		}
		choices := mustBuild(t, setsQuery([][]string{{"pid", "eec"}}), results)

		require.Len(t, choices[0].Options, 1)
		assert.Equal(t, [][]string{{"pid-1", "pid-2"}, {"eec-1", "eec-2"}}, slotHashes(choices[0].Options[0]),
			"two slots of two candidates, where #803 built four bundles")
	})

	t.Run("options of different sizes sit side by side in one choice", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"pid":      {OwnedCandidates: cands(usable("pid", "pid-hash", "family_name"))},
			"eec":      {OwnedCandidates: cands(usable("eec", "eec-hash", "code"))},
			"passport": {OwnedCandidates: cands(usable("passport", "passport-hash", "document_number"))},
		}
		choices := mustBuild(t, setsQuery([][]string{{"pid", "eec"}, {"passport"}}), results)

		require.Len(t, choices[0].Options, 2)
		assert.Equal(t, []string{"pid", "eec"}, slotIds(choices[0].Options[0]))
		assert.Equal(t, []string{"passport"}, slotIds(choices[0].Options[1]))
	})

	t.Run("an incomplete option: the empty slot offers its type, the owned one does not", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			// Handlers describe an owned query too; a descriptor without an issue
			// URL is not offered next to a usable card.
			"pid": {
				OwnedCandidates:       cands(usable("pid", "pid-hash", "family_name")),
				ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "pid"}},
			},
			"eec": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
		}
		choices := mustBuild(t, setsQuery([][]string{{"pid", "eec"}}), results)

		option := choices[0].Options[0]
		assert.Equal(t, [][]string{{"pid-hash"}, {}}, slotHashes(option))
		assert.Empty(t, option.Slots[0].Obtainable, "the card the user holds is not asked for again")
		assert.Equal(t, []string{"eec"}, descriptorIdsOf(option.Slots[1].Obtainable))
	})

	t.Run("an option missing both credentials offers both", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"pid": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "pid"}}},
			"eec": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
		}
		choices := mustBuild(t, setsQuery([][]string{{"pid", "eec"}}), results)

		option := choices[0].Options[0]
		assert.Equal(t, []string{"pid"}, descriptorIdsOf(option.Slots[0].Obtainable))
		assert.Equal(t, []string{"eec"}, descriptorIdsOf(option.Slots[1].Obtainable))
	})

	t.Run("a slot that can be added in several ways lists each way", func(t *testing.T) {
		// A query's descriptors are alternatives (for instance one per vct value).
		results := map[string]*CredentialQueryResult{
			"pid": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "pid-a"}, {CredentialId: "pid-b"}}},
			"eec": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
		}
		choices := mustBuild(t, setsQuery([][]string{{"pid", "eec"}}), results)

		assert.Equal(t, []string{"pid-a", "pid-b"}, descriptorIdsOf(choices[0].Options[0].Slots[0].Obtainable))
	})

	t.Run("an incomplete option and a complete one are both options", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"pid":      {OwnedCandidates: cands(usable("pid", "pid-hash", "family_name"))},
			"eec":      {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
			"passport": {OwnedCandidates: cands(usable("passport", "passport-hash", "document_number"))},
		}
		choices := mustBuild(t, setsQuery([][]string{{"pid", "eec"}, {"passport"}}), results)

		require.Len(t, choices[0].Options, 2, "an option is listed whether or not it is complete")
		assert.Equal(t, [][]string{{"pid-hash"}, {}}, slotHashes(choices[0].Options[0]))
		assert.Equal(t, [][]string{{"passport-hash"}}, slotHashes(choices[0].Options[1]))
	})

	t.Run("after the missing credential is issued its slot has it", func(t *testing.T) {
		query := setsQuery([][]string{{"pid", "eec"}})
		before := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: cands(usable("pid", "pid-hash", "family_name"))},
			"eec": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
		}
		choices := mustBuild(t, query, before)
		assert.Equal(t, [][]string{{"pid-hash"}, {}}, slotHashes(choices[0].Options[0]))

		after := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: cands(usable("pid", "pid-hash", "family_name"))},
			"eec": {OwnedCandidates: cands(usable("eec", "eec-hash", "code"))},
		}
		choices = mustBuild(t, query, after)
		assert.Equal(t, [][]string{{"pid-hash"}, {"eec-hash"}}, slotHashes(choices[0].Options[0]))
		assert.Empty(t, choices[0].Options[0].Slots[1].Obtainable)
	})

	// The case #803 could not answer: two queries of the same type asking the
	// same claims in one option. Each is its own slot with the same candidates,
	// so the app can say which card answers which query.
	t.Run("two queries of one type and claims in one option are two slots", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"email1": {OwnedCandidates: cands(usable("email", "e-1", "email"), usable("email", "e-2", "email"))},
			"email2": {OwnedCandidates: cands(usable("email", "e-1", "email"), usable("email", "e-2", "email"))},
		}
		choices := mustBuild(t, setsQuery([][]string{{"email1", "email2"}}), results)

		option := choices[0].Options[0]
		assert.Equal(t, []string{"email1", "email2"}, slotIds(option))
		assert.Equal(t, [][]string{{"e-1", "e-2"}, {"e-1", "e-2"}}, slotHashes(option))
	})
}

// Several credential sets are several choices, in the order the sets appear,
// each with its own required flag.
func TestChoicesFromSeveralCredentialSets(t *testing.T) {
	notRequired := false

	t.Run("single-query options in two sets are two choices", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"email": {OwnedCandidates: cands(usable("email", "email-hash", "email"))},
			"sc":    {OwnedCandidates: cands(usable("sc", "sc-hash", "studentcardnumber"))},
			"name":  {OwnedCandidates: cands(usable("name", "name-hash", "fullname"))},
		}
		choices := mustBuild(t, setsQuery([][]string{{"email"}, {"sc"}}, [][]string{{"name"}}), results)

		require.Len(t, choices, 2)
		require.Len(t, choices[0].Options, 2)
		assert.Equal(t, []string{"email"}, slotIds(choices[0].Options[0]))
		assert.Equal(t, []string{"sc"}, slotIds(choices[0].Options[1]))
		require.Len(t, choices[1].Options, 1)
		assert.Equal(t, []string{"name"}, slotIds(choices[1].Options[0]))
	})

	t.Run("a required combined set and an optional set keep their own choices", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"pid":   {OwnedCandidates: cands(usable("pid", "pid-hash", "family_name"))},
			"eec":   {OwnedCandidates: cands(usable("eec", "eec-hash", "code"))},
			"email": {OwnedCandidates: cands(usable("email", "email-hash", "email"))},
		}
		query := setsQuery([][]string{{"pid", "eec"}}, [][]string{{"email"}})
		query.CredentialSets[1].Required = &notRequired
		choices := mustBuild(t, query, results)

		require.Len(t, choices, 2)
		assert.False(t, choices[0].Optional)
		assert.Equal(t, []string{"pid", "eec"}, slotIds(choices[0].Options[0]))
		assert.True(t, choices[1].Optional)
		assert.Equal(t, []string{"email"}, slotIds(choices[1].Options[0]))
	})

	t.Run("an optional set with an incomplete option still offers what completes it", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"pid": {OwnedCandidates: cands(usable("pid", "pid-hash", "family_name"))},
			"eec": {ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "eec"}}},
		}
		query := setsQuery([][]string{{"pid", "eec"}})
		query.CredentialSets[0].Required = &notRequired
		choices := mustBuild(t, query, results)

		assert.True(t, choices[0].Optional)
		assert.Equal(t, []string{"eec"}, descriptorIdsOf(choices[0].Options[0].Slots[1].Obtainable))
	})

	// One query in two sets has one presentation, so it is one slot wherever it
	// appears: the same id, the same candidates.
	t.Run("one query in two sets is the same slot in both", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"pid":   {OwnedCandidates: cands(usable("pid", "pid-1", "family_name"), usable("pid", "pid-2", "family_name"))},
			"email": {OwnedCandidates: cands(usable("email", "email-hash", "email"))},
			"phone": {OwnedCandidates: cands(usable("phone", "phone-hash", "phone"))},
		}
		choices := mustBuild(t, setsQuery([][]string{{"pid", "email"}}, [][]string{{"pid", "phone"}}), results)

		first, second := choices[0].Options[0].Slots[0], choices[1].Options[0].Slots[0]
		assert.Equal(t, "pid", first.Id)
		assert.Equal(t, first, second)
	})
}

// `multiple` is a property of the query, so it holds for its slot inside a
// credential set as well as without sets.
func TestMultipleIsKeptInsideCredentialSets(t *testing.T) {
	query := DcqlQuery{
		Credentials:    []CredentialQuery{{Id: "emails", Format: "fake", Multiple: true}, {Id: "name", Format: "fake"}},
		CredentialSets: []CredentialSetQuery{{Options: [][]string{{"emails", "name"}}}},
	}
	results := map[string]*CredentialQueryResult{
		"emails": {OwnedCandidates: cands(usable("email", "e-1", "email"), usable("email", "e-2", "email"), usable("email", "e-3", "email"))},
		"name":   {OwnedCandidates: cands(usable("name", "n-1", "name"))},
	}
	choices := mustBuild(t, query, results)

	slots := choices[0].Options[0].Slots
	assert.True(t, slots[0].Multiple)
	assert.Len(t, slots[0].Candidates, 3)
	assert.False(t, slots[1].Multiple)
}

// setsQuery builds a query with one credential set per argument; every query id
// a set names gets a credential query of format "fake".
func setsQuery(sets ...[][]string) DcqlQuery {
	query := DcqlQuery{}
	seen := map[string]bool{}
	for _, options := range sets {
		for _, option := range options {
			for _, id := range option {
				if !seen[id] {
					seen[id] = true
					query.Credentials = append(query.Credentials, CredentialQuery{Id: id, Format: "fake"})
				}
			}
		}
		query.CredentialSets = append(query.CredentialSets, CredentialSetQuery{Options: options})
	}
	return query
}

func mustBuild(t *testing.T, query DcqlQuery, results map[string]*CredentialQueryResult) []clientmodels.DisclosureChoice {
	t.Helper()
	require.NoError(t, query.Validate())
	choices, err := buildChoices(query, results)
	require.NoError(t, err)
	return choices
}

// usable is a stored credential offered as a usable candidate, disclosing one
// element.
func usable(credentialId, hash, element string) *clientmodels.SelectableCredentialInstance {
	return &clientmodels.SelectableCredentialInstance{
		CredentialId: credentialId,
		Hash:         hash,
		Attributes:   []clientmodels.Attribute{attrAt(element)},
		Usable:       true,
	}
}

func cands(c ...*clientmodels.SelectableCredentialInstance) []*clientmodels.SelectableCredentialInstance {
	return c
}

func slotIds(option clientmodels.DisclosureOption) []string {
	ids := make([]string, 0, len(option.Slots))
	for _, slot := range option.Slots {
		ids = append(ids, slot.Id)
	}
	return ids
}

func slotHashes(option clientmodels.DisclosureOption) [][]string {
	out := make([][]string, 0, len(option.Slots))
	for _, slot := range option.Slots {
		hashes := []string{}
		for _, c := range slot.Candidates {
			hashes = append(hashes, c.Hash)
		}
		out = append(out, hashes)
	}
	return out
}

func descriptorIdsOf(descriptors []*clientmodels.CredentialDescriptor) []string {
	ids := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		ids = append(ids, descriptor.CredentialId)
	}
	return ids
}
