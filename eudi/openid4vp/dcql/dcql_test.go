package dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPlanFromCredentialQueries(t *testing.T) {
	t.Run("single query with owned candidates", func(t *testing.T) {
		queries := []CredentialQuery{
			{Id: "q1", Format: "dc+sd-jwt"},
		}
		queryResults := map[string]*CredentialQueryResult{
			"q1": {
				OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
					{CredentialId: "test.email", Hash: "abc123"},
				},
				ObtainableDescriptors: []*clientmodels.CredentialDescriptor{
					{CredentialId: "test.email"},
				},
			},
		}

		plan, _, err := buildPlanFromCredentialQueries(queries, queryResults, nil, nil)
		require.NoError(t, err)
		require.Len(t, plan.DisclosureChoicesOverview, 1)

		pickOne := plan.DisclosureChoicesOverview[0]
		assert.False(t, pickOne.Optional)
		assert.Len(t, pickOne.OwnedOptions, 1)
		require.Len(t, pickOne.OwnedOptions[0].Credentials, 1)
		assert.Equal(t, "abc123", pickOne.OwnedOptions[0].Credentials[0].Hash)
		assert.Len(t, pickOne.ObtainableOptions, 1)
	})

	t.Run("multiple queries all required", func(t *testing.T) {
		queries := []CredentialQuery{
			{Id: "q1", Format: "dc+sd-jwt"},
			{Id: "q2", Format: "dc+sd-jwt"},
		}
		queryResults := map[string]*CredentialQueryResult{
			"q1": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h1"}}},
			"q2": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h2"}}},
		}

		plan, _, err := buildPlanFromCredentialQueries(queries, queryResults, nil, nil)
		require.NoError(t, err)
		require.Len(t, plan.DisclosureChoicesOverview, 2)
		assert.False(t, plan.DisclosureChoicesOverview[0].Optional)
		assert.False(t, plan.DisclosureChoicesOverview[1].Optional)
	})

	t.Run("missing query result returns error", func(t *testing.T) {
		queries := []CredentialQuery{{Id: "missing"}}
		_, _, err := buildPlanFromCredentialQueries(queries, map[string]*CredentialQueryResult{}, nil, nil)
		require.Error(t, err)
	})
}

func TestBuildPlanFromCredentialSets(t *testing.T) {
	t.Run("required credential set groups options", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"q1": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h1"}}},
			"q2": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h2"}}},
		}
		credSets := []CredentialSetQuery{
			{Options: [][]string{{"q1"}, {"q2"}}},
		}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)
		require.Len(t, plan.DisclosureChoicesOverview, 1)
		assert.False(t, plan.DisclosureChoicesOverview[0].Optional)
		assert.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 2)
	})

	t.Run("optional credential set", func(t *testing.T) {
		notRequired := false
		queryResults := map[string]*CredentialQueryResult{
			"q1": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h1"}}},
		}
		credSets := []CredentialSetQuery{
			{Options: [][]string{{"q1"}}, Required: &notRequired},
		}

		plan, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)
		require.Len(t, plan.DisclosureChoicesOverview, 1)
		assert.True(t, plan.DisclosureChoicesOverview[0].Optional)
	})

	t.Run("multi-query options not supported", func(t *testing.T) {
		queryResults := map[string]*CredentialQueryResult{
			"q1": {},
			"q2": {},
		}
		credSets := []CredentialSetQuery{
			{Options: [][]string{{"q1", "q2"}}},
		}

		_, _, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})

	t.Run("empty option array returns error instead of panicking", func(t *testing.T) {
		credSets := []CredentialSetQuery{
			{Options: [][]string{{}}},
		}

		_, _, err := buildPlanFromCredentialSets(map[string]*CredentialQueryResult{}, credSets, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty inner option array")
	})
}

// TestChoiceQueryIdsDistinguishQueriesAnsweredByOneCredential pins the property
// a request-wide hash-keyed map could not express: one stored credential
// answering two credential queries must be routed to both, not to whichever
// query was processed last.
//
// A verifier asking for age_over_18 and age_over_21 as two queries is answered
// twice by one age credential. With a single hash → query id map, both choices
// resolved to the second query, the first query went unanswered, and the
// verifier rejected the whole response.
func TestChoiceQueryIdsDistinguishQueriesAnsweredByOneCredential(t *testing.T) {
	const sharedHash = "one-stored-credential"

	queries := []CredentialQuery{
		{Id: "age18", Format: "mso_mdoc"},
		{Id: "age21", Format: "mso_mdoc"},
	}
	queryResults := map[string]*CredentialQueryResult{
		"age18": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
			{Hash: sharedHash, Attributes: []clientmodels.Attribute{attrAt("age_over_18")}},
		}},
		"age21": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
			{Hash: sharedHash, Attributes: []clientmodels.Attribute{attrAt("age_over_21")}},
		}},
	}

	plan, queryIds, err := buildPlanFromCredentialQueries(queries, queryResults, nil, nil)
	require.NoError(t, err)

	require.Len(t, queryIds, len(plan.DisclosureChoicesOverview),
		"the query ids must stay parallel to the choices the user is shown")
	assert.Equal(t, "age18", queryIds[0].QueryIdFor(sharedHash, pathsOf("age_over_18")))
	assert.Equal(t, "age21", queryIds[1].QueryIdFor(sharedHash, pathsOf("age_over_21")),
		"the same credential in a later choice must keep that choice's query id")
}

// A credential set merges the candidates of several queries into one pick-one,
// so within a single choice the query is a property of the candidate.
func TestChoiceQueryIdsWithinACredentialSet(t *testing.T) {
	credSets := []CredentialSetQuery{
		{Options: [][]string{{"pid"}, {"mdl"}}},
	}
	queryResults := map[string]*CredentialQueryResult{
		"pid": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
			{Hash: "pid-hash", Attributes: []clientmodels.Attribute{attrAt("family_name")}},
		}},
		"mdl": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
			{Hash: "mdl-hash", Attributes: []clientmodels.Attribute{attrAt("driving_privileges")}},
		}},
	}

	plan, queryIds, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
	require.NoError(t, err)

	require.Len(t, plan.DisclosureChoicesOverview, 1, "one set is one choice")
	require.Len(t, queryIds, 1)
	assert.Equal(t, "pid", queryIds[0].QueryIdFor("pid-hash", pathsOf("family_name")))
	assert.Equal(t, "mdl", queryIds[0].QueryIdFor("mdl-hash", pathsOf("driving_privileges")))
}

// The hard case for a credential set: both options are satisfied by the same
// stored credential, so it is offered twice in one choice and the two candidates
// differ only in the element they would reveal. The claim paths the user
// approved are what say which option — and so which query — was chosen.
func TestChoiceQueryIdsWithinASetSharedCredential(t *testing.T) {
	const sharedHash = "one-age-credential"

	credSets := []CredentialSetQuery{
		{Options: [][]string{{"age18"}, {"age21"}}},
	}
	queryResults := map[string]*CredentialQueryResult{
		"age18": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
			{Hash: sharedHash, Attributes: []clientmodels.Attribute{attrAt("age_over_18")}},
		}},
		"age21": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
			{Hash: sharedHash, Attributes: []clientmodels.Attribute{attrAt("age_over_21")}},
		}},
	}

	_, queryIds, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
	require.NoError(t, err)
	require.Len(t, queryIds, 1)

	assert.Equal(t, "age21", queryIds[0].QueryIdFor(sharedHash, pathsOf("age_over_21")),
		"picking the second option must answer the second option's query")
	assert.Equal(t, "age18", queryIds[0].QueryIdFor(sharedHash, pathsOf("age_over_18")))
	assert.Equal(t, "age18", queryIds[0].QueryIdFor(sharedHash, nil),
		"with nothing to disambiguate, the first candidate holding the credential wins")
	assert.Empty(t, queryIds[0].QueryIdFor("not-offered", pathsOf("age_over_18")),
		"a credential the choice never offered resolves to no query at all")
}

// A candidate carrying no hash cannot be selected by the app, and must not
// occupy an entry that a later lookup could match.
func TestChoiceQueryIdsSkipHashlessCandidates(t *testing.T) {
	ids := choiceQueryIds([]*clientmodels.SelectableCredentialInstance{
		{Hash: ""},
		{Hash: "real", Attributes: []clientmodels.Attribute{attrAt("age_over_18")}},
	}, "q1")

	require.Len(t, ids, 1)
	assert.Equal(t, "real", ids[0].Hash)
	assert.Equal(t, "q1", ids[0].QueryId)
}

// attrAt is a disclosed attribute at [ns, element]; a section header (nil value)
// is not a disclosed path and must not take part in matching.
func attrAt(element string) clientmodels.Attribute {
	value := clientmodels.NewAttributeValue(true)
	return clientmodels.Attribute{ClaimPath: []any{"ns", element}, Value: value}
}

func pathsOf(elements ...string) [][]any {
	paths := make([][]any, 0, len(elements))
	for _, element := range elements {
		paths = append(paths, []any{"ns", element})
	}
	return paths
}

// While a card is missing the plan has the issuance steps and the choices
// together: the app shows the whole request at once, with an empty spot (a
// pick-one without owned options) for each missing card.
func TestPlanKeepsChoicesWhileCardsAreMissing(t *testing.T) {
	queries := []CredentialQuery{
		{Id: "email", Format: "dc+sd-jwt"},
		{Id: "phone", Format: "dc+sd-jwt"},
	}
	owned := func(id, hash string) []*clientmodels.SelectableCredentialInstance {
		return []*clientmodels.SelectableCredentialInstance{{CredentialId: id, Hash: hash}}
	}
	obtainable := func(id string) []*clientmodels.CredentialDescriptor {
		return []*clientmodels.CredentialDescriptor{{CredentialId: id}}
	}
	missingPhone := map[string]*CredentialQueryResult{
		"email": {OwnedCandidates: owned("test.email", "e1"), ObtainableDescriptors: obtainable("test.email")},
		"phone": {ObtainableDescriptors: obtainable("test.phone")},
	}

	t.Run("unsatisfied: steps and choices, the missing one empty", func(t *testing.T) {
		plan, ids, err := buildPlanFromCredentialQueries(queries, missingPhone, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, plan.IssueDuringDisclosure)
		require.Len(t, plan.IssueDuringDisclosure.Steps, 1)
		require.Len(t, plan.DisclosureChoicesOverview, 2)
		assert.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 1)
		assert.Empty(t, plan.DisclosureChoicesOverview[1].OwnedOptions)
		assert.Len(t, plan.DisclosureChoicesOverview[1].ObtainableOptions, 1)
		// The query ids stay parallel to the choices.
		require.Len(t, ids, 2)
		assert.Equal(t, "email", ids[0].QueryIdFor("e1", nil))
		assert.Empty(t, ids[1])
	})

	first, _, err := buildPlanFromCredentialQueries(queries, missingPhone, nil, nil)
	require.NoError(t, err)

	t.Run("refreshed, still missing: the steps stay, nothing issued", func(t *testing.T) {
		plan, ids, err := buildPlanFromCredentialQueries(queries, missingPhone, first, nil)
		require.NoError(t, err)
		require.NotNil(t, plan.IssueDuringDisclosure)
		assert.Empty(t, plan.IssueDuringDisclosure.IssuedCredentialIds)
		require.Len(t, plan.DisclosureChoicesOverview, 2)
		assert.Empty(t, plan.DisclosureChoicesOverview[1].OwnedOptions)
		assert.Len(t, ids, 2)
	})

	t.Run("refreshed after the issuance: the new card is owned and tracked", func(t *testing.T) {
		issued := map[string]*CredentialQueryResult{
			"email": missingPhone["email"],
			"phone": {OwnedCandidates: owned("test.phone", "p1"), ObtainableDescriptors: obtainable("test.phone")},
		}
		plan, ids, err := buildPlanFromCredentialQueries(queries, issued, first, nil)
		require.NoError(t, err)
		require.NotNil(t, plan.IssueDuringDisclosure)
		assert.Contains(t, plan.IssueDuringDisclosure.IssuedCredentialIds, "test.phone")
		require.Len(t, plan.DisclosureChoicesOverview, 2)
		assert.Len(t, plan.DisclosureChoicesOverview[1].OwnedOptions, 1)
		assert.Equal(t, "phone", ids[1].QueryIdFor("p1", nil))
	})
}
