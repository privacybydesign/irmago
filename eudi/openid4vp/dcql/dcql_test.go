package dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func buildPlan(t *testing.T, query DcqlQuery, results map[string]*CredentialQueryResult, previous *clientmodels.DisclosurePlan, preExisting map[string]struct{}) *clientmodels.DisclosurePlan {
	t.Helper()
	plan, err := NewDcqlHandler(nil).BuildDisclosurePlan(query, &DcqlResult{QueryResults: results}, previous, preExisting)
	require.NoError(t, err)
	return plan
}

func TestBuildPlanFromCredentialQueries(t *testing.T) {
	t.Run("single query with owned candidates", func(t *testing.T) {
		query := DcqlQuery{Credentials: []CredentialQuery{{Id: "q1", Format: "dc+sd-jwt"}}}
		results := map[string]*CredentialQueryResult{
			"q1": {
				OwnedCandidates:       cands(usable("test.email", "abc123", "email")),
				ObtainableDescriptors: []*clientmodels.CredentialDescriptor{{CredentialId: "test.email"}},
			},
		}

		plan := buildPlan(t, query, results, nil, nil)
		require.Len(t, plan.Choices, 1)
		assert.False(t, plan.Choices[0].Optional)
		require.Len(t, plan.Choices[0].Options, 1)
		require.Len(t, plan.Choices[0].Options[0].Slots, 1)
		slot := plan.Choices[0].Options[0].Slots[0]
		assert.Equal(t, "q1", slot.Id)
		require.Len(t, slot.Candidates, 1)
		assert.Equal(t, "abc123", slot.Candidates[0].Hash)
		assert.Empty(t, slot.Obtainable, "a descriptor without issue URL is not offered beside a usable card")
	})

	t.Run("multiple queries all required", func(t *testing.T) {
		query := DcqlQuery{Credentials: []CredentialQuery{{Id: "q1", Format: "dc+sd-jwt"}, {Id: "q2", Format: "dc+sd-jwt"}}}
		results := map[string]*CredentialQueryResult{
			"q1": {OwnedCandidates: cands(usable("a", "h1", "x"))},
			"q2": {OwnedCandidates: cands(usable("b", "h2", "x"))},
		}

		plan := buildPlan(t, query, results, nil, nil)
		require.Len(t, plan.Choices, 2)
		assert.False(t, plan.Choices[0].Optional)
		assert.False(t, plan.Choices[1].Optional)
	})

	t.Run("missing query result returns error", func(t *testing.T) {
		query := DcqlQuery{Credentials: []CredentialQuery{{Id: "missing"}}}
		_, err := NewDcqlHandler(nil).BuildDisclosurePlan(query, &DcqlResult{QueryResults: map[string]*CredentialQueryResult{}}, nil, nil)
		require.Error(t, err)
	})
}

func TestBuildPlanFromCredentialSets(t *testing.T) {
	t.Run("a set with two options is one choice of two options", func(t *testing.T) {
		results := map[string]*CredentialQueryResult{
			"q1": {OwnedCandidates: cands(usable("a", "h1", "x"))},
			"q2": {OwnedCandidates: cands(usable("b", "h2", "x"))},
		}
		plan := buildPlan(t, setsQuery([][]string{{"q1"}, {"q2"}}), results, nil, nil)
		require.Len(t, plan.Choices, 1)
		assert.False(t, plan.Choices[0].Optional)
		require.Len(t, plan.Choices[0].Options, 2)
		assert.Equal(t, []string{"q1"}, slotIds(plan.Choices[0].Options[0]))
		assert.Equal(t, []string{"q2"}, slotIds(plan.Choices[0].Options[1]))
	})

	t.Run("optional credential set", func(t *testing.T) {
		notRequired := false
		query := setsQuery([][]string{{"q1"}})
		query.CredentialSets[0].Required = &notRequired
		plan := buildPlan(t, query, map[string]*CredentialQueryResult{"q1": {OwnedCandidates: cands(usable("a", "h1", "x"))}}, nil, nil)
		require.Len(t, plan.Choices, 1)
		assert.True(t, plan.Choices[0].Optional)
	})

	t.Run("an empty option is an error instead of a panic", func(t *testing.T) {
		query := DcqlQuery{
			Credentials:    []CredentialQuery{{Id: "q1", Format: "fake"}},
			CredentialSets: []CredentialSetQuery{{Options: [][]string{{}}}},
		}
		_, err := NewDcqlHandler(nil).BuildDisclosurePlan(query, &DcqlResult{QueryResults: map[string]*CredentialQueryResult{}}, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty inner option array")
	})
}

// One stored credential that answers two queries is a candidate of both
// slots: the slot id says which query each presentation answers, which is
// what a request-wide hash → query map could not.
func TestOneCredentialAnswersTwoQueriesInItsOwnSlots(t *testing.T) {
	query := DcqlQuery{Credentials: []CredentialQuery{{Id: "age18", Format: "mso_mdoc"}, {Id: "age21", Format: "mso_mdoc"}}}
	results := map[string]*CredentialQueryResult{
		"age18": {OwnedCandidates: cands(usable("age", "one-card", "age_over_18"))},
		"age21": {OwnedCandidates: cands(usable("age", "one-card", "age_over_21"))},
	}
	plan := buildPlan(t, query, results, nil, nil)
	require.Len(t, plan.Choices, 2)
	first, second := plan.Choices[0].Options[0].Slots[0], plan.Choices[1].Options[0].Slots[0]
	assert.Equal(t, "age18", first.Id)
	assert.Equal(t, "age21", second.Id)
	assert.Equal(t, "one-card", first.Candidates[0].Hash)
	assert.Equal(t, "one-card", second.Candidates[0].Hash)
	assert.Equal(t, []any{"ns", "age_over_21"}, second.Candidates[0].Attributes[0].ClaimPath)
}

// attrAt is a disclosed attribute at [ns, element].
func attrAt(element string) clientmodels.Attribute {
	value := clientmodels.NewAttributeValue(true)
	return clientmodels.Attribute{ClaimPath: []any{"ns", element}, Value: value}
}

// While a card is missing the plan has every choice, the missing slot without
// candidates and with the type to add. Once it is issued the slot has it, and
// the plan records that it was issued for this request.
func TestPlanKeepsChoicesWhileCardsAreMissing(t *testing.T) {
	query := DcqlQuery{Credentials: []CredentialQuery{{Id: "email", Format: "dc+sd-jwt"}, {Id: "phone", Format: "dc+sd-jwt"}}}
	obtainable := func(id string) []*clientmodels.CredentialDescriptor {
		return []*clientmodels.CredentialDescriptor{{CredentialId: id}}
	}
	missingPhone := map[string]*CredentialQueryResult{
		"email": {OwnedCandidates: cands(usable("test.email", "e1", "email")), ObtainableDescriptors: obtainable("test.email")},
		"phone": {ObtainableDescriptors: obtainable("test.phone")},
	}
	preExisting := map[string]struct{}{"e1": {}}

	first := buildPlan(t, query, missingPhone, nil, preExisting)
	require.Len(t, first.Choices, 2)
	assert.Equal(t, [][]string{{"e1"}}, slotHashes(first.Choices[0].Options[0]))
	assert.Equal(t, [][]string{{}}, slotHashes(first.Choices[1].Options[0]))
	assert.Equal(t, []string{"test.phone"}, descriptorIdsOf(first.Choices[1].Options[0].Slots[0].Obtainable))
	assert.Empty(t, first.IssuedCredentialIds)

	t.Run("refreshed, still missing: nothing issued", func(t *testing.T) {
		plan := buildPlan(t, query, missingPhone, first, preExisting)
		assert.Empty(t, plan.IssuedCredentialIds)
		assert.Empty(t, plan.Choices[1].Options[0].Slots[0].Candidates)
	})

	t.Run("refreshed after the issuance: the new card is a candidate and recorded", func(t *testing.T) {
		issued := map[string]*CredentialQueryResult{
			"email": missingPhone["email"],
			"phone": {OwnedCandidates: cands(usable("test.phone", "p1", "phone")), ObtainableDescriptors: obtainable("test.phone")},
		}
		plan := buildPlan(t, query, issued, first, preExisting)
		assert.Equal(t, [][]string{{"p1"}}, slotHashes(plan.Choices[1].Options[0]))
		assert.Equal(t, map[string]struct{}{"test.phone": {}}, plan.IssuedCredentialIds,
			"the email was there before; only the phone was issued for the request")
	})
}
