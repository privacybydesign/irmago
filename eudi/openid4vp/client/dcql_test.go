package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildPlanFromCredentialQueries(t *testing.T) {
	t.Run("single query with owned candidates", func(t *testing.T) {
		queries := []dcql.CredentialQuery{
			{Id: "q1", Format: "dc+sd-jwt"},
		}
		queryResults := map[string]*clientmodels.CredentialQueryResult{
			"q1": {
				OwnedCandidates: []*clientmodels.SelectableCredentialInstance{
					{CredentialId: "test.email", Hash: "abc123"},
				},
				ObtainableDescriptors: []*clientmodels.CredentialDescriptor{
					{CredentialId: "test.email"},
				},
			},
		}

		plan, err := buildPlanFromCredentialQueries(queries, queryResults, nil, nil)
		require.NoError(t, err)
		require.Len(t, plan.DisclosureChoicesOverview, 1)

		pickOne := plan.DisclosureChoicesOverview[0]
		assert.False(t, pickOne.Optional)
		assert.Len(t, pickOne.OwnedOptions, 1)
		assert.Equal(t, "abc123", pickOne.OwnedOptions[0].Hash)
		assert.Len(t, pickOne.ObtainableOptions, 1)
	})

	t.Run("multiple queries all required", func(t *testing.T) {
		queries := []dcql.CredentialQuery{
			{Id: "q1", Format: "dc+sd-jwt"},
			{Id: "q2", Format: "dc+sd-jwt"},
		}
		queryResults := map[string]*clientmodels.CredentialQueryResult{
			"q1": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h1"}}},
			"q2": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h2"}}},
		}

		plan, err := buildPlanFromCredentialQueries(queries, queryResults, nil, nil)
		require.NoError(t, err)
		require.Len(t, plan.DisclosureChoicesOverview, 2)
		assert.False(t, plan.DisclosureChoicesOverview[0].Optional)
		assert.False(t, plan.DisclosureChoicesOverview[1].Optional)
	})

	t.Run("missing query result returns error", func(t *testing.T) {
		queries := []dcql.CredentialQuery{{Id: "missing"}}
		_, err := buildPlanFromCredentialQueries(queries, map[string]*clientmodels.CredentialQueryResult{}, nil, nil)
		require.Error(t, err)
	})
}

func TestBuildPlanFromCredentialSets(t *testing.T) {
	t.Run("required credential set groups options", func(t *testing.T) {
		queryResults := map[string]*clientmodels.CredentialQueryResult{
			"q1": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h1"}}},
			"q2": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h2"}}},
		}
		credSets := []dcql.CredentialSetQuery{
			{Options: [][]string{{"q1"}, {"q2"}}},
		}

		plan, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)
		require.Len(t, plan.DisclosureChoicesOverview, 1)
		assert.False(t, plan.DisclosureChoicesOverview[0].Optional)
		assert.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 2)
	})

	t.Run("optional credential set", func(t *testing.T) {
		notRequired := false
		queryResults := map[string]*clientmodels.CredentialQueryResult{
			"q1": {OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{Hash: "h1"}}},
		}
		credSets := []dcql.CredentialSetQuery{
			{Options: [][]string{{"q1"}}, Required: &notRequired},
		}

		plan, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.NoError(t, err)
		require.Len(t, plan.DisclosureChoicesOverview, 1)
		assert.True(t, plan.DisclosureChoicesOverview[0].Optional)
	})

	t.Run("multi-query options not supported", func(t *testing.T) {
		queryResults := map[string]*clientmodels.CredentialQueryResult{
			"q1": {},
			"q2": {},
		}
		credSets := []dcql.CredentialSetQuery{
			{Options: [][]string{{"q1", "q2"}}},
		}

		_, err := buildPlanFromCredentialSets(queryResults, credSets, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not supported")
	})
}
