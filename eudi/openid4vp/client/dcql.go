package client

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
)

// buildPlanFromCredentialQueries builds a DisclosurePlan when no credential_sets are present.
// Each credential query becomes one DisclosurePickOne entry (all required).
func buildPlanFromCredentialQueries(
	queries []dcql.CredentialQuery,
	queryResults map[string]*clientmodels.CredentialQueryResult,
) (*clientmodels.DisclosurePlan, error) {
	pickOnes := make([]clientmodels.DisclosurePickOne, 0, len(queries))

	for _, query := range queries {
		result, ok := queryResults[query.Id]
		if !ok {
			return nil, fmt.Errorf("no result for credential query %q", query.Id)
		}

		pickOnes = append(pickOnes, clientmodels.DisclosurePickOne{
			Optional:          false,
			OwnedOptions:      result.OwnedCandidates,
			ObtainableOptions: result.ObtainableDescriptors,
		})
	}

	return &clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: pickOnes,
	}, nil
}

// buildPlanFromCredentialSets builds a DisclosurePlan when credential_sets are present.
// Each credential set becomes one DisclosurePickOne, grouping all options (which reference
// credential queries) into owned/obtainable lists.
func buildPlanFromCredentialSets(
	queryResults map[string]*clientmodels.CredentialQueryResult,
	credentialSets []dcql.CredentialSetQuery,
) (*clientmodels.DisclosurePlan, error) {
	pickOnes := make([]clientmodels.DisclosurePickOne, 0, len(credentialSets))

	for _, credentialSet := range credentialSets {
		optional := credentialSet.Required != nil && !*credentialSet.Required

		var allOwned []*clientmodels.SelectableCredentialInstance
		var allObtainable []*clientmodels.CredentialDescriptor

		for _, option := range credentialSet.Options {
			if len(option) > 1 {
				return nil, fmt.Errorf(
					"credential set `options` field has inner option array that consists of multiple credential queries, which is not supported at the moment",
				)
			}

			queryId := option[0]
			result, ok := queryResults[queryId]
			if !ok {
				return nil, fmt.Errorf("no result for credential query %q referenced in credential set", queryId)
			}

			allOwned = append(allOwned, result.OwnedCandidates...)
			allObtainable = append(allObtainable, result.ObtainableDescriptors...)
		}

		pickOnes = append(pickOnes, clientmodels.DisclosurePickOne{
			Optional:          optional,
			OwnedOptions:      allOwned,
			ObtainableOptions: allObtainable,
		})
	}

	return &clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: pickOnes,
	}, nil
}
