package dcql

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// buildPlanFromCredentialQueries builds a DisclosurePlan when no credential_sets are present.
// Each credential query becomes one DisclosurePickOne entry (all required).
func buildPlanFromCredentialQueries(
	queries []CredentialQuery,
	queryResults map[string]*CredentialQueryResult,
	previousPlan *clientmodels.DisclosurePlan,
	preExistingHashes map[string]struct{},
) (*clientmodels.DisclosurePlan, error) {
	pickOnes := make([]clientmodels.DisclosurePickOne, 0, len(queries))

	for _, query := range queries {
		result, ok := queryResults[query.Id]
		if !ok {
			return nil, fmt.Errorf("no result for credential query %q", query.Id)
		}

		pickOnes = append(pickOnes, clientmodels.DisclosurePickOne{
			Optional:          false,
			Multiple:          query.Multiple,
			OwnedOptions:      wrapAsBundles(result.OwnedCandidates),
			ObtainableOptions: result.ObtainableDescriptors,
		})
	}

	return finalizePlan(&clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: pickOnes,
	}, previousPlan, preExistingHashes), nil
}

// wrapAsBundles wraps each DCQL candidate as a single-credential
// DisclosureBundle. DCQL queries map one-to-one to credential types, so each
// candidate always satisfies its query on its own.
func wrapAsBundles(candidates []*clientmodels.SelectableCredentialInstance) []*clientmodels.DisclosureBundle {
	if len(candidates) == 0 {
		return nil
	}
	bundles := make([]*clientmodels.DisclosureBundle, len(candidates))
	for i, c := range candidates {
		bundles[i] = &clientmodels.DisclosureBundle{
			Credentials: []*clientmodels.SelectableCredentialInstance{c},
		}
	}
	return bundles
}

// buildPlanFromCredentialSets builds a DisclosurePlan when credential_sets are present.
func buildPlanFromCredentialSets(
	queryResults map[string]*CredentialQueryResult,
	credentialSets []CredentialSetQuery,
	previousPlan *clientmodels.DisclosurePlan,
	preExistingHashes map[string]struct{},
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
			OwnedOptions:      wrapAsBundles(allOwned),
			ObtainableOptions: allObtainable,
		})
	}

	return finalizePlan(&clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: pickOnes,
	}, previousPlan, preExistingHashes), nil
}

// finalizePlan handles the issuance-during-disclosure logic:
// - On first call (previousPlan == nil): detects unsatisfied disjunctions and creates IssueDuringDisclosure
// - On refresh (previousPlan != nil): updates IssueDuringDisclosure tracking with newly issued credentials
func finalizePlan(plan *clientmodels.DisclosurePlan, previousPlan *clientmodels.DisclosurePlan, preExistingHashes map[string]struct{}) *clientmodels.DisclosurePlan {
	if previousPlan == nil {
		// First time: check if issuance is needed
		return addIssueDuringDisclosure(plan)
	}

	// Refresh: update existing issuance tracking
	if previousPlan.IssueDuringDisclosure == nil {
		return plan
	}

	// Track which credentials were issued since the original plan
	prevSteps := previousPlan.IssueDuringDisclosure.Steps
	issuedIds := make(map[string]struct{})
	allSatisfied := true

	for _, step := range prevSteps {
		stepSatisfied := false
		for _, bundle := range step.Options {
			bundleSatisfied := true
			for _, desc := range bundle.Credentials {
				descSatisfied := false
			search:
				for _, pickOne := range plan.DisclosureChoicesOverview {
					for _, ownedBundle := range pickOne.OwnedOptions {
						for _, owned := range ownedBundle.Credentials {
							if owned.CredentialId == desc.CredentialId {
								descSatisfied = true
								break search
							}
						}
					}
				}
				if !descSatisfied {
					bundleSatisfied = false
					break
				}
			}
			if bundleSatisfied {
				for _, desc := range bundle.Credentials {
					issuedIds[desc.CredentialId] = struct{}{}
				}
				stepSatisfied = true
				break
			}
		}
		if !stepSatisfied {
			allSatisfied = false
		}
	}

	// Merge previously tracked issued IDs
	for id := range previousPlan.IssueDuringDisclosure.IssuedCredentialIds {
		issuedIds[id] = struct{}{}
	}

	plan.IssueDuringDisclosure = &clientmodels.IssueDuringDisclosure{
		Steps:               prevSteps,
		IssuedCredentialIds: issuedIds,
	}

	// If not all steps satisfied, hide the disclosure choices
	if !allSatisfied {
		plan.DisclosureChoicesOverview = nil
	}

	return plan
}

// addIssueDuringDisclosure checks if any required DisclosurePickOne has no owned options
// and adds IssueDuringDisclosure with issuance steps for unsatisfied disjunctions.
func addIssueDuringDisclosure(plan *clientmodels.DisclosurePlan) *clientmodels.DisclosurePlan {
	var issuanceSteps []clientmodels.IssuanceStep

	for _, pickOne := range plan.DisclosureChoicesOverview {
		if len(pickOne.OwnedOptions) == 0 && len(pickOne.ObtainableOptions) > 0 && !pickOne.Optional {
			// DCQL queries map one-to-one to credentials, so each obtainable
			// option becomes a single-credential bundle.
			options := make([]*clientmodels.IssuanceBundle, 0, len(pickOne.ObtainableOptions))
			for _, obt := range pickOne.ObtainableOptions {
				options = append(options, &clientmodels.IssuanceBundle{
					Credentials: []*clientmodels.CredentialDescriptor{obt},
				})
			}
			issuanceSteps = append(issuanceSteps, clientmodels.IssuanceStep{
				Options: options,
			})
		}
	}

	if len(issuanceSteps) > 0 {
		plan.IssueDuringDisclosure = &clientmodels.IssueDuringDisclosure{
			Steps:               issuanceSteps,
			IssuedCredentialIds: map[string]struct{}{},
		}
		// When issuance is needed, don't show disclosure choices yet
		plan.DisclosureChoicesOverview = nil
	}

	return plan
}
