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
			OwnedOptions:      result.OwnedCandidates,
			ObtainableOptions: result.ObtainableDescriptors,
		})
	}

	return finalizePlan(&clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: pickOnes,
	}, previousPlan, preExistingHashes), nil
}

// buildPlanFromCredentialSets builds a DisclosurePlan when credential_sets are present.
func buildPlanFromCredentialSets(
	queryResults map[string]*clientmodels.CredentialQueryResult,
	credentialSets []dcql.CredentialSetQuery,
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
			OwnedOptions:      allOwned,
			ObtainableOptions: allObtainable,
		})
	}

	return finalizePlan(&clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: pickOnes,
	}, previousPlan, preExistingHashes), nil
}

// finalizePlan handles the issuance-during-disclosure logic:
// - On first call (previousPlan == nil): detects unsatisfied disjunctions and creates IssueDuringDislosure
// - On refresh (previousPlan != nil): updates IssueDuringDislosure tracking with newly issued credentials
func finalizePlan(plan *clientmodels.DisclosurePlan, previousPlan *clientmodels.DisclosurePlan, preExistingHashes map[string]struct{}) *clientmodels.DisclosurePlan {
	if previousPlan == nil {
		// First time: check if issuance is needed
		return addIssueDuringDisclosure(plan)
	}

	// Refresh: update existing issuance tracking
	if previousPlan.IssueDuringDislosure == nil {
		return plan
	}

	// Track which credentials were issued since the original plan
	prevSteps := previousPlan.IssueDuringDislosure.Steps
	issuedIds := make(map[string]struct{})
	allSatisfied := true

	for _, step := range prevSteps {
		stepSatisfied := false
		for _, option := range step.Options {
			for _, pickOne := range plan.DisclosureChoicesOverview {
				for _, owned := range pickOne.OwnedOptions {
					if owned.CredentialId == option.CredentialId {
						issuedIds[owned.CredentialId] = struct{}{}
						stepSatisfied = true
					}
				}
			}
		}
		if !stepSatisfied {
			allSatisfied = false
		}
	}

	// Merge previously tracked issued IDs
	for id := range previousPlan.IssueDuringDislosure.IssuedCredentialIds {
		issuedIds[id] = struct{}{}
	}

	plan.IssueDuringDislosure = &clientmodels.IssueDuringDislosure{
		Steps:               prevSteps,
		IssuedCredentialIds: issuedIds,
	}

	// If not all steps satisfied, hide the disclosure choices
	if !allSatisfied {
		plan.DisclosureChoicesOverview = nil
	}

	return plan
}

// satisfiesRequestedAttributes checks if given attributes satisfy requested attributes.
func satisfiesRequestedAttributes(given, requested []clientmodels.Attribute) bool {
	givenByID := make(map[string]clientmodels.Attribute)
	for _, g := range given {
		givenByID[g.Id] = g
	}
	for _, r := range requested {
		if r.RequestedValue == nil || !r.RequestedValue.HasValue() {
			continue
		}
		g, ok := givenByID[r.Id]
		if !ok || g.Value == nil {
			return false
		}
		// Compare TranslatedString values
		if r.RequestedValue.TranslatedString != nil && g.Value.TranslatedString != nil {
			for lang, want := range *r.RequestedValue.TranslatedString {
				have, ok := (*g.Value.TranslatedString)[lang]
				if !ok || have != want {
					return false
				}
			}
		}
	}
	return true
}

// filterMismatchedAttributes returns attributes from owned that don't match the requested values.
func filterMismatchedAttributes(owned, requested []clientmodels.Attribute) []clientmodels.Attribute {
	requestedByID := make(map[string]*clientmodels.Attribute)
	for i := range requested {
		requestedByID[requested[i].Id] = &requested[i]
	}
	var mismatched []clientmodels.Attribute
	for _, attr := range owned {
		req, ok := requestedByID[attr.Id]
		if !ok || req.RequestedValue == nil || !req.RequestedValue.HasValue() {
			continue
		}
		if attr.Value != nil {
			ok, _ := clientmodels.SatisfiesRequestedAttributes(
				[]clientmodels.Attribute{attr},
				[]clientmodels.Attribute{*req},
			)
			if !ok {
				mismatched = append(mismatched, clientmodels.Attribute{
					Id:             attr.Id,
					DisplayName:    attr.DisplayName,
					Description:    attr.Description,
					Value:          attr.Value,
					RequestedValue: req.RequestedValue,
				})
			}
		}
	}
	return mismatched
}

// addIssueDuringDisclosure checks if any required DisclosurePickOne has no owned options
// and adds IssueDuringDislosure with issuance steps for unsatisfied disjunctions.
func addIssueDuringDisclosure(plan *clientmodels.DisclosurePlan) *clientmodels.DisclosurePlan {
	var issuanceSteps []clientmodels.IssuanceStep

	for _, pickOne := range plan.DisclosureChoicesOverview {
		if len(pickOne.OwnedOptions) == 0 && len(pickOne.ObtainableOptions) > 0 && !pickOne.Optional {
			issuanceSteps = append(issuanceSteps, clientmodels.IssuanceStep{
				Options: pickOne.ObtainableOptions,
			})
		}
	}

	if len(issuanceSteps) > 0 {
		plan.IssueDuringDislosure = &clientmodels.IssueDuringDislosure{
			Steps:               issuanceSteps,
			IssuedCredentialIds: map[string]struct{}{},
		}
		// When issuance is needed, don't show disclosure choices yet
		plan.DisclosureChoicesOverview = nil
	}

	return plan
}
