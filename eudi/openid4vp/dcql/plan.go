package dcql

import (
	"fmt"
	"slices"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// buildPlanFromCredentialQueries builds a DisclosurePlan when no credential_sets are present.
// Each credential query becomes one DisclosurePickOne entry (all required).
func buildPlanFromCredentialQueries(
	queries []CredentialQuery,
	queryResults map[string]*CredentialQueryResult,
	previousPlan *clientmodels.DisclosurePlan,
	preExistingHashes map[string]struct{},
) (*clientmodels.DisclosurePlan, []ChoiceQueryIds, error) {
	pickOnes := make([]clientmodels.DisclosurePickOne, 0, len(queries))
	queryIds := make([]ChoiceQueryIds, 0, len(queries))
	issuance := make([][]*clientmodels.IssuanceBundle, 0, len(queries))

	for _, query := range queries {
		result, ok := queryResults[query.Id]
		if !ok {
			return nil, nil, fmt.Errorf("no result for credential query %q", query.Id)
		}

		pickOnes = append(pickOnes, clientmodels.DisclosurePickOne{
			Optional:          false,
			Multiple:          query.Multiple,
			OwnedOptions:      wrapAsBundles(result.OwnedCandidates),
			ObtainableOptions: result.ObtainableDescriptors,
		})
		queryIds = append(queryIds, choiceQueryIds(result.OwnedCandidates, query.Id))
		// Each descriptor answers the query on its own.
		issuance = append(issuance, issuanceBundles([][]*clientmodels.CredentialDescriptor{result.ObtainableDescriptors}))
	}

	return withQueryIds(finalizePlan(&clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: pickOnes,
	}, previousPlan, preExistingHashes, issuance), queryIds)
}

// wrapAsBundles wraps each candidate of a single query as a single-credential
// DisclosureBundle: a candidate answers its own query on its own.
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
) (*clientmodels.DisclosurePlan, []ChoiceQueryIds, error) {
	pickOnes := make([]clientmodels.DisclosurePickOne, 0, len(credentialSets))
	queryIds := make([]ChoiceQueryIds, 0, len(credentialSets))
	issuance := make([][]*clientmodels.IssuanceBundle, 0, len(credentialSets))

	for _, credentialSet := range credentialSets {
		optional := credentialSet.Required != nil && !*credentialSet.Required

		var owned []*clientmodels.DisclosureBundle
		var obtainable []*clientmodels.CredentialDescriptor
		var setIssuance []*clientmodels.IssuanceBundle
		var setQueryIds ChoiceQueryIds
		// A query named in several options is offered for issuance once.
		listed := map[string]struct{}{}

		for _, option := range credentialSet.Options {
			// A set merges its options into one pick-one, so the query is
			// recorded per candidate, in the same order the candidates are
			// offered. Two options can be satisfied by one stored credential,
			// which is then offered twice and told apart by the element each
			// would reveal.
			planned, err := planOption(option, queryResults)
			if err != nil {
				return nil, nil, err
			}
			owned = append(owned, planned.owned...)
			setIssuance = append(setIssuance, planned.issuance...)
			setQueryIds = append(setQueryIds, planned.queryIds...)

			for _, queryId := range option {
				if _, done := listed[queryId]; done {
					continue
				}
				// Of an incomplete option, only what it is missing can be obtained.
				if len(planned.owned) == 0 && len(queryResults[queryId].OwnedCandidates) > 0 {
					continue
				}
				listed[queryId] = struct{}{}
				obtainable = append(obtainable, queryResults[queryId].ObtainableDescriptors...)
			}
		}

		pickOnes = append(pickOnes, clientmodels.DisclosurePickOne{
			Optional:          optional,
			OwnedOptions:      owned,
			ObtainableOptions: obtainable,
		})
		queryIds = append(queryIds, setQueryIds)
		issuance = append(issuance, setIssuance)
	}

	return withQueryIds(finalizePlan(&clientmodels.DisclosurePlan{
		DisclosureChoicesOverview: pickOnes,
	}, previousPlan, preExistingHashes, issuance), queryIds)
}

// plannedOption is what one credential set option adds to its set's pick-one.
type plannedOption struct {
	// owned holds a bundle per combination of owned candidates, one candidate
	// per query, when every query of the option has one.
	owned []*clientmodels.DisclosureBundle
	// issuance holds, when the option is incomplete, a bundle per way to
	// obtain the credentials it is missing.
	issuance []*clientmodels.IssuanceBundle
	// queryIds says which query each owned candidate answers.
	queryIds ChoiceQueryIds
}

// planOption works out one credential set option. An option lists credential
// query ids that are answered together (OpenID4VP 1.0 § 6.2), so it can only be
// shared when every one of its queries has an owned candidate. Its bundles are
// then every combination of those candidates, in the order the option names the
// queries, the first query varying slowest. An option that is incomplete offers
// no bundle; issuing it means issuing only the credentials it is missing, never
// the ones the user already holds.
//
// An option of one query gives what a set of single-query options always gave:
// a bundle per candidate and an issuance bundle per obtainable descriptor.
func planOption(option []string, queryResults map[string]*CredentialQueryResult) (plannedOption, error) {
	if len(option) == 0 {
		return plannedOption{}, fmt.Errorf("credential set `options` field has an empty inner option array")
	}

	results := make([]*CredentialQueryResult, len(option))
	complete := true
	for i, queryId := range option {
		result, ok := queryResults[queryId]
		if !ok {
			return plannedOption{}, fmt.Errorf("no result for credential query %q referenced in credential set", queryId)
		}
		results[i] = result
		if len(result.OwnedCandidates) == 0 {
			complete = false
		}
	}

	var planned plannedOption
	if complete {
		candidates := make([][]*clientmodels.SelectableCredentialInstance, len(option))
		for i, result := range results {
			candidates[i] = result.OwnedCandidates
			planned.queryIds = append(planned.queryIds, choiceQueryIds(result.OwnedCandidates, option[i])...)
		}
		for _, combination := range combinations(candidates) {
			planned.owned = append(planned.owned, &clientmodels.DisclosureBundle{Credentials: combination})
		}
		return planned, nil
	}

	var missing [][]*clientmodels.CredentialDescriptor
	for _, result := range results {
		if len(result.OwnedCandidates) == 0 {
			missing = append(missing, result.ObtainableDescriptors)
		}
	}
	planned.issuance = issuanceBundles(missing)
	return planned, nil
}

// issuanceBundles is a bundle per way to obtain one credential for each of the
// given queries: a query's descriptors are alternatives, and the queries are all
// needed. A query that nothing can be obtained for leaves no way at all.
func issuanceBundles(perQuery [][]*clientmodels.CredentialDescriptor) []*clientmodels.IssuanceBundle {
	var bundles []*clientmodels.IssuanceBundle
	for _, combination := range combinations(perQuery) {
		bundles = append(bundles, &clientmodels.IssuanceBundle{Credentials: combination})
	}
	return bundles
}

// combinations returns every way to pick one item from each list, the first list
// varying slowest. An empty list, or no lists at all, leaves no combination.
func combinations[T any](lists [][]T) [][]T {
	if len(lists) == 0 {
		return nil
	}
	result := [][]T{{}}
	for _, list := range lists {
		next := make([][]T, 0, len(result)*len(list))
		for _, prefix := range result {
			for _, item := range list {
				next = append(next, append(slices.Clip(slices.Clone(prefix)), item))
			}
		}
		result = next
	}
	return result
}

// choiceQueryIds records, for every candidate of one query, that it answers
// that query and which paths it would disclose. Candidates keep the order they
// are offered in, so the entries line up with the pick-one's owned options.
func choiceQueryIds(candidates []*clientmodels.SelectableCredentialInstance, queryId string) ChoiceQueryIds {
	ids := make(ChoiceQueryIds, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Hash == "" {
			// Nothing the app can select, so nothing to resolve later.
			continue
		}
		pathKeys := make(map[string]struct{}, len(candidate.Attributes))
		for _, attr := range candidate.Attributes {
			if attr.Value == nil {
				continue // a section header is not a disclosed path
			}
			pathKeys[clientmodels.ClaimPathKey(attr.ClaimPath)] = struct{}{}
		}
		ids = append(ids, CandidateQuery{Hash: candidate.Hash, QueryId: queryId, PathKeys: pathKeys})
	}
	return ids
}

// withQueryIds keeps the per-choice query ids parallel to the plan's choices.
// finalizePlan drops the choices while an issuance-during-disclosure step is
// still outstanding; the ids go with them, so nothing can index into a list that
// no longer matches what the user was shown.
func withQueryIds(plan *clientmodels.DisclosurePlan, queryIds []ChoiceQueryIds) (*clientmodels.DisclosurePlan, []ChoiceQueryIds, error) {
	if plan.DisclosureChoicesOverview == nil {
		return plan, nil, nil
	}
	return plan, queryIds, nil
}

// finalizePlan handles the issuance-during-disclosure logic:
// - On first call (previousPlan == nil): detects unsatisfied disjunctions and creates IssueDuringDisclosure
// - On refresh (previousPlan != nil): updates IssueDuringDisclosure tracking with newly issued credentials
//
// issuance runs parallel to the plan's choices: per pick-one, the ways to obtain
// what it is missing.
func finalizePlan(
	plan *clientmodels.DisclosurePlan,
	previousPlan *clientmodels.DisclosurePlan,
	preExistingHashes map[string]struct{},
	issuance [][]*clientmodels.IssuanceBundle,
) *clientmodels.DisclosurePlan {
	if previousPlan == nil {
		// First time: check if issuance is needed
		return addIssueDuringDisclosure(plan, issuance)
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
//
// A step's options are the pick-one's issuance bundles, not its obtainable
// descriptors one by one: a credential set option that names several queries is
// only answered when all of them are, so obtaining one of its credentials alone
// does not get the user anywhere.
func addIssueDuringDisclosure(plan *clientmodels.DisclosurePlan, issuance [][]*clientmodels.IssuanceBundle) *clientmodels.DisclosurePlan {
	var issuanceSteps []clientmodels.IssuanceStep

	for i, pickOne := range plan.DisclosureChoicesOverview {
		if len(pickOne.OwnedOptions) == 0 && i < len(issuance) && len(issuance[i]) > 0 && !pickOne.Optional {
			issuanceSteps = append(issuanceSteps, clientmodels.IssuanceStep{
				Options: issuance[i],
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
