package dcql

import (
	"fmt"
	"slices"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// buildChoices describes the request as choices → options → slots (#804):
//
//   - without credential_sets, one required choice per credential query, with
//     one option of one slot;
//   - with credential_sets, one choice per set (optional when required is
//     false), one option per entry of its options, one slot per query id in
//     that entry. Queries no set names are not part of the plan.
//
// A slot is a query: its id is the query id and it has the query's candidates
// and obtainable descriptors. The same query named in several options or sets
// is the same slot each time, built once, so it carries the same candidates.
func buildChoices(query DcqlQuery, queryResults map[string]*CredentialQueryResult) ([]clientmodels.DisclosureChoice, error) {
	queryById := make(map[string]CredentialQuery, len(query.Credentials))
	for _, q := range query.Credentials {
		queryById[q.Id] = q
	}

	slots := make(map[string]clientmodels.DisclosureSlot)
	slotFor := func(queryId string) (clientmodels.DisclosureSlot, error) {
		if slot, ok := slots[queryId]; ok {
			return slot, nil
		}
		q, ok := queryById[queryId]
		if !ok {
			return clientmodels.DisclosureSlot{}, fmt.Errorf("credential set references unknown credential query id %q", queryId)
		}
		result, ok := queryResults[queryId]
		if !ok {
			return clientmodels.DisclosureSlot{}, fmt.Errorf("no result for credential query %q", queryId)
		}
		slot := buildSlot(q, result)
		slots[queryId] = slot
		return slot, nil
	}

	if query.CredentialSets == nil {
		choices := make([]clientmodels.DisclosureChoice, 0, len(query.Credentials))
		for _, q := range query.Credentials {
			slot, err := slotFor(q.Id)
			if err != nil {
				return nil, err
			}
			choices = append(choices, clientmodels.DisclosureChoice{
				Options: []clientmodels.DisclosureOption{{Slots: []clientmodels.DisclosureSlot{slot}}},
			})
		}
		return choices, nil
	}

	choices := make([]clientmodels.DisclosureChoice, 0, len(query.CredentialSets))
	for _, set := range query.CredentialSets {
		if len(set.Options) == 0 {
			return nil, fmt.Errorf("credential set has an empty options array, so it can never be satisfied")
		}
		choice := clientmodels.DisclosureChoice{
			Optional: set.Required != nil && !*set.Required,
			Options:  make([]clientmodels.DisclosureOption, 0, len(set.Options)),
		}
		for _, option := range set.Options {
			if len(option) == 0 {
				return nil, fmt.Errorf("credential set `options` field has an empty inner option array")
			}
			opt := clientmodels.DisclosureOption{Slots: make([]clientmodels.DisclosureSlot, 0, len(option))}
			for _, queryId := range option {
				if slices.ContainsFunc(opt.Slots, func(s clientmodels.DisclosureSlot) bool { return s.Id == queryId }) {
					return nil, fmt.Errorf("credential set option names credential query id %q more than once", queryId)
				}
				slot, err := slotFor(queryId)
				if err != nil {
					return nil, err
				}
				opt.Slots = append(opt.Slots, slot)
			}
			choice.Options = append(choice.Options, opt)
		}
		choices = append(choices, choice)
	}
	return choices, nil
}

// buildSlot turns one query's result into its slot: the candidates best first,
// and what can be added for it.
func buildSlot(query CredentialQuery, result *CredentialQueryResult) clientmodels.DisclosureSlot {
	candidates := make([]*clientmodels.SelectableCredentialInstance, 0, len(result.OwnedCandidates))
	for _, c := range result.OwnedCandidates {
		if c.Hash == "" {
			continue // nothing the app could select
		}
		candidates = append(candidates, c)
	}
	clientmodels.SortCandidates(candidates)

	return clientmodels.DisclosureSlot{
		Id:         query.Id,
		Multiple:   query.Multiple,
		Candidates: candidates,
		Obtainable: slotObtainable(candidates, result.ObtainableDescriptors),
	}
}

// slotObtainable picks the descriptors a slot offers. While the slot has no
// usable candidate every descriptor is offered, also one without an issue URL:
// it tells the user what is asked even when it cannot be added here, and for
// a singleton it is how a revoked, expired or not-allowed card is added again.
// Once a usable card is there, only a type that can be added next to it (an
// issue URL, not a singleton) is still offered.
func slotObtainable(candidates []*clientmodels.SelectableCredentialInstance, descriptors []*clientmodels.CredentialDescriptor) []*clientmodels.CredentialDescriptor {
	hasUsable := slices.ContainsFunc(candidates, func(c *clientmodels.SelectableCredentialInstance) bool { return c.Usable })
	obtainable := make([]*clientmodels.CredentialDescriptor, 0, len(descriptors))
	for _, d := range descriptors {
		if !hasUsable || (d.IssueURL != nil && *d.IssueURL != "" && !d.IsSingleton) {
			obtainable = append(obtainable, d)
		}
	}
	return obtainable
}

// SetUsable records on a candidate whether it can be shared for this request,
// from what the format handler knows of it. Revoked wins over expired, and
// expired over used up, so the reason names what adding the card again fixes
// first.
func SetUsable(candidate *clientmodels.SelectableCredentialInstance, expired bool) {
	switch {
	case candidate.Revoked:
		candidate.UnusableReason = clientmodels.UnusableReason_Revoked
	case expired:
		candidate.UnusableReason = clientmodels.UnusableReason_Expired
	case candidate.BatchInstanceCountRemaining != nil && *candidate.BatchInstanceCountRemaining == 0:
		candidate.UnusableReason = clientmodels.UnusableReason_UsedUp
	default:
		candidate.UnusableReason = clientmodels.UnusableReason_None
	}
	candidate.Usable = candidate.UnusableReason == clientmodels.UnusableReason_None
}

// ExpiredAt reports whether a credential with this expiry (unix seconds, nil
// for none) has expired at now.
func ExpiredAt(expiry *int64, now time.Time) bool {
	return expiry != nil && now.After(time.Unix(*expiry, 0))
}

// RequestedValues are a claim's allowed values as attribute values, in
// request order and keeping their type; nil when any value will do.
func RequestedValues(claim Claim) []clientmodels.AttributeValue {
	if len(claim.Values) == 0 {
		return nil
	}
	values := make([]clientmodels.AttributeValue, 0, len(claim.Values))
	for _, v := range claim.Values {
		if av := clientmodels.NewAttributeValue(v); av != nil {
			values = append(values, *av)
		}
	}
	return values
}
