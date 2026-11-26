package client

import (
	"slices"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// detectWrongCredentialIssued finds the card the user added for this request
// that does not satisfy it: a card not held when the request arrived
// (preExisting), of a type a waiting slot offers to add, that is not a
// candidate of that slot because its values are not the ones asked. A slot
// waits while its required choice has no option with a usable card in every
// slot; once the choice can be answered nothing is reported for it.
//
// It returns that card with only the attributes whose value does not match,
// each with what was asked (as the frontend shows both), or nil. Of several,
// the one issued last; on a tie, one other than the card reported on the
// previous plan, as the newer one is more likely the one just added.
func detectWrongCredentialIssued(
	plan, previous *clientmodels.DisclosurePlan,
	credentials []*clientmodels.Credential,
	preExisting map[string]struct{},
) *clientmodels.Credential {
	previousWrongHash := ""
	if previous != nil && previous.WrongCredentialIssued != nil {
		previousWrongHash = previous.WrongCredentialIssued.Hash
	}

	var wrong *clientmodels.Credential
	for _, choice := range plan.Choices {
		if choice.Optional || slices.ContainsFunc(choice.Options, optionComplete) {
			continue
		}
		for _, option := range choice.Options {
			for _, slot := range option.Slots {
				if slotHasUsable(slot) {
					continue
				}
				for _, descriptor := range slot.Obtainable {
					for _, cred := range credentials {
						if cred.CredentialId != descriptor.CredentialId || isPreExisting(cred, preExisting) || isCandidate(slot, cred) {
							continue
						}
						if ok, _ := SatisfiesRequestedAttributes(cred.Attributes, descriptor.Attributes); ok {
							continue
						}
						if wrong == nil || issuedLater(cred, wrong, previousWrongHash) {
							wrong = filterCredentialToMismatchedAttributes(cred, descriptor.Attributes)
						}
					}
				}
			}
		}
	}
	return wrong
}

// issuedLater reports whether cred was issued after current, preferring on a
// tie a card other than the one reported before.
func issuedLater(cred, current *clientmodels.Credential, previousWrongHash string) bool {
	if cred.IssuanceDate == nil || current.IssuanceDate == nil {
		return false
	}
	if *cred.IssuanceDate != *current.IssuanceDate {
		return *cred.IssuanceDate > *current.IssuanceDate
	}
	return current.Hash == previousWrongHash && cred.Hash != previousWrongHash
}

func optionComplete(option clientmodels.DisclosureOption) bool {
	for _, slot := range option.Slots {
		if !slotHasUsable(slot) {
			return false
		}
	}
	return true
}

func slotHasUsable(slot clientmodels.DisclosureSlot) bool {
	return slices.ContainsFunc(slot.Candidates, func(c *clientmodels.SelectableCredentialInstance) bool { return c.Usable })
}

func isPreExisting(cred *clientmodels.Credential, preExisting map[string]struct{}) bool {
	if _, ok := preExisting[cred.Hash]; ok {
		return true
	}
	for _, hash := range cred.CredentialInstanceIds {
		if _, ok := preExisting[hash]; ok {
			return true
		}
	}
	return false
}

func isCandidate(slot clientmodels.DisclosureSlot, cred *clientmodels.Credential) bool {
	return slices.ContainsFunc(slot.Candidates, func(c *clientmodels.SelectableCredentialInstance) bool {
		return c.Hash == cred.Hash || slices.Contains(mapValues(cred.CredentialInstanceIds), c.Hash)
	})
}

func mapValues(m map[clientmodels.CredentialFormat]string) []string {
	values := make([]string, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}
