package clientmodels

import (
	"fmt"
	"slices"
)

// ValidateAnswer checks an answer per slot against the plan it answers (the
// last one sent to the app):
//
//   - one ChoiceSelection per choice, in order;
//   - Option -1 (nothing shared) only for an optional choice, else an index
//     into the choice's options;
//   - one SlotSelection per slot of the chosen option, with the slot's id, in
//     order;
//   - exactly one credential per slot, or at least one when the slot is
//     Multiple, never the same one twice;
//   - every credential is one of the slot's candidates, and a usable one;
//   - a slot id chosen in two choices carries the same credential(s) in both,
//     unless the slot is Multiple (DCQL: a query has one presentation);
//   - a card used in several slots has a use left for each of them.
//
// A nil plan has no choices, so only an empty answer fits it.
func ValidateAnswer(plan *DisclosurePlan, answer []ChoiceSelection) error {
	var choices []DisclosureChoice
	if plan != nil {
		choices = plan.Choices
	}
	if len(answer) != len(choices) {
		return fmt.Errorf("answer has %d choices, the plan %d", len(answer), len(choices))
	}

	chosenBySlotId := map[string][]string{}
	usesByHash := map[string]int{}
	presented := map[string]struct{}{}
	remainingByHash := map[string]*uint{}

	for i, selection := range answer {
		choice := choices[i]
		if selection.Option == -1 {
			if !choice.Optional {
				return fmt.Errorf("choice %d is required, but nothing was chosen for it", i)
			}
			if len(selection.Slots) != 0 {
				return fmt.Errorf("choice %d shares nothing, but names %d slots", i, len(selection.Slots))
			}
			continue
		}
		if selection.Option < 0 || selection.Option >= len(choice.Options) {
			return fmt.Errorf("choice %d has no option %d", i, selection.Option)
		}
		option := choice.Options[selection.Option]
		if len(selection.Slots) != len(option.Slots) {
			return fmt.Errorf("choice %d option %d has %d slots, the answer %d", i, selection.Option, len(option.Slots), len(selection.Slots))
		}

		for j, slotSelection := range selection.Slots {
			slot := option.Slots[j]
			if slotSelection.SlotId != slot.Id {
				return fmt.Errorf("choice %d slot %d is %q, the answer names %q", i, j, slot.Id, slotSelection.SlotId)
			}
			switch n := len(slotSelection.Credentials); {
			case n == 0:
				return fmt.Errorf("slot %q has no card", slot.Id)
			case n > 1 && !slot.Multiple:
				return fmt.Errorf("slot %q takes one card, the answer has %d", slot.Id, n)
			}

			hashes := make([]string, 0, len(slotSelection.Credentials))
			for _, credential := range slotSelection.Credentials {
				if slices.Contains(hashes, credential.CredentialHash) {
					return fmt.Errorf("slot %q names card %s twice", slot.Id, credential.CredentialHash)
				}
				candidate := findCandidate(slot.Candidates, credential.CredentialHash)
				if candidate == nil {
					return fmt.Errorf("card %s is not a candidate of slot %q", credential.CredentialHash, slot.Id)
				}
				if !candidate.Usable {
					return fmt.Errorf("card %s cannot be used for slot %q (%s)", credential.CredentialHash, slot.Id, candidate.UnusableReason)
				}
				hashes = append(hashes, credential.CredentialHash)
				remainingByHash[credential.CredentialHash] = candidate.BatchInstanceCountRemaining
			}

			if previous, seen := chosenBySlotId[slot.Id]; seen && !slot.Multiple && !slices.Equal(previous, hashes) {
				return fmt.Errorf("slot %q is answered with different cards in two choices", slot.Id)
			}
			chosenBySlotId[slot.Id] = hashes
			// One presentation per card per slot id, however many choices
			// name that slot.
			for _, hash := range hashes {
				key := slot.Id + "\x00" + hash
				if _, counted := presented[key]; !counted {
					presented[key] = struct{}{}
					usesByHash[hash]++
				}
			}
		}
	}

	for hash, uses := range usesByHash {
		if remaining := remainingByHash[hash]; remaining != nil && uint(uses) > *remaining {
			return fmt.Errorf("card %s is chosen %d times but has %d uses left", hash, uses, *remaining)
		}
	}
	return nil
}

func findCandidate(candidates []*SelectableCredentialInstance, hash string) *SelectableCredentialInstance {
	for _, c := range candidates {
		if c.Hash == hash {
			return c
		}
	}
	return nil
}
