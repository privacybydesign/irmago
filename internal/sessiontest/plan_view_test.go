package sessiontest

import (
	"fmt"
	"slices"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// The session tests describe what a request offers per choice: the cards it
// can be answered with, what can be added, and, while a required choice cannot
// be answered yet, what is still missing. This file reads that from the plan's
// choices → options → slots, so the tests keep stating what they check while
// the plan itself is in slots.

// pickOne is one choice of the plan seen as the cards that answer it.
type pickOne struct {
	Optional bool
	// The DCQL `multiple` flag of a slot in the choice.
	Multiple bool
	// One bundle per way to answer the choice with cards the wallet holds: per
	// option whose every slot has a usable card, each combination of one usable
	// card per slot. A multiple slot gives one bundle per card; a test that
	// shares several builds that answer itself.
	OwnedOptions []*bundle
	// What the choice's slots offer to add, each type once.
	ObtainableOptions []*clientmodels.CredentialDescriptor
}

// bundle is one way to answer a choice: a card per slot of one option.
type bundle struct {
	Credentials []*clientmodels.SelectableCredentialInstance

	option  int
	slotIds []string
}

// pickOnes is the plan's choices seen as pick-ones, in order.
func pickOnes(plan *clientmodels.DisclosurePlan) []pickOne {
	if plan == nil {
		return nil
	}
	views := make([]pickOne, 0, len(plan.Choices))
	for _, choice := range plan.Choices {
		view := pickOne{Optional: choice.Optional}
		for k, option := range choice.Options {
			combinations := [][]*clientmodels.SelectableCredentialInstance{{}}
			for _, slot := range option.Slots {
				view.Multiple = view.Multiple || slot.Multiple
				var next [][]*clientmodels.SelectableCredentialInstance
				for _, prefix := range combinations {
					for _, c := range slot.Candidates {
						if c.Usable {
							next = append(next, append(slices.Clone(prefix), c))
						}
					}
				}
				combinations = next
				for _, d := range slot.Obtainable {
					if !slices.ContainsFunc(view.ObtainableOptions, func(o *clientmodels.CredentialDescriptor) bool { return o.CredentialId == d.CredentialId }) {
						view.ObtainableOptions = append(view.ObtainableOptions, d)
					}
				}
			}
			for _, cards := range combinations {
				if len(cards) == 0 {
					continue
				}
				b := &bundle{Credentials: cards, option: k}
				for _, slot := range option.Slots {
					b.slotIds = append(b.slotIds, slot.Id)
				}
				view.OwnedOptions = append(view.OwnedOptions, b)
			}
		}
		views = append(views, view)
	}
	return views
}

// issuanceStep is a required choice that cannot be answered yet: per option,
// a way to add what that option still misses.
type issuanceStep struct {
	Options []*issuanceBundle
}

// issuanceBundle is what one option still misses: a descriptor per slot
// without a usable card.
type issuanceBundle struct {
	Credentials []*clientmodels.CredentialDescriptor
}

// issuanceView is what the plan says about adding cards for the request.
type issuanceView struct {
	Steps                 []issuanceStep
	IssuedCredentialIds   map[string]struct{}
	WrongCredentialIssued *clientmodels.Credential
}

// issuance is the plan's issuance view: nil when nothing is missing, nothing
// was issued and no wrong card was added.
func issuance(plan *clientmodels.DisclosurePlan) *issuanceView {
	if plan == nil {
		return nil
	}
	var steps []issuanceStep
	for _, choice := range plan.Choices {
		if choice.Optional || slices.ContainsFunc(choice.Options, optionAnswerable) {
			continue
		}
		var step issuanceStep
		for _, option := range choice.Options {
			// Per option, each combination of one descriptor per missing slot.
			combinations := [][]*clientmodels.CredentialDescriptor{{}}
			for _, slot := range option.Slots {
				if slotAnswerable(slot) {
					continue
				}
				var next [][]*clientmodels.CredentialDescriptor
				for _, prefix := range combinations {
					for _, d := range slot.Obtainable {
						next = append(next, append(slices.Clone(prefix), d))
					}
				}
				combinations = next
			}
			for _, descriptors := range combinations {
				if len(descriptors) > 0 {
					step.Options = append(step.Options, &issuanceBundle{Credentials: descriptors})
				}
			}
		}
		// A step is something that can be added; a choice with nothing to add
		// is not one.
		if len(step.Options) > 0 {
			steps = append(steps, step)
		}
	}
	if len(steps) == 0 && len(plan.IssuedCredentialIds) == 0 && plan.WrongCredentialIssued == nil {
		return nil
	}
	return &issuanceView{Steps: steps, IssuedCredentialIds: plan.IssuedCredentialIds, WrongCredentialIssued: plan.WrongCredentialIssued}
}

func slotAnswerable(slot clientmodels.DisclosureSlot) bool {
	return slices.ContainsFunc(slot.Candidates, func(c *clientmodels.SelectableCredentialInstance) bool { return c.Usable })
}

func optionAnswerable(option clientmodels.DisclosureOption) bool {
	for _, slot := range option.Slots {
		if !slotAnswerable(slot) {
			return false
		}
	}
	return true
}

// makeDisclosureChoice answers the bundle's choice with its option and cards,
// sharing every attribute each card shows.
func makeDisclosureChoice(b *bundle) clientmodels.ChoiceSelection {
	choice := clientmodels.ChoiceSelection{Option: b.option}
	for i, cred := range b.Credentials {
		choice.Slots = append(choice.Slots, clientmodels.SlotSelection{
			SlotId:      b.slotIds[i],
			Credentials: []clientmodels.SelectedCredential{selectWhole(cred)},
		})
	}
	return choice
}

// skipChoice answers an optional choice with nothing.
func skipChoice() clientmodels.ChoiceSelection {
	return clientmodels.ChoiceSelection{Option: -1}
}

// choicesOf builds plan choices from pick-ones, for the helpers' own tests:
// each owned bundle becomes an option with a slot per card (usable), and the
// obtainable types an option with one slot that has no card and offers them.
func choicesOf(views []pickOne) []clientmodels.DisclosureChoice {
	choices := make([]clientmodels.DisclosureChoice, 0, len(views))
	for i, view := range views {
		choice := clientmodels.DisclosureChoice{Optional: view.Optional, Options: []clientmodels.DisclosureOption{}}
		for k, b := range view.OwnedOptions {
			option := clientmodels.DisclosureOption{}
			for j, card := range b.Credentials {
				usable := *card
				usable.Usable = true
				option.Slots = append(option.Slots, clientmodels.DisclosureSlot{
					Id:         fmt.Sprintf("%d:%d:%d", i, k, j),
					Multiple:   view.Multiple,
					Candidates: []*clientmodels.SelectableCredentialInstance{&usable},
					Obtainable: []*clientmodels.CredentialDescriptor{},
				})
			}
			choice.Options = append(choice.Options, option)
		}
		if len(view.ObtainableOptions) > 0 {
			choice.Options = append(choice.Options, clientmodels.DisclosureOption{Slots: []clientmodels.DisclosureSlot{{
				Id:         fmt.Sprintf("%d:add", i),
				Candidates: []*clientmodels.SelectableCredentialInstance{},
				Obtainable: view.ObtainableOptions,
			}}})
		}
		choices = append(choices, choice)
	}
	return choices
}

// stepChoices builds required choices that cannot be answered yet, one per
// step: per step option, an option whose slots each miss one of its types.
func stepChoices(steps []issuanceStep) []clientmodels.DisclosureChoice {
	choices := make([]clientmodels.DisclosureChoice, 0, len(steps))
	for i, step := range steps {
		choice := clientmodels.DisclosureChoice{Options: []clientmodels.DisclosureOption{}}
		for k, b := range step.Options {
			option := clientmodels.DisclosureOption{}
			for j, d := range b.Credentials {
				option.Slots = append(option.Slots, clientmodels.DisclosureSlot{
					Id:         fmt.Sprintf("step%d:%d:%d", i, k, j),
					Candidates: []*clientmodels.SelectableCredentialInstance{},
					Obtainable: []*clientmodels.CredentialDescriptor{d},
				})
			}
			choice.Options = append(choice.Options, option)
		}
		choices = append(choices, choice)
	}
	return choices
}

// singleCredBundles wraps each card as a one-card bundle.
func singleCredBundles(creds ...*clientmodels.SelectableCredentialInstance) []*bundle {
	out := make([]*bundle, 0, len(creds))
	for _, c := range creds {
		out = append(out, &bundle{Credentials: []*clientmodels.SelectableCredentialInstance{c}})
	}
	return out
}
