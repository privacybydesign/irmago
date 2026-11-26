package clientmodels

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAnswer(t *testing.T) {
	two := uint(2)
	one := uint(1)
	card := func(hash string) *SelectableCredentialInstance {
		return &SelectableCredentialInstance{Hash: hash, Usable: true}
	}
	expired := &SelectableCredentialInstance{Hash: "expired", UnusableReason: UnusableReason_Expired}
	batchOfTwo := &SelectableCredentialInstance{Hash: "batch", Usable: true, BatchInstanceCountRemaining: &two}
	lastUse := &SelectableCredentialInstance{Hash: "last", Usable: true, BatchInstanceCountRemaining: &one}

	slot := func(id string, multiple bool, candidates ...*SelectableCredentialInstance) DisclosureSlot {
		return DisclosureSlot{Id: id, Multiple: multiple, Candidates: candidates}
	}
	// Choice 0 (required): option 0 is pid + email, option 1 is passport.
	// Choice 1 (optional): phone, or the same pid query again.
	// Choice 2 (required): emails, multiple; and two slots of one type.
	plan := &DisclosurePlan{Choices: []DisclosureChoice{
		{Options: []DisclosureOption{
			{Slots: []DisclosureSlot{slot("pid", false, card("pid-1"), card("pid-2")), slot("email", false, card("e-1"), expired, batchOfTwo, lastUse)}},
			{Slots: []DisclosureSlot{slot("passport", false, card("pp-1"))}},
		}},
		{Optional: true, Options: []DisclosureOption{
			{Slots: []DisclosureSlot{slot("phone", false, card("ph-1"))}},
			{Slots: []DisclosureSlot{slot("pid", false, card("pid-1"), card("pid-2"))}},
		}},
		{Options: []DisclosureOption{
			{Slots: []DisclosureSlot{slot("emails", true, card("e-1"), card("e-2"), batchOfTwo)}},
			{Slots: []DisclosureSlot{slot("email1", false, batchOfTwo, lastUse, card("e-1")), slot("email2", false, batchOfTwo, lastUse, card("e-1"))}},
		}},
	}}

	pick := func(slotId string, hashes ...string) SlotSelection {
		sel := SlotSelection{SlotId: slotId}
		for _, h := range hashes {
			sel.Credentials = append(sel.Credentials, SelectedCredential{CredentialHash: h})
		}
		return sel
	}
	choice := func(option int, slots ...SlotSelection) ChoiceSelection {
		return ChoiceSelection{Option: option, Slots: slots}
	}
	valid := func() []ChoiceSelection {
		return []ChoiceSelection{
			choice(0, pick("pid", "pid-1"), pick("email", "e-1")),
			choice(-1),
			choice(0, pick("emails", "e-1", "e-2")),
		}
	}
	with := func(i int, c ChoiceSelection) []ChoiceSelection {
		a := valid()
		a[i] = c
		return a
	}

	tests := []struct {
		name    string
		answer  []ChoiceSelection
		wantErr string
	}{
		{"valid", valid(), ""},
		{"too few choices", valid()[:2], "answer has 2 choices, the plan 3"},
		{"nothing for a required choice", with(0, choice(-1)), "choice 0 is required"},
		{"nothing, but naming slots", with(1, choice(-1, pick("phone", "ph-1"))), "shares nothing"},
		{"an option that does not exist", with(0, choice(2)), "no option 2"},
		{"too few slots", with(0, choice(0, pick("pid", "pid-1"))), "has 2 slots, the answer 1"},
		{"slots out of order", with(0, choice(0, pick("email", "e-1"), pick("pid", "pid-1"))), `is "pid", the answer names "email"`},
		{"an unknown slot id", with(0, choice(1, pick("visa", "pp-1"))), `the answer names "visa"`},
		{"no card", with(0, choice(0, pick("pid"), pick("email", "e-1"))), `slot "pid" has no card`},
		{"two cards for a single slot", with(0, choice(0, pick("pid", "pid-1", "pid-2"), pick("email", "e-1"))), "takes one card"},
		{"several cards for a multiple slot", with(2, choice(0, pick("emails", "e-1", "e-2", "batch"))), ""},
		{"one card twice in a multiple slot", with(2, choice(0, pick("emails", "e-1", "e-1"))), "twice"},
		{"a card that is not a candidate", with(0, choice(0, pick("pid", "pp-1"), pick("email", "e-1"))), "not a candidate"},
		{"an unusable candidate", with(0, choice(0, pick("pid", "pid-1"), pick("email", "expired"))), "cannot be used"},
		{"the same slot in two choices, same card", with(1, choice(1, pick("pid", "pid-1"))), ""},
		{"the same slot in two choices, different cards", with(1, choice(1, pick("pid", "pid-2"))), "different cards in two choices"},
		{"one card in two slots with two uses left", with(2, choice(1, pick("email1", "batch"), pick("email2", "batch"))), ""},
		{"one card in two slots with one use left", with(2, choice(1, pick("email1", "last"), pick("email2", "last"))), "has 1 uses left"},
		{"one unlimited card in two slots", with(2, choice(1, pick("email1", "e-1"), pick("email2", "e-1"))), ""},
		{"a card used in two choices counts twice", []ChoiceSelection{
			choice(0, pick("pid", "pid-1"), pick("email", "last")),
			choice(-1),
			choice(1, pick("email1", "last"), pick("email2", "e-1")),
		}, "has 1 uses left"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAnswer(plan, tt.answer)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}

	t.Run("no plan takes only an empty answer", func(t *testing.T) {
		require.NoError(t, ValidateAnswer(nil, nil))
		require.NoError(t, ValidateAnswer(nil, []ChoiceSelection{}))
		require.Error(t, ValidateAnswer(nil, []ChoiceSelection{choice(-1)}))
	})
}
