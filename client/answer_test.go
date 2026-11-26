package client

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func pickSlot(slotId string, credentials ...clientmodels.SelectedCredential) clientmodels.SlotSelection {
	return clientmodels.SlotSelection{SlotId: slotId, Credentials: credentials}
}

func card(hash string, paths ...[]any) clientmodels.SelectedCredential {
	return clientmodels.SelectedCredential{CredentialHash: hash, AttributePaths: paths}
}

func TestAnswerToOpenID4VPSelections(t *testing.T) {
	t.Run("one selection per card per slot, the slot id as query id", func(t *testing.T) {
		selections := answerToOpenID4VPSelections([]clientmodels.ChoiceSelection{
			{Option: 0, Slots: []clientmodels.SlotSelection{
				pickSlot("pid", card("pid-1", []any{"family_name"}, []any{"address", "street"})),
				pickSlot("eec", card("eec-1", []any{"credentialSubject", "code"})),
			}},
		})
		assert.Equal(t, []dcql.DisclosureSelection{
			{QueryId: "pid", CredentialHash: "pid-1", ClaimPaths: [][]any{{"family_name"}, {"address", "street"}}},
			{QueryId: "eec", CredentialHash: "eec-1", ClaimPaths: [][]any{{"credentialSubject", "code"}}},
		}, selections)
	})

	t.Run("a multiple slot gives a selection per card", func(t *testing.T) {
		selections := answerToOpenID4VPSelections([]clientmodels.ChoiceSelection{
			{Option: 0, Slots: []clientmodels.SlotSelection{pickSlot("emails", card("e-1"), card("e-2"))}},
		})
		require.Len(t, selections, 2)
		assert.Equal(t, "emails", selections[0].QueryId)
		assert.Equal(t, "emails", selections[1].QueryId)
	})

	t.Run("one card in two slots is presented for each", func(t *testing.T) {
		selections := answerToOpenID4VPSelections([]clientmodels.ChoiceSelection{
			{Option: 0, Slots: []clientmodels.SlotSelection{pickSlot("email1", card("e-1")), pickSlot("email2", card("e-1"))}},
		})
		require.Len(t, selections, 2)
		assert.Equal(t, []string{"email1", "email2"}, []string{selections[0].QueryId, selections[1].QueryId})
	})

	t.Run("one slot in two choices is presented once", func(t *testing.T) {
		selections := answerToOpenID4VPSelections([]clientmodels.ChoiceSelection{
			{Option: 0, Slots: []clientmodels.SlotSelection{pickSlot("pid", card("pid-1")), pickSlot("email", card("e-1"))}},
			{Option: 0, Slots: []clientmodels.SlotSelection{pickSlot("pid", card("pid-1")), pickSlot("phone", card("ph-1"))}},
		})
		var ids []string
		for _, s := range selections {
			ids = append(ids, s.QueryId)
		}
		assert.Equal(t, []string{"pid", "email", "phone"}, ids)
	})

	t.Run("an optional choice answered with nothing sends nothing for it", func(t *testing.T) {
		selections := answerToOpenID4VPSelections([]clientmodels.ChoiceSelection{
			{Option: -1},
			{Option: 0, Slots: []clientmodels.SlotSelection{pickSlot("email", card("e-1"))}},
		})
		require.Len(t, selections, 1)
		assert.Equal(t, "email", selections[0].QueryId)
	})
}

func TestAnswerToIrmaChoice(t *testing.T) {
	condiscon := irma.AttributeConDisCon{}
	require.NoError(t, json.Unmarshal([]byte(`[
		[[], ["irma-demo.MijnOverheid.fullName.familyname"]],
		[
			["irma-demo.RU.studentCard.level", "irma-demo.MijnOverheid.root.BSN", "irma-demo.RU.studentCard.studentID"],
			["irma-demo.RU.studentCard"]
		]
	]`), &condiscon))

	attrs := func(choice *irma.DisclosureChoice, i int) []string {
		var out []string
		for _, a := range choice.Attributes[i] {
			out = append(out, a.Type.String()+"@"+a.CredentialHash)
		}
		return out
	}

	t.Run("the con's attributes in the con's order, from the card per type", func(t *testing.T) {
		choice, err := answerToIrmaChoice([]clientmodels.ChoiceSelection{
			{Option: 0, Slots: []clientmodels.SlotSelection{pickSlot("0:irma-demo.MijnOverheid.fullName", card("name"))}},
			// Slots in schema order and paths in any order: the con decides.
			{Option: 0, Slots: []clientmodels.SlotSelection{
				pickSlot("1:irma-demo.RU.studentCard", card("student", []any{"studentID"}, []any{"level"})),
				pickSlot("1:irma-demo.MijnOverheid.root", card("root", []any{"BSN"})),
			}},
		}, condiscon)
		require.NoError(t, err)
		require.Len(t, choice.Attributes, 2)
		assert.Equal(t, []string{"irma-demo.MijnOverheid.fullName.familyname@name"}, attrs(choice, 0),
			"option 0 is the first non-empty con")
		assert.Equal(t, []string{
			"irma-demo.RU.studentCard.level@student",
			"irma-demo.MijnOverheid.root.BSN@root",
			"irma-demo.RU.studentCard.studentID@student",
		}, attrs(choice, 1))
	})

	t.Run("an optional choice answered with nothing discloses nothing", func(t *testing.T) {
		choice, err := answerToIrmaChoice([]clientmodels.ChoiceSelection{
			{Option: -1},
			{Option: 1, Slots: []clientmodels.SlotSelection{pickSlot("1:irma-demo.RU.studentCard", card("student"))}},
		}, condiscon)
		require.NoError(t, err)
		assert.Empty(t, choice.Attributes[0])
		assert.Equal(t, []string{"irma-demo.RU.studentCard@student"}, attrs(choice, 1),
			"a request for only the credential discloses the credential")
	})

	t.Run("a slot of the con left out is an error", func(t *testing.T) {
		_, err := answerToIrmaChoice([]clientmodels.ChoiceSelection{
			{Option: -1},
			{Option: 0, Slots: []clientmodels.SlotSelection{pickSlot("1:irma-demo.RU.studentCard", card("student"))}},
		}, condiscon)
		require.Error(t, err)
	})
}

// sessionWithPlan is a session waiting for permission on plan, with spies for
// what reaches the UI and the protocol.
func sessionWithPlan(plan *clientmodels.DisclosurePlan) (*session, *dispatchSpy, *[]dcql.DisclosureSelection, *int) {
	s, spy := newFinishTestSession()
	s.State.Status = clientmodels.Status_RequestPermission
	s.State.DisclosurePlan = plan
	var granted []dcql.DisclosureSelection
	dismissed := 0
	s.openid4vpPermissionHandler = func(proceed bool, selections []dcql.DisclosureSelection) {
		if proceed {
			granted = selections
		}
	}
	s.dismisser = dismisserFunc(func() {
		dismissed++
		// What a protocol does on dismissal: report it.
		s.State.Status = clientmodels.Status_Dismissed
		s.finish()
	})
	return s, spy, &granted, &dismissed
}

type dismisserFunc func()

func (f dismisserFunc) Dismiss() { f() }

func TestAnswerPermission(t *testing.T) {
	plan := &clientmodels.DisclosurePlan{Choices: []clientmodels.DisclosureChoice{{Options: []clientmodels.DisclosureOption{{
		Slots: []clientmodels.DisclosureSlot{{Id: "email", Candidates: []*clientmodels.SelectableCredentialInstance{
			{Hash: "e-1", Usable: true},
			{Hash: "e-old", UnusableReason: clientmodels.UnusableReason_Expired},
		}}},
	}}}}}
	answer := func(hash string) clientmodels.SessionPermissionInteractionPayload {
		return clientmodels.SessionPermissionInteractionPayload{Granted: true, Choices: []clientmodels.ChoiceSelection{
			{Option: 0, Slots: []clientmodels.SlotSelection{pickSlot("email", card(hash, []any{"email"}))}},
		}}
	}

	t.Run("a valid answer reaches the protocol", func(t *testing.T) {
		s, spy, granted, dismissed := sessionWithPlan(plan)
		require.NoError(t, s.answerPermission(answer("e-1")))
		assert.Equal(t, []dcql.DisclosureSelection{{QueryId: "email", CredentialHash: "e-1", ClaimPaths: [][]any{{"email"}}}}, *granted)
		assert.Zero(t, *dismissed)
		assert.Empty(t, spy.statuses)
	})

	t.Run("an answer naming an unusable card ends the session with an error", func(t *testing.T) {
		s, spy, granted, dismissed := sessionWithPlan(plan)
		err := s.answerPermission(answer("e-old"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be used")
		assert.Nil(t, *granted, "nothing is presented")
		assert.Equal(t, 1, *dismissed, "the protocol is stopped")
		assert.Equal(t, []clientmodels.SessionStatus{clientmodels.Status_Error}, spy.statuses,
			"the UI sees the error, not the dismissal that follows it")
	})

	t.Run("a refusal needs no valid answer", func(t *testing.T) {
		s, _, granted, _ := sessionWithPlan(plan)
		refused := false
		s.openid4vpPermissionHandler = func(proceed bool, _ []dcql.DisclosureSelection) { refused = !proceed }
		require.NoError(t, s.answerPermission(clientmodels.SessionPermissionInteractionPayload{Granted: false, Choices: []clientmodels.ChoiceSelection{}}))
		assert.True(t, refused)
		assert.Nil(t, *granted)
	})
}
