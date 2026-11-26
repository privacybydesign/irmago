package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// TestAnswerSkipsAnOptionalChoice pins how a skipped optional credential
// reaches the DCQL handlers: as nothing at all.
//
// A DCQL credential_set with `"required": false` becomes an optional choice,
// which the app skips with option -1. The conversion then produces no
// DisclosureSelection for it, so no handler is asked to disclose anything and
// the credential is simply absent from the response.
//
// This matters because the alternative shape, a selected credential carrying no
// claim paths, is refused by mdoc_dcql.selectiveDiscloseByPaths and fails the
// whole disclosure. That refusal is correct — an mdoc has no always-disclosed
// payload, so disclosing zero elements would emit an empty `nameSpaces` map,
// which ISO/IEC 18013-5 does not permit — but it must never be what a legitimate
// skip produces. If someone later makes the conversion emit a selection for
// every choice regardless, this test fails rather than optional credentials
// becoming un-skippable.
func TestAnswerSkipsAnOptionalChoice(t *testing.T) {
	plan := &clientmodels.DisclosurePlan{Choices: []clientmodels.DisclosureChoice{
		{Options: []clientmodels.DisclosureOption{{Slots: []clientmodels.DisclosureSlot{{
			Id: "required_pid", Candidates: []*clientmodels.SelectableCredentialInstance{{Hash: "required-hash", Usable: true}},
		}}}}},
		{Optional: true, Options: []clientmodels.DisclosureOption{{Slots: []clientmodels.DisclosureSlot{{
			Id: "optional_age", Candidates: []*clientmodels.SelectableCredentialInstance{{Hash: "optional-hash", Usable: true}},
		}}}}},
	}}
	answer := []clientmodels.ChoiceSelection{
		{Option: 0, Slots: []clientmodels.SlotSelection{{SlotId: "required_pid", Credentials: []clientmodels.SelectedCredential{{
			CredentialId:   "urn:eudi:pid:1",
			CredentialHash: "required-hash",
			AttributePaths: [][]any{{"given_name"}},
		}}}}},
		{Option: -1},
	}
	require.NoError(t, clientmodels.ValidateAnswer(plan, answer))

	selections := answerToOpenID4VPSelections(answer)
	require.Len(t, selections, 1,
		"a skipped optional choice must produce no selection, so no handler is asked to disclose nothing")
	require.Equal(t, "required_pid", selections[0].QueryId)
	require.Equal(t, "required-hash", selections[0].CredentialHash)
	require.NotEmpty(t, selections[0].ClaimPaths,
		"the required credential must still carry the paths it discloses")

	// Naming a card for the skipped choice while saying "nothing" is refused,
	// rather than read as either.
	answer[1].Slots = []clientmodels.SlotSelection{{SlotId: "optional_age"}}
	require.Error(t, clientmodels.ValidateAnswer(plan, answer))
}
