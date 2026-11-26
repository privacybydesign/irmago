package client

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/irma"
)

// The answer per slot (clientmodels.ChoiceSelection), checked with
// clientmodels.ValidateAnswer, becomes what each protocol sends.

// answerToOpenID4VPSelections turns an answer into one DCQL selection per card
// per slot: the slot id is the query id. A slot named in several choices (one
// query in two credential sets) is presented once.
func answerToOpenID4VPSelections(answer []clientmodels.ChoiceSelection) []dcql.DisclosureSelection {
	selections := []dcql.DisclosureSelection{}
	presented := map[string]struct{}{}
	for _, choice := range answer {
		for _, slot := range choice.Slots {
			for _, credential := range slot.Credentials {
				key := slot.SlotId + "\x00" + credential.CredentialHash
				if _, done := presented[key]; done {
					continue
				}
				presented[key] = struct{}{}
				claimPaths := make([][]any, 0, len(credential.AttributePaths))
				for _, path := range credential.AttributePaths {
					if len(path) > 0 {
						claimPaths = append(claimPaths, path)
					}
				}
				selections = append(selections, dcql.DisclosureSelection{
					QueryId:        slot.SlotId,
					CredentialHash: credential.CredentialHash,
					ClaimPaths:     claimPaths,
				})
			}
		}
	}
	return selections
}

// answerToIrmaChoice turns an answer into the IRMA disclosure choice for the
// request's condiscon. For a chosen option it discloses exactly the attributes
// of the matching con, in the con's order (the verifier matches them by
// position), each from the card chosen for its credential type's slot. The app's
// attribute paths are not needed: an IRMA con fixes what is disclosed. A choice
// answered with nothing discloses nothing.
func answerToIrmaChoice(answer []clientmodels.ChoiceSelection, condiscon irma.AttributeConDisCon) (*irma.DisclosureChoice, error) {
	result := &irma.DisclosureChoice{Attributes: [][]*irma.AttributeIdentifier{}}
	if len(answer) != len(condiscon) {
		return nil, fmt.Errorf("answer has %d choices, the request %d discons", len(answer), len(condiscon))
	}
	for disconIndex, choice := range answer {
		attrs := []*irma.AttributeIdentifier{}
		if choice.Option == -1 {
			result.Attributes = append(result.Attributes, attrs)
			continue
		}

		// Options are the discon's non-empty cons, in order.
		var cons []irma.AttributeCon
		for _, con := range condiscon[disconIndex] {
			if len(con) > 0 {
				cons = append(cons, con)
			}
		}
		if choice.Option < 0 || choice.Option >= len(cons) {
			return nil, fmt.Errorf("discon %d has no option %d", disconIndex, choice.Option)
		}

		hashBySlotId := make(map[string]string, len(choice.Slots))
		for _, slot := range choice.Slots {
			if len(slot.Credentials) != 1 {
				return nil, fmt.Errorf("slot %q has %d cards, an IRMA slot takes one", slot.SlotId, len(slot.Credentials))
			}
			hashBySlotId[slot.SlotId] = slot.Credentials[0].CredentialHash
		}
		for _, request := range cons[choice.Option] {
			slotId := IrmaSlotId(disconIndex, request.Type.CredentialTypeIdentifier())
			hash, ok := hashBySlotId[slotId]
			if !ok {
				return nil, fmt.Errorf("no card chosen for slot %q", slotId)
			}
			attrs = append(attrs, &irma.AttributeIdentifier{Type: request.Type, CredentialHash: hash})
		}
		result.Attributes = append(result.Attributes, attrs)
	}
	return result, nil
}
