package client

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

// createIrmaChoices describes an IRMA condiscon as choices → options → slots:
//
//   - one choice per discon, optional when it holds an empty con (which is not
//     an option itself);
//   - one option per non-empty con;
//   - one slot per credential type of the con, in order of first appearance,
//     with id "{discon index}:{credential type id}", so the same type in two
//     discons is two independent slots.
//
// A slot's candidates are the stored instances of its type that satisfy the
// con, each with only the attributes the con asks of that type (none when it
// asks only for the credential), in schema order, best first. Its obtainable
// descriptor is offered when irmaclient suggests adding the type.
func createIrmaChoices(
	irmaConfig *irma.Configuration,
	credentials []*clientmodels.Credential,
	discons []irmaclient.DisconSlots,
	locale string,
) ([]clientmodels.DisclosureChoice, error) {
	choices := make([]clientmodels.DisclosureChoice, 0, len(discons))
	for disconIndex, discon := range discons {
		choice := clientmodels.DisclosureChoice{
			Optional: discon.Optional,
			Options:  make([]clientmodels.DisclosureOption, 0, len(discon.Cons)),
		}
		for _, con := range discon.Cons {
			option := clientmodels.DisclosureOption{Slots: make([]clientmodels.DisclosureSlot, 0, len(con))}
			for _, credSlot := range con {
				slot, err := createIrmaSlot(irmaConfig, credentials, disconIndex, credSlot, locale)
				if err != nil {
					return nil, err
				}
				option.Slots = append(option.Slots, slot)
			}
			choice.Options = append(choice.Options, option)
		}
		choices = append(choices, choice)
	}
	return choices, nil
}

// IrmaSlotId is the id of the slot for a credential type in a discon.
func IrmaSlotId(disconIndex int, credType irma.CredentialTypeIdentifier) string {
	return fmt.Sprintf("%d:%s", disconIndex, credType.String())
}

func createIrmaSlot(
	irmaConfig *irma.Configuration,
	credentials []*clientmodels.Credential,
	disconIndex int,
	credSlot irmaclient.CredentialSlot,
	locale string,
) (clientmodels.DisclosureSlot, error) {
	slot := clientmodels.DisclosureSlot{
		Id:         IrmaSlotId(disconIndex, credSlot.Type),
		Candidates: make([]*clientmodels.SelectableCredentialInstance, 0, len(credSlot.Candidates)),
		Obtainable: []*clientmodels.CredentialDescriptor{},
	}
	credType := irmaConfig.CredentialTypes[credSlot.Type]

	for _, candidate := range credSlot.Candidates {
		orig := findCredential(credentials, candidate.Hash)
		if orig == nil {
			return clientmodels.DisclosureSlot{}, fmt.Errorf("failed to find credential for hash: %v", candidate.Hash)
		}
		instance := *orig
		instance.Attributes = []clientmodels.Attribute{}
		for _, request := range credSlot.Requests {
			if request.Type.IsCredential() {
				continue // only the credential is asked for: no attribute
			}
			attr, ok := lookupAttrValue(orig, &irma.AttributeIdentifier{Type: request.Type})
			if !ok {
				return clientmodels.DisclosureSlot{}, fmt.Errorf("credential %s does not contain attribute %v", candidate.Hash, request.Type)
			}
			if request.Value != nil {
				requested := irmaRequestedValue(request)
				attr.RequestedValue = &requested
				attr.RequestedValues = []clientmodels.AttributeValue{requested}
			}
			instance.Attributes = append(instance.Attributes, attr)
		}
		instance.Attributes = sortAttributesBySchema(instance.Attributes, credType)
		instance.Usable = candidate.Usable
		instance.UnusableReason = clientmodels.UnusableReason(candidate.Reason)
		slot.Candidates = append(slot.Candidates, &instance)
	}
	clientmodels.SortCandidates(slot.Candidates)

	if credSlot.Obtainable {
		descriptor, err := getCredentialDescriptor(irmaConfig, credSlot.Type, locale)
		if err != nil {
			return clientmodels.DisclosureSlot{}, err
		}
		for _, request := range credSlot.Requests {
			if request.Type.IsCredential() {
				continue
			}
			for i := range descriptor.Attributes {
				if clientmodels.ClaimPathKey(descriptor.Attributes[i].ClaimPath) != clientmodels.ClaimPathKey([]any{request.Type.Name()}) {
					continue
				}
				requested := irmaRequestedValue(request)
				descriptor.Attributes[i].RequestedValue = &requested
				if request.Value != nil {
					descriptor.Attributes[i].RequestedValues = []clientmodels.AttributeValue{requested}
				}
			}
		}
		slot.Obtainable = append(slot.Obtainable, descriptor)
	}
	return slot, nil
}

// irmaRequestedValue is what an IRMA attribute request asks: a string value
// when it requires one, else only the type, as the pick-one plan sends it.
func irmaRequestedValue(request irma.AttributeRequest) clientmodels.AttributeValue {
	value := clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}
	if request.Value != nil {
		v := *request.Value
		value.String = &v
	}
	return value
}
