package protocol

import (
	"encoding/json"
	"errors"

	"github.com/credentials/irmago"
)

// AttributeDisjunction ...
type AttributeDisjunction struct {
	Label      string
	Attributes []irmago.AttributeIdentifier
	Values     map[irmago.AttributeIdentifier]string

	selected *irmago.AttributeIdentifier
}

type AttributeDisjunctionList []*AttributeDisjunction

func (disjunction *AttributeDisjunction) HasValues() bool {
	return disjunction.Values != nil && len(disjunction.Values) != 0
}

func (disjunction *AttributeDisjunction) Satisfied() bool {
	if disjunction.selected == nil {
		return false
	}
	for _, attr := range disjunction.Attributes {
		if *disjunction.selected == attr {
			return true
		}
	}
	return false
}

// MatchesStore returns true if all attributes contained in the disjunction are
// present in the MetaStore.
func (disjunction *AttributeDisjunction) MatchesStore() bool {
	for ai := range disjunction.Values {
		creddescription, exists := irmago.MetaStore.Credentials[ai.CredentialTypeIdentifier()]
		if !exists {
			return false
		}
		if !creddescription.ContainsAttribute(ai) {
			return false
		}
	}
	return true
}

// Satisfied indicates whether each contained attribute disjunction has a chosen attribute.
func (dl AttributeDisjunctionList) Satisfied() bool {
	for _, disjunction := range dl {
		if !disjunction.Satisfied() {
			return false
		}
	}
	return true
}

// Find searches for and returns the disjunction that contains the specified attribute identifier, or nil if not found.
func (dl AttributeDisjunctionList) Find(ai irmago.AttributeIdentifier) *AttributeDisjunction {
	for _, disjunction := range dl {
		for _, attr := range disjunction.Attributes {
			if attr == ai {
				return disjunction
			}
		}
	}
	return nil
}

func (disjunction *AttributeDisjunction) MarshalJSON() ([]byte, error) {
	if !disjunction.HasValues() {
		temp := struct {
			Label      string                       `json:"label"`
			Attributes []irmago.AttributeIdentifier `json:"attributes"`
		}{
			Label:      disjunction.Label,
			Attributes: disjunction.Attributes,
		}
		return json.Marshal(temp)
	} else {
		temp := struct {
			Label      string                                `json:"label"`
			Attributes map[irmago.AttributeIdentifier]string `json:"attributes"`
		}{
			Label:      disjunction.Label,
			Attributes: disjunction.Values,
		}
		return json.Marshal(temp)
	}
}

func (disjunction *AttributeDisjunction) UnmarshalJSON(bytes []byte) error {
	if disjunction.Values == nil {
		disjunction.Values = make(map[irmago.AttributeIdentifier]string)
	}
	if disjunction.Attributes == nil {
		disjunction.Attributes = make([]irmago.AttributeIdentifier, 0, 3)
	}

	// We don't know if the json element "attributes" is a list, or a map.
	// So we unmarshal it into a temporary struct that has interface{} as the
	// type of "attributes", so that we can check which of the two it is.
	temp := struct {
		Label      string      `json:"label"`
		Attributes interface{} `json:"attributes"`
	}{}
	json.Unmarshal(bytes, &temp)
	disjunction.Label = temp.Label

	switch temp.Attributes.(type) {
	case map[string]interface{}:
		temp := struct {
			Label      string            `json:"label"`
			Attributes map[string]string `json:"attributes"`
		}{}
		json.Unmarshal(bytes, &temp)
		for str, value := range temp.Attributes {
			id := irmago.NewAttributeIdentifier(str)
			disjunction.Attributes = append(disjunction.Attributes, id)
			disjunction.Values[id] = value
		}
	case []interface{}:
		temp := struct {
			Label      string   `json:"label"`
			Attributes []string `json:"attributes"`
		}{}
		json.Unmarshal(bytes, &temp)
		for _, str := range temp.Attributes {
			disjunction.Attributes = append(disjunction.Attributes, irmago.NewAttributeIdentifier(str))
		}
	default:
		return errors.New("could not parse attribute disjunction: element 'attributes' was incorrect")
	}

	return nil
}
