package protocol

import (
	"encoding/json"
	"errors"

	"github.com/credentials/irmago"
)

// An AttributeDisjunction encapsulates a list of possible attributes, one
// of which should be disclused.
type AttributeDisjunction struct {
	Label      string
	Attributes []irmago.AttributeTypeIdentifier
	Values     map[irmago.AttributeTypeIdentifier]string

	selected *irmago.AttributeTypeIdentifier
}

// An AttributeDisjunctionList is a list of AttributeDisjunctions.
type AttributeDisjunctionList []*AttributeDisjunction

// HasValues indicates if the attributes of this disjunction have values
// that should be satisfied.
func (disjunction *AttributeDisjunction) HasValues() bool {
	return disjunction.Values != nil && len(disjunction.Values) != 0
}

// Satisfied indicates if this disjunction has a valid chosen attribute
// to be disclosed.
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
func (dl AttributeDisjunctionList) Find(ai irmago.AttributeTypeIdentifier) *AttributeDisjunction {
	for _, disjunction := range dl {
		for _, attr := range disjunction.Attributes {
			if attr == ai {
				return disjunction
			}
		}
	}
	return nil
}

// MarshalJSON marshals the disjunction to JSON.
func (disjunction *AttributeDisjunction) MarshalJSON() ([]byte, error) {
	if !disjunction.HasValues() {
		temp := struct {
			Label      string                           `json:"label"`
			Attributes []irmago.AttributeTypeIdentifier `json:"attributes"`
		}{
			Label:      disjunction.Label,
			Attributes: disjunction.Attributes,
		}
		return json.Marshal(temp)
	}

	temp := struct {
		Label      string                                    `json:"label"`
		Attributes map[irmago.AttributeTypeIdentifier]string `json:"attributes"`
	}{
		Label:      disjunction.Label,
		Attributes: disjunction.Values,
	}
	return json.Marshal(temp)
}

// UnmarshalJSON unmarshals an attribute disjunction from JSON.
func (disjunction *AttributeDisjunction) UnmarshalJSON(bytes []byte) error {
	if disjunction.Values == nil {
		disjunction.Values = make(map[irmago.AttributeTypeIdentifier]string)
	}
	if disjunction.Attributes == nil {
		disjunction.Attributes = make([]irmago.AttributeTypeIdentifier, 0, 3)
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
			id := irmago.NewAttributeTypeIdentifier(str)
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
			disjunction.Attributes = append(disjunction.Attributes, irmago.NewAttributeTypeIdentifier(str))
		}
	default:
		return errors.New("could not parse attribute disjunction: element 'attributes' was incorrect")
	}

	return nil
}
