package did

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Document represents a W3C DID Document.
type Document struct {
	Context            interface{}          `json:"@context"`
	ID                 string               `json:"id"`
	Controller         string               `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []VerificationRef    `json:"authentication,omitempty"`
	AssertionMethod    []VerificationRef    `json:"assertionMethod,omitempty"`
	KeyAgreement       []VerificationRef    `json:"keyAgreement,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

// VerificationMethod represents a verification method in a DID Document.
type VerificationMethod struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	Controller         string   `json:"controller"`
	PublicKeyJwk       *jwk.Key `json:"publicKeyJwk,omitempty"`
	PublicKeyMultibase string   `json:"publicKeyMultibase,omitempty"`
}

// VerificationRef can be either a string (reference) or an embedded VerificationMethod.
type VerificationRef interface{}

// Service represents a service endpoint in a DID Document.
type Service struct {
	ID              string      `json:"id"`
	Type            string      `json:"type"`
	ServiceEndpoint interface{} `json:"serviceEndpoint"`
}

func (v *VerificationMethod) UnmarshalJSON(data []byte) error {
	type Alias VerificationMethod
	aux := &struct {
		PublicKeyJwk any `json:"publicKeyJwk,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(v),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.PublicKeyJwk != nil {
		jsonData, err := json.Marshal(aux.PublicKeyJwk)
		if err != nil {
			return fmt.Errorf("failed to marshal publicKeyJwk: %v", err)
		}
		key, err := jwk.ParseKey(jsonData)
		if err != nil {
			return fmt.Errorf("failed to parse publicKeyJwk: %v", err)
		}
		v.PublicKeyJwk = &key
	}

	return nil
}
