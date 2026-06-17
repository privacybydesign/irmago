package did

import (
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Document represents a W3C DID Document.
type Document struct {
	Context            any                  `json:"@context"`
	ID                 string               `json:"id"`
	Controller         string               `json:"controller,omitempty"`
	VerificationMethod []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication     []VerificationRef    `json:"authentication,omitempty"`
	AssertionMethod    []VerificationRef    `json:"assertionMethod,omitempty"`
	KeyAgreement       []VerificationRef    `json:"keyAgreement,omitempty"`
	Service            []Service            `json:"service,omitempty"`
}

type VerificationMethodType string

const (
	VerificationMethodType_JsonWebKey     VerificationMethodType = "JsonWebKey"
	VerificationMethodType_JsonWebKey2020 VerificationMethodType = "JsonWebKey2020"
	VerificationMethodType_Multikey       VerificationMethodType = "Multikey"
)

// VerificationMethod represents a verification method in a DID Document.
type VerificationMethod struct {
	Context      any                    `json:"@context,omitempty"`
	ID           string                 `json:"id"`
	Type         VerificationMethodType `json:"type"`
	Controller   string                 `json:"controller"`
	PublicKeyJwk *jwk.Key               `json:"publicKeyJwk,omitempty"`
	Expires      *string                `json:"expires,omitempty"`
	Revoked      *string                `json:"revoked,omitempty"`
}

// VerificationRef can be either a string (reference) or an embedded VerificationMethod.
type VerificationRef any

// Service represents a service endpoint in a DID Document.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint any    `json:"serviceEndpoint"`
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
