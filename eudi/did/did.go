package did

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/mr-tron/base58/base58"
)

// Document represents a W3C DID Document.
type Document struct {
	Context              any                  `json:"@context"` // can be either a string or a list of strings
	ID                   string               `json:"id"`
	AlsoKnownAs          []string             `json:"alsoKnownAs,omitempty"`
	Controller           any                  `json:"controller,omitempty"` // can be either a string or a list of strings
	VerificationMethod   []VerificationMethod `json:"verificationMethod,omitempty"`
	Authentication       []VerificationRef    `json:"authentication,omitempty"`
	AssertionMethod      []VerificationRef    `json:"assertionMethod,omitempty"`
	KeyAgreement         []VerificationRef    `json:"keyAgreement,omitempty"`
	CapabilityInvocation []VerificationRef    `json:"capabilityInvocation,omitempty"`
	CapabilityDelegation []VerificationRef    `json:"capabilityDelegation,omitempty"`
	Service              []Service            `json:"service,omitempty"`
}

type VerificationMethodType string

const (
	VerificationMethodType_JsonWebKey                 VerificationMethodType = "JsonWebKey"
	VerificationMethodType_JsonWebKey2020             VerificationMethodType = "JsonWebKey2020"
	VerificationMethodType_Multikey                   VerificationMethodType = "Multikey"
	VerificationMethodType_Ed25519VerificationKey2018 VerificationMethodType = "Ed25519VerificationKey2018"
)

// VerificationMethod represents a verification method in a DID Document.
type VerificationMethod struct {
	Context      any                    `json:"@context,omitempty"`
	ID           string                 `json:"id"`
	Type         VerificationMethodType `json:"type"`
	Controller   string                 `json:"controller"`
	Expires      *string                `json:"expires,omitempty"`
	Revoked      *string                `json:"revoked,omitempty"`
	PublicKeyJwk *jwk.Key               `json:"publicKeyJwk,omitempty"`

	PublicKeyMultibase        *string `json:"publicKeyMultibase,omitempty"`
	decodedMultibasePublicKey *jwk.Key

	PublicKeyBase58        *string `json:"publicKeyBase58,omitempty"`
	decodedBase58PublicKey *jwk.Key
}

func (v *VerificationMethod) PublicKey() *jwk.Key {
	if v.PublicKeyJwk != nil {
		return v.PublicKeyJwk
	}
	if v.decodedMultibasePublicKey != nil {
		return v.decodedMultibasePublicKey
	}
	return v.decodedBase58PublicKey
}

// VerificationRef can be either a string (reference) or an embedded VerificationMethod.
type VerificationRef any

// Service represents a service endpoint in a DID Document.
type Service struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint any    `json:"serviceEndpoint"`
}

func (d *Document) UnmarshalJSON(data []byte) error {
	type Alias Document
	aux := &struct {
		Authentication       []json.RawMessage `json:"authentication,omitempty"`
		AssertionMethod      []json.RawMessage `json:"assertionMethod,omitempty"`
		KeyAgreement         []json.RawMessage `json:"keyAgreement,omitempty"`
		CapabilityInvocation []json.RawMessage `json:"capabilityInvocation,omitempty"`
		CapabilityDelegation []json.RawMessage `json:"capabilityDelegation,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(d),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	var err error
	if d.Authentication, err = parseVerificationRefs(aux.Authentication); err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	if d.AssertionMethod, err = parseVerificationRefs(aux.AssertionMethod); err != nil {
		return fmt.Errorf("assertionMethod: %w", err)
	}
	if d.KeyAgreement, err = parseVerificationRefs(aux.KeyAgreement); err != nil {
		return fmt.Errorf("keyAgreement: %w", err)
	}
	if d.CapabilityInvocation, err = parseVerificationRefs(aux.CapabilityInvocation); err != nil {
		return fmt.Errorf("capabilityInvocation: %w", err)
	}
	if d.CapabilityDelegation, err = parseVerificationRefs(aux.CapabilityDelegation); err != nil {
		return fmt.Errorf("capabilityDelegation: %w", err)
	}

	return nil
}

// parseVerificationRefs parses a slice of raw JSON values into VerificationRefs.
// Each element is either a string (DID URL reference) or an embedded VerificationMethod object.
func parseVerificationRefs(raw []json.RawMessage) ([]VerificationRef, error) {
	refs := make([]VerificationRef, 0, len(raw))
	for _, r := range raw {
		trimmed := bytes.TrimSpace(r)
		if len(trimmed) == 0 {
			continue
		}
		if trimmed[0] == '"' {
			var ref string
			if err := json.Unmarshal(r, &ref); err != nil {
				return nil, err
			}
			refs = append(refs, ref)
		} else {
			var vm VerificationMethod
			if err := json.Unmarshal(r, &vm); err != nil {
				return nil, err
			}
			refs = append(refs, vm)
		}
	}
	return refs, nil
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

	present := 0
	if v.PublicKeyJwk != nil {
		present++
	}
	if v.PublicKeyMultibase != nil {
		present++
	}
	if v.PublicKeyBase58 != nil {
		present++
	}
	if present > 1 {
		return fmt.Errorf("publicKeyJwk, publicKeyMultibase and publicKeyBase58 are mutually exclusive")
	}

	if v.PublicKeyMultibase != nil {
		rawKey, err := ResolvePublicKeyFromMultibase(*v.PublicKeyMultibase)
		if err != nil {
			return fmt.Errorf("failed to decode publicKeyMultibase: %w", err)
		}
		key, err := jwk.Import(rawKey)
		if err != nil {
			return fmt.Errorf("failed to convert publicKeyMultibase to JWK: %w", err)
		}
		v.decodedMultibasePublicKey = &key
	}

	if v.PublicKeyBase58 != nil {
		decodedBytes, err := base58.Decode(*v.PublicKeyBase58)
		if err != nil {
			return fmt.Errorf("failed to decode publicKeyBase58: %w", err)
		}
		switch v.Type {
		case VerificationMethodType_Ed25519VerificationKey2018:
			key, err := jwk.Import(ed25519.PublicKey(decodedBytes))
			if err != nil {
				return fmt.Errorf("failed to convert publicKeyBase58 to JWK: %w", err)
			}
			v.decodedBase58PublicKey = &key
		case VerificationMethodType_JsonWebKey2020:
			key, err := jwk.ParseKey(decodedBytes)
			if err != nil {
				return fmt.Errorf("failed to parse publicKeyBase58 as JWK: %w", err)
			}
			v.decodedBase58PublicKey = &key
		default:
			return fmt.Errorf("unsupported verification method type for publicKeyBase58: %s", v.Type)
		}
	}

	return nil
}
