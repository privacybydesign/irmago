package irmago

import (
	"encoding/json"
	"strings"
)

type metaObjectIdentifier string

// SchemeManagerIdentifier identifies a scheme manager. Equal to its ID. For example "irma-demo".
type SchemeManagerIdentifier struct {
	metaObjectIdentifier
}

// IssuerIdentifier identifies an issuer. For example "irma-demo.RU".
type IssuerIdentifier struct {
	metaObjectIdentifier
}

// CredentialTypeIdentifier identifies a credentialtype. For example "irma-demo.RU.studentCard".
type CredentialTypeIdentifier struct {
	metaObjectIdentifier
}

// AttributeTypeIdentifier identifies an attribute. For example "irma-demo.RU.studentCard.studentID".
type AttributeTypeIdentifier struct {
	metaObjectIdentifier
}

// CredentialIdentifier identifies a credential instance.
type CredentialIdentifier struct {
	Type  CredentialTypeIdentifier
	Index int
	Count int
}

// AttributeIdentifier identifies an attribute instance.
type AttributeIdentifier struct {
	Type  AttributeTypeIdentifier
	Index int
	Count int
}

// Parent returns the parent object of this identifier.
func (oi metaObjectIdentifier) Parent() string {
	str := string(oi)
	return str[:strings.LastIndex(str, ".")]
}

// Name returns the last part of this identifier.
func (oi metaObjectIdentifier) Name() string {
	str := string(oi)
	return str[strings.LastIndex(str, ".")+1:]
}

// String returns this identifier as a string.
func (oi metaObjectIdentifier) String() string {
	return string(oi)
}

// NewSchemeManagerIdentifier converts the specified identifier to a SchemeManagerIdentifier.
func NewSchemeManagerIdentifier(id string) SchemeManagerIdentifier {
	return SchemeManagerIdentifier{metaObjectIdentifier(id)}
}

// NewIssuerIdentifier converts the specified identifier to a IssuerIdentifier.
func NewIssuerIdentifier(id string) IssuerIdentifier {
	return IssuerIdentifier{metaObjectIdentifier(id)}
}

// NewCredentialTypeIdentifier converts the specified identifier to a CredentialTypeIdentifier.
func NewCredentialTypeIdentifier(id string) CredentialTypeIdentifier {
	return CredentialTypeIdentifier{metaObjectIdentifier(id)}
}

// NewAttributeTypeIdentifier converts the specified identifier to a AttributeTypeIdentifier.
func NewAttributeTypeIdentifier(id string) AttributeTypeIdentifier {
	return AttributeTypeIdentifier{metaObjectIdentifier(id)}
}

// SchemeManagerIdentifier returns the scheme manager identifer of the issuer.
func (id IssuerIdentifier) SchemeManagerIdentifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(id.Parent())
}

// IssuerIdentifier returns the IssuerIdentifier of the credential identifier.
func (id CredentialTypeIdentifier) IssuerIdentifier() IssuerIdentifier {
	return NewIssuerIdentifier(id.Parent())
}

// CredentialTypeIdentifier returns the CredentialTypeIdentifier of the attribute identifier.
func (id AttributeTypeIdentifier) CredentialTypeIdentifier() CredentialTypeIdentifier {
	return NewCredentialTypeIdentifier(id.Parent())
}

// IsCredential returns true if this attribute refers to its containing credential
// (i.e., it consists of only 3 parts).
func (id AttributeTypeIdentifier) IsCredential() bool {
	return strings.Count(id.String(), ".") == 2
}

// CredentialIdentifier returns the credential identifier of this attribute.
func (ai *AttributeIdentifier) CredentialIdentifier() CredentialIdentifier {
	return CredentialIdentifier{Type: ai.Type.CredentialTypeIdentifier(), Index: ai.Index, Count: ai.Count}
}

// MarshalJSON marshals this instance to JSON as a string.
func (id AttributeTypeIdentifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

// MarshalJSON marshals this instance to JSON as a string.
func (id CredentialTypeIdentifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

// UnmarshalJSON unmarshals this instance from JSON.
func (id *AttributeTypeIdentifier) UnmarshalJSON(b []byte) error {
	var val string
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}
	id.metaObjectIdentifier = metaObjectIdentifier(val)
	return nil
}

// UnmarshalJSON unmarshals this instance from JSON.
func (id *CredentialTypeIdentifier) UnmarshalJSON(b []byte) error {
	var val string
	err := json.Unmarshal(b, &val)
	if err != nil {
		return err
	}
	id.metaObjectIdentifier = metaObjectIdentifier(val)
	return nil
}

// TODO this also for the other identifiers
func (id *IssuerIdentifier) UnmarshalText(text []byte) error {
	*id = NewIssuerIdentifier(string(text))
	return nil
}
