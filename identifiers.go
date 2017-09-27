package irmago

import "strings"

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

// MarshalText implements encoding.TextMarshaler.
func (id SchemeManagerIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *SchemeManagerIdentifier) UnmarshalText(text []byte) error {
	*id = NewSchemeManagerIdentifier(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (id IssuerIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *IssuerIdentifier) UnmarshalText(text []byte) error {
	*id = NewIssuerIdentifier(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (id CredentialTypeIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *CredentialTypeIdentifier) UnmarshalText(text []byte) error {
	*id = NewCredentialTypeIdentifier(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (id AttributeTypeIdentifier) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (id *AttributeTypeIdentifier) UnmarshalText(text []byte) error {
	*id = NewAttributeTypeIdentifier(string(text))
	return nil
}
