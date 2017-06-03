package irmago

import "strings"

// Base object for identifiers
type objectIdentifier struct {
	string `json:"identifier"`
	parts  []string
}

// IssuerIdentifier identifies an issuer.
type IssuerIdentifier struct {
	objectIdentifier
}

// CredentialTypeIdentifier identifies a credential type
type CredentialTypeIdentifier struct {
	objectIdentifier
	issuer *IssuerIdentifier
}

// AttributeTypeIdentifier identifies an attribute within a credential type.
type AttributeTypeIdentifier struct {
	objectIdentifier
	cred *CredentialTypeIdentifier
}

// NewIssuerIdentifier returns a new IssuerIdentifier
func NewIssuerIdentifier(identifier string) *IssuerIdentifier {
	return &IssuerIdentifier{
		objectIdentifier: objectIdentifier{string: identifier},
	}
}

// NewCredentialTypeIdentifier returns a new CredentialTypeIdentifier
func NewCredentialTypeIdentifier(identifier string) *CredentialTypeIdentifier {
	return &CredentialTypeIdentifier{
		objectIdentifier: objectIdentifier{string: identifier},
	}
}

// NewAttributeTypeIdentifier returns a new AttributeTypeIdentifier
func NewAttributeTypeIdentifier(identifier string) *AttributeTypeIdentifier {
	return &AttributeTypeIdentifier{
		objectIdentifier: objectIdentifier{string: identifier},
	}
}

func (o *objectIdentifier) split() []string {
	if o.parts == nil {
		o.parts = strings.Split(o.string, ".")
	}

	return o.parts
}

// SchemeManagerName returns the name of the scheme maanger of the current credential type.
func (ci *CredentialTypeIdentifier) SchemeManagerName() string {
	return ci.split()[0]
}

// IssuerName returns the issuer name of the current credential type.
func (ci *CredentialTypeIdentifier) IssuerName() string {
	return ci.split()[1]
}

// IssuerIdentifier returns the issuer identifier of the current credential type.
func (ci *CredentialTypeIdentifier) IssuerIdentifier() *IssuerIdentifier {
	if ci.issuer == nil {
		ci.issuer = &IssuerIdentifier{
			objectIdentifier: objectIdentifier{string: ci.SchemeManagerName() + "." + ci.IssuerName()},
		}
	}

	return ci.issuer
}

// CredentialName returns the name of the current credential type.
func (ci *CredentialTypeIdentifier) CredentialName() string {
	return ci.split()[2]
}
