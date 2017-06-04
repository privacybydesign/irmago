package irmago

// Contains identifiers for issuers, credential types, and attributes
// Thin wrapper about their string equivalents (e.g., "irma-demo.RU")
// in case of the "RU" issuer in the "irma-demo" domain
// Not sure if these are at all necessary. Avoid if possible, TODO: remove these?

import "strings"

// Base object for identifiers
type objectIdentifier struct {
	string `json:"identifier"`
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
	return strings.Split(o.string, ".")
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
		ci.issuer = NewIssuerIdentifier(strings.Join(ci.split()[:1], "."))
	}
	return ci.issuer
}

// CredentialName returns the name of the current credential type.
func (ci *CredentialTypeIdentifier) CredentialName() string {
	return ci.split()[2]
}

// SchemeManagerName ...
func (ai *AttributeTypeIdentifier) SchemeManagerName() string {
	return ai.split()[0]
}

// IssuerName ...
func (ai *AttributeTypeIdentifier) IssuerName() string {
	return ai.split()[1]
}

// CredentialName ...
func (ai *AttributeTypeIdentifier) CredentialName() string {
	return ai.split()[2]
}

// AttributeName ..
func (ai *AttributeTypeIdentifier) AttributeName() string {
	return ai.split()[3]
}

// CredentialTypeIdentifier ...
func (ai *AttributeTypeIdentifier) CredentialTypeIdentifier() *CredentialTypeIdentifier {
	if ai.cred == nil {
		ai.cred = NewCredentialTypeIdentifier(strings.Join(ai.split()[:2], "."))
	}
	return ai.cred
}

// IssuerIdentifier ...
func (ai *AttributeTypeIdentifier) IssuerIdentifier() *IssuerIdentifier {
	return ai.CredentialTypeIdentifier().IssuerIdentifier()
}
