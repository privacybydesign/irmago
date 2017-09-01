package irmago

import (
	"encoding/xml"

	"errors"

	"github.com/mhe/gabi"
)

// SchemeManager describes a scheme manager.
type SchemeManager struct {
	ID                string           `xml:"Id"`
	Name              TranslatedString `xml:"Name"`
	URL               string           `xml:"Contact"`
	Description       TranslatedString
	KeyshareServer    string
	KeyshareWebsite   string
	KeyshareAttribute string
	XMLVersion        int      `xml:"version,attr"`
	XMLName           xml.Name `xml:"SchemeManager"`
}

// Issuer describes an issuer.
type Issuer struct {
	ID              string           `xml:"ID"`
	Name            TranslatedString `xml:"Name"`
	ShortName       TranslatedString `xml:"ShortName"`
	SchemeManagerID string           `xml:"SchemeManager"`
	ContactAddress  string
	ContactEMail    string
	URL             string `xml:"baseURL"`
	XMLVersion      int    `xml:"version,attr"`
}

// CredentialType is a description of a credential type, specifying (a.o.) its name, issuer, and attributes.
type CredentialType struct {
	ID              string           `xml:"CredentialID"`
	Name            TranslatedString `xml:"Name"`
	ShortName       TranslatedString `xml:"ShortName"`
	IssuerID        string           `xml:"IssuerID"`
	SchemeManagerID string           `xml:"SchemeManager"`
	IsSingleton     bool             `xml:"ShouldBeSingleton"`
	Description     TranslatedString
	Attributes      []AttributeDescription `xml:"Attributes>Attribute"`
	XMLVersion      int                    `xml:"version,attr"`
	XMLName         xml.Name               `xml:"IssueSpecification"`
}

// ContainsAttribute tests whether the specified attribute is contained in this
// credentialtype.
func (ct *CredentialType) ContainsAttribute(ai AttributeTypeIdentifier) bool {
	if ai.CredentialTypeIdentifier().String() != ct.Identifier().String() {
		return false
	}
	for _, desc := range ct.Attributes {
		if desc.ID == ai.Name() {
			return true
		}
	}
	return false
}

// AttributeDescription is a description of an attribute within a credential type.
type AttributeDescription struct {
	ID          string `xml:"id,attr"`
	Name        TranslatedString
	Description TranslatedString
}

// IndexOf returns the index of the specified attribute if present,
// or an error (and -1) if not present.
func (ct CredentialType) IndexOf(ai AttributeTypeIdentifier) (int, error) {
	if ai.CredentialTypeIdentifier() != ct.Identifier() {
		return -1, errors.New("Wrong credential type")
	}
	for i, description := range ct.Attributes {
		if description.ID == ai.Name() {
			return i, nil
		}
	}
	return -1, errors.New("Attribute identifier not found")
}

// TranslatedString represents an XML tag containing a string translated to multiple languages.
// For example: <Foo id="bla"><en>Hello world</en><nl>Hallo wereld</nl></Foo>
type TranslatedString struct {
	Translations []struct {
		XMLName xml.Name
		Text    string `xml:",chardata"`
	} `xml:",any"`
}

// Translation returns the specified translation.
func (ts *TranslatedString) Translation(lang string) string {
	for _, translation := range ts.Translations {
		if translation.XMLName.Local == lang {
			return translation.Text
		}
	}
	return ""
}

// Identifier returns the identifier of the specified credential type.
func (ct *CredentialType) Identifier() CredentialTypeIdentifier {
	return NewCredentialTypeIdentifier(ct.SchemeManagerID + "." + ct.IssuerID + "." + ct.ID)
}

// IssuerIdentifier returns the issuer identifier of the specified credential type.
func (ct *CredentialType) IssuerIdentifier() IssuerIdentifier {
	return NewIssuerIdentifier(ct.SchemeManagerID + "." + ct.IssuerID)
}

// Identifier returns the identifier of the specified issuer description.
func (id *Issuer) Identifier() IssuerIdentifier {
	return NewIssuerIdentifier(id.SchemeManagerID + "." + id.ID)
}

// Identifier returns the identifier of the specified scheme manager.
func (sm *SchemeManager) Identifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(sm.ID)
}

// CurrentPublicKey returns the latest known public key of the issuer identified by this instance.
func (id *Issuer) CurrentPublicKey() *gabi.PublicKey {
	keys := MetaStore.PublicKeys[id.Identifier()]
	if keys == nil || len(keys) == 0 {
		return nil
	}
	return keys[len(keys)-1]
}

// PublicKey returns the specified public key of the issuer identified by this instance.
func (id *Issuer) PublicKey(index int) *gabi.PublicKey {
	keys := MetaStore.PublicKeys[id.Identifier()]
	if keys == nil || index >= len(keys) {
		return nil
	}
	return keys[index]
}
