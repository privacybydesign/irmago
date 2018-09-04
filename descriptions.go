package irma

import (
	"encoding/xml"
	"fmt"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/internal/fs"
)

// This file contains data types for scheme managers, issuers, credential types
// matching the XML files in irma_configuration.

// SchemeManager describes a scheme manager.
type SchemeManager struct {
	ID                string           `xml:"Id"`
	Name              TranslatedString `xml:"Name"`
	URL               string           `xml:"Url"`
	Contact           string           `xml:"contact"`
	Description       TranslatedString
	KeyshareServer    string
	KeyshareWebsite   string
	KeyshareAttribute string
	XMLVersion        int      `xml:"version,attr"`
	XMLName           xml.Name `xml:"SchemeManager"`

	Status SchemeManagerStatus `xml:"-"`
	Valid  bool                `xml:"-"` // true iff Status == SchemeManagerStatusValid

	Timestamp Timestamp

	index SchemeManagerIndex
}

// Issuer describes an issuer.
type Issuer struct {
	ID              string           `xml:"ID"`
	Name            TranslatedString `xml:"Name"`
	ShortName       TranslatedString `xml:"ShortName"`
	SchemeManagerID string           `xml:"SchemeManager"`
	ContactAddress  string
	ContactEMail    string
	XMLVersion      int `xml:"version,attr"`

	Valid bool `xml:"-"`
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
	AttributeTypes  []*AttributeType `xml:"Attributes>Attribute" json:"-"`
	XMLVersion      int              `xml:"version,attr"`
	XMLName         xml.Name         `xml:"IssueSpecification"`

	Valid bool `xml:"-"`
}

// AttributeType is a description of an attribute within a credential type.
type AttributeType struct {
	ID          string `xml:"id,attr"`
	Optional    string `xml:"optional,attr"  json:",omitempty"`
	Name        TranslatedString
	Description TranslatedString

	Index        int  `xml:"-"`
	DisplayIndex *int `xml:"displayIndex,attr" json:",omitempty"`

	// Taken from containing CredentialType
	CredentialTypeID string `xml:"-"`
	IssuerID         string `xml:"-"`
	SchemeManagerID  string `xml:"-"`
}

func (ad AttributeType) GetAttributeTypeIdentifier() AttributeTypeIdentifier {
	return NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s.%s.%s", ad.SchemeManagerID, ad.IssuerID, ad.CredentialTypeID, ad.ID))
}

func (ad AttributeType) IsOptional() bool {
	return ad.Optional == "true"
}

// ContainsAttribute tests whether the specified attribute is contained in this
// credentialtype.
func (ct *CredentialType) ContainsAttribute(ai AttributeTypeIdentifier) bool {
	if ai.CredentialTypeIdentifier().String() != ct.Identifier().String() {
		return false
	}
	for _, desc := range ct.AttributeTypes {
		if desc.ID == ai.Name() {
			return true
		}
	}
	return false
}

// IndexOf returns the index of the specified attribute if present,
// or an error (and -1) if not present.
func (ct CredentialType) IndexOf(ai AttributeTypeIdentifier) (int, error) {
	if ai.CredentialTypeIdentifier() != ct.Identifier() {
		return -1, errors.New("Wrong credential type")
	}
	for i, description := range ct.AttributeTypes {
		if description.ID == ai.Name() {
			return i, nil
		}
	}
	return -1, errors.New("Attribute identifier not found")
}

func (ct CredentialType) AttributeType(ai AttributeTypeIdentifier) *AttributeType {
	i, _ := ct.IndexOf(ai)
	if i == -1 {
		return nil
	}
	return ct.AttributeTypes[i]
}

// TranslatedString is a map of translated strings.
type TranslatedString map[string]string

type xmlTranslation struct {
	XMLName xml.Name
	Text    string `xml:",chardata"`
}

type xmlTranslatedString struct {
	Translations []xmlTranslation `xml:",any"`
}

// MarshalXML implements xml.Marshaler.
func (ts *TranslatedString) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	temp := &xmlTranslatedString{}
	for lang, text := range *ts {
		temp.Translations = append(temp.Translations,
			xmlTranslation{XMLName: xml.Name{Local: lang}, Text: text},
		)
	}
	return e.EncodeElement(temp, start)
}

// UnmarshalXML unmarshals an XML tag containing a string translated to multiple languages,
// for example: <Foo><en>Hello world</en><nl>Hallo wereld</nl></Foo>
// into a TranslatedString: { "en": "Hello world" , "nl": "Hallo wereld" }
func (ts *TranslatedString) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if map[string]string(*ts) == nil {
		*ts = TranslatedString(make(map[string]string))
	}
	temp := &xmlTranslatedString{}
	if err := d.DecodeElement(temp, &start); err != nil {
		return err
	}
	for _, translation := range temp.Translations {
		(*ts)[translation.XMLName.Local] = translation.Text
	}
	return nil
}

// Identifier returns the identifier of the specified credential type.
func (ct *CredentialType) Identifier() CredentialTypeIdentifier {
	return NewCredentialTypeIdentifier(ct.SchemeManagerID + "." + ct.IssuerID + "." + ct.ID)
}

// IssuerIdentifier returns the issuer identifier of the specified credential type.
func (ct *CredentialType) IssuerIdentifier() IssuerIdentifier {
	return NewIssuerIdentifier(ct.SchemeManagerID + "." + ct.IssuerID)
}

func (ct *CredentialType) SchemeManagerIdentifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(ct.SchemeManagerID)
}

func (ct *CredentialType) Logo(conf *Configuration) string {
	path := fmt.Sprintf("%s/%s/%s/Issues/%s/logo.png", conf.Path, ct.SchemeManagerID, ct.IssuerID, ct.ID)
	exists, err := fs.PathExists(path)
	if err != nil || !exists {
		return ""
	}
	return path
}

// Identifier returns the identifier of the specified issuer description.
func (id *Issuer) Identifier() IssuerIdentifier {
	return NewIssuerIdentifier(id.SchemeManagerID + "." + id.ID)
}

func (id *Issuer) SchemeManagerIdentifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(id.SchemeManagerID)
}

func NewSchemeManager(name string) *SchemeManager {
	return &SchemeManager{ID: name, Status: SchemeManagerStatusUnprocessed, Valid: false}
}

// Identifier returns the identifier of the specified scheme manager.
func (sm *SchemeManager) Identifier() SchemeManagerIdentifier {
	return NewSchemeManagerIdentifier(sm.ID)
}

// Distributed indicates if this scheme manager uses a keyshare server.
func (sm *SchemeManager) Distributed() bool {
	return len(sm.KeyshareServer) > 0
}
