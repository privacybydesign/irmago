package irma

import (
	"encoding/xml"
	"fmt"
	"path/filepath"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/internal/common"
)

// This file contains data types for scheme managers, issuers, credential types
// matching the XML files in irma_configuration.

// SchemeManager describes a scheme manager.
type SchemeManager struct {
	ID                string           `xml:"Id"`
	Name              TranslatedString `xml:"Name"`
	URL               string           `xml:"Url"`
	Contact           string           `xml:"contact"`
	Demo              bool             `xml:"Demo"` // Decides whether to download private keys
	Description       TranslatedString
	MinimumAppVersion SchemeAppVersion
	KeyshareServer    string
	KeyshareWebsite   string
	KeyshareAttribute string
	TimestampServer   string
	XMLVersion        int      `xml:"version,attr"`
	XMLName           xml.Name `xml:"SchemeManager"`

	Status    SchemeManagerStatus `xml:"-"`
	Timestamp Timestamp

	storagepath string
	index       SchemeManagerIndex
}

type SchemeAppVersion struct {
	Android int `xml:"Android"`
	IOS     int `xml:"iOS"`
}

// Issuer describes an issuer.
type Issuer struct {
	ID              string           `xml:"ID"`
	Name            TranslatedString `xml:"Name"`
	ShortName       TranslatedString `xml:"ShortName"`
	SchemeManagerID string           `xml:"SchemeManager"`
	ContactAddress  string
	ContactEMail    string
	DeprecatedSince Timestamp
	XMLVersion      int `xml:"version,attr"`
}

// CredentialType is a description of a credential type, specifying (a.o.) its name, issuer, and attributes.
type CredentialType struct {
	ID                    string           `xml:"CredentialID"`
	Name                  TranslatedString `xml:"Name"`
	ShortName             TranslatedString `xml:"ShortName"`
	IssuerID              string           `xml:"IssuerID"`
	SchemeManagerID       string           `xml:"SchemeManager"`
	IsSingleton           bool             `xml:"ShouldBeSingleton"`
	DisallowDelete        bool             `xml:"DisallowDelete"`
	Description           TranslatedString
	AttributeTypes        []*AttributeType `xml:"Attributes>Attribute" json:"-"`
	RevocationServers     []string         `xml:"RevocationServers>RevocationServer"`
	RevocationUpdateCount uint64
	RevocationUpdateSpeed uint64
	RevocationIndex       int      `xml:"-"`
	XMLVersion            int      `xml:"version,attr"`
	XMLName               xml.Name `xml:"IssueSpecification"`

	IssueURL     TranslatedString `xml:"IssueURL"`
	IsULIssueURL bool             `xml:"IsULIssueURL"`

	DeprecatedSince Timestamp

	ForegroundColor         string
	BackgroundGradientStart string
	BackgroundGradientEnd   string

	IsInCredentialStore bool
	Category            TranslatedString
	FAQIntro            TranslatedString
	FAQPurpose          TranslatedString
	FAQContent          TranslatedString
	FAQHowto            TranslatedString
}

// AttributeType is a description of an attribute within a credential type.
type AttributeType struct {
	ID          string `xml:"id,attr"`
	Optional    string `xml:"optional,attr"  json:",omitempty"`
	Name        TranslatedString
	Description TranslatedString

	Index        int    `xml:"-"`
	DisplayIndex *int   `xml:"displayIndex,attr" json:",omitempty"`
	DisplayHint  string `xml:"displayHint,attr"  json:",omitempty"`

	RevocationAttribute bool `xml:"revocation,attr" json:",omitempty"`

	// Taken from containing CredentialType
	CredentialTypeID string `xml:"-"`
	IssuerID         string `xml:"-"`
	SchemeManagerID  string `xml:"-"`
}

// RequestorScheme describes verified requestors
type RequestorScheme struct {
	ID        RequestorSchemeIdentifier `json:"id"`
	URL       string                    `json:"url"`
	Status    SchemeManagerStatus       `json:"-"`
	Timestamp Timestamp                 `json:"-"`

	storagepath string
	index       SchemeManagerIndex
	requestors  []*RequestorInfo
}

// RequestorInfo describes a single verified requestor
type RequestorInfo struct {
	Scheme     RequestorSchemeIdentifier `json:"scheme"`
	Name       TranslatedString          `json:"name"`
	Industry   *TranslatedString         `json:"industry"`
	Hostnames  []string                  `json:"hostnames"`
	Logo       *string                   `json:"logo"`
	ValidUntil *Timestamp                `json:"valid_until"`
}

// RequestorChunk is a number of verified requestors stored together. The RequestorScheme can consist of multiple such chunks
type RequestorChunk []*RequestorInfo

// NewRequestorInfo returns a Requestor with just the given hostname
func NewRequestorInfo(hostname string) *RequestorInfo {
	return &RequestorInfo{
		Name:      NewTranslatedString(&hostname),
		Hostnames: []string{hostname},
	}
}

func (ad AttributeType) GetAttributeTypeIdentifier() AttributeTypeIdentifier {
	return NewAttributeTypeIdentifier(fmt.Sprintf("%s.%s.%s.%s", ad.SchemeManagerID, ad.IssuerID, ad.CredentialTypeID, ad.ID))
}

func (ad AttributeType) IsOptional() bool {
	return ad.Optional == "true"
}

func (ct *CredentialType) RevocationSupported() bool {
	return len(ct.RevocationServers) > 0
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
	scheme := conf.SchemeManagers[ct.SchemeManagerIdentifier()]
	path := filepath.Join(scheme.path(), ct.IssuerID, "Issues", ct.ID, "logo.png")
	exists, err := common.PathExists(path)
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
