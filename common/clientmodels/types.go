package clientmodels

import (
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

const DefaultFallbackLanguage = "en"

// TranslatedString is a map from language code to translated text.
type TranslatedString map[string]string

// TrustedParty represents an issuer, verifier, or scheme manager.
type TrustedParty struct {
	Id string `json:"id"`
	// Display name for the party
	Name TranslatedString `json:"name"`
	// Url for the party (which can be different per language)
	Url *TranslatedString `json:"url"`
	// The image data for this party.
	Image *Image `json:"image,omitempty"`
	// The trust chain for this party (if any)
	Parent *TrustedParty `json:"parent"`
	// Whether this party is verified by the scheme manager
	Verified bool `json:"verified"`
}

type Image struct {
	// Base64-encoded image data
	Base64 string `json:"base64"`
	// The MIME type of the image (e.g. "image/png")
	MimeType *string `json:"mime_type,omitempty"`
}

// ImageFromFile reads an image file from disk and returns it as a base64-encoded Image.
// Returns nil if the path is empty or the file cannot be read.
func ImageFromFile(path string) *Image {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return &Image{Base64: base64.StdEncoding.EncodeToString(data)}
}

// AttributeType indicates the type of an attribute value.
type AttributeType string

const (
	AttributeType_String      AttributeType = "string"
	AttributeType_Bool        AttributeType = "boolean"
	AttributeType_Int         AttributeType = "integer"
	AttributeType_Image       AttributeType = "image"
	AttributeType_Base64Image AttributeType = "base64_image"
)

// AttributeValue holds a single scalar attribute value. Compound types (arrays,
// objects) are represented as multiple Attribute entries with nested claim paths
// instead.
type AttributeValue struct {
	Type AttributeType `json:"type"`

	Int         *int64  `json:"int,omitempty"`
	Bool        *bool   `json:"bool,omitempty"`
	String      *string `json:"string,omitempty"`
	ImagePath   *string `json:"image_path,omitempty"`
	Base64Image *string `json:"base64_image,omitempty"`
}

// NewAttributeValue converts a scalar Go value into an AttributeValue.
// Only handles scalar types (string, bool, int64, float64). Returns nil for nil
// input. Callers must flatten arrays and objects into separate Attribute entries.
func NewAttributeValue(val any) *AttributeValue {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		return &AttributeValue{Type: AttributeType_String, String: &v}
	case bool:
		return &AttributeValue{Type: AttributeType_Bool, Bool: &v}
	case int64:
		return &AttributeValue{Type: AttributeType_Int, Int: &v}
	case float64:
		i := int64(v)
		if v == float64(i) {
			return &AttributeValue{Type: AttributeType_Int, Int: &i}
		}
		s := fmt.Sprintf("%g", v)
		return &AttributeValue{Type: AttributeType_String, String: &s}
	default:
		s := fmt.Sprintf("%v", v)
		return &AttributeValue{Type: AttributeType_String, String: &s}
	}
}

// HasValue returns true if this AttributeValue carries an actual value (not just a type constraint).
func (v *AttributeValue) HasValue() bool {
	return v.Int != nil || v.Bool != nil || v.String != nil ||
		v.ImagePath != nil || v.Base64Image != nil
}

// Attribute represents a single claim within a credential.
type Attribute struct {
	// Canonical identifier: the full claim path as an array of strings and integers.
	// Examples:
	//   ["email"]                    — flat IRMA attribute
	//   ["address", "street"]        — nested SD-JWT claim
	//   ["courses", 1]              — specific array element
	//   ["departments", 0, "name"]  — nested object inside array
	//
	// The UI sends this path back verbatim in SelectedCredential.AttributePaths
	// when the user grants disclosure permission.
	ClaimPath []any `json:"claim_path"`

	// Human-readable name for this attribute, localized.
	// Nil for array item attributes where the parent's name serves as the label.
	DisplayName *TranslatedString `json:"display_name,omitempty"`

	// Optional longer description for this attribute, localized.
	Description *TranslatedString `json:"description,omitempty"`

	// The actual value of this attribute as provided by the issuer.
	// Nil for section header attributes and unfilled requested attributes.
	Value *AttributeValue `json:"value,omitempty"`

	// The value that a verifier requested for this attribute (if any).
	RequestedValue *AttributeValue `json:"requested_value,omitempty"`
}

// ClaimPathKey produces a deterministic string key from a claim path for use
// in maps. Go slices can't be map keys, so this serializes the path.
//
// Each element is type-prefixed and delimited so different paths can't
// collide via formatting accidents (e.g. ["a b"] vs ["a", "b"]). Whole-value
// float64s — the form JSON unmarshaling produces — are coerced to integer
// form so a JSON-decoded path matches a Go-literal int path. Unknown element
// types fall back to a generic format so callers always get a string.
func ClaimPathKey(path []any) string {
	var sb strings.Builder
	for _, elem := range path {
		sb.WriteByte('|')
		switch v := elem.(type) {
		case nil:
			sb.WriteString("null")
		case string:
			sb.WriteByte('s')
			sb.WriteString(v)
		case float64:
			if !math.IsInf(v, 0) && !math.IsNaN(v) && v == math.Trunc(v) {
				sb.WriteByte('i')
				sb.WriteString(strconv.FormatFloat(v, 'f', -1, 64))
			} else {
				sb.WriteByte('f')
				sb.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
			}
		case int:
			sb.WriteByte('i')
			sb.WriteString(strconv.Itoa(v))
		case int64:
			sb.WriteByte('i')
			sb.WriteString(strconv.FormatInt(v, 10))
		default:
			sb.WriteByte('?')
			fmt.Fprintf(&sb, "%v", v)
		}
	}
	return sb.String()
}

// Credential represents a full credential with all its metadata and attribute values.
type Credential struct {
	// The id for this credential. For IRMA/idemix credentials this would look like
	// "pbdf.sidn-pbdf.email", for EUDI credentials this is the VCT URL.
	CredentialId string `json:"credential_id"`
	// Hash over all attribute values and the credential id.
	Hash string `json:"hash"`
	// Base64-encoded image for this credential.
	Image *Image `json:"image,omitempty"`
	// The display name for this credential, localized.
	Name TranslatedString `json:"name"`
	// All information about the credential issuer.
	Issuer TrustedParty `json:"issuer"`
	// The IDs for all instances of this credential in all different formats.
	CredentialInstanceIds map[CredentialFormat]string `json:"credential_instance_ids"`
	// The number of credential instances left per format (batched issuance).
	BatchInstanceCountsRemaining map[CredentialFormat]*uint `json:"batch_instance_counts_remaining"`
	// All the attributes and their values in this credential.
	// Ordered by the source metadata (IRMA scheme or EUDI issuer metadata).
	// Nested objects and arrays are flattened with full claim paths.
	Attributes []Attribute `json:"attributes"`
	// The date and time (unix format) at which this credential was issued.
	IssuanceDate *int64 `json:"issuance_date"`
	// The date and time (unix format) when this credential expires (0 if no expiry).
	ExpiryDate *int64 `json:"expiry_date"`
	// Whether or not this credential has been revoked.
	Revoked bool `json:"revoked"`
	// Whether or not revocation is supported for this credential.
	RevocationSupported bool `json:"revocation_supported"`
	// URL at which this credential can be issued (if any).
	IssueURL *TranslatedString `json:"issue_url"`
}

// CredentialToLogCredential converts a Credential to a LogCredential, extracting formats
// from CredentialInstanceIds (falling back to BatchInstanceCountsRemaining).
func CredentialToLogCredential(c *Credential) LogCredential {
	formats := make([]CredentialFormat, 0, len(c.CredentialInstanceIds))
	for f := range c.CredentialInstanceIds {
		formats = append(formats, f)
	}
	if len(formats) == 0 {
		for f := range c.BatchInstanceCountsRemaining {
			formats = append(formats, f)
		}
	}
	return LogCredential{
		CredentialId:        c.CredentialId,
		Formats:             formats,
		Image:               c.Image,
		Name:                c.Name,
		Issuer:              c.Issuer,
		Attributes:          c.Attributes,
		IssuanceDate:        c.IssuanceDate,
		ExpiryDate:          c.ExpiryDate,
		Revoked:             c.Revoked,
		RevocationSupported: c.RevocationSupported,
		IssueURL:            c.IssueURL,
	}
}

// CredentialDescriptor describes a credential type without any instance-specific values.
type CredentialDescriptor struct {
	CredentialId string            `json:"credential_id"`
	Name         TranslatedString  `json:"name"`
	Issuer       TrustedParty      `json:"issuer"`
	Category     *TranslatedString `json:"category,omitempty"`
	Image        *Image            `json:"image,omitempty"`
	Attributes   []Attribute       `json:"attributes"`
	IssueURL     *TranslatedString `json:"issue_url,omitempty"`

	// The credential type's FAQ texts from the scheme, so frontends can show
	// the explanation content in flows that only receive a descriptor (e.g.
	// obtaining a missing credential during disclosure). Nil for credentials
	// without a scheme entry, such as generic EUDI credentials.
	Faq *Faq `json:"faq,omitempty"`
}

// CredentialStoreItem is a credential descriptor with FAQ information.
type CredentialStoreItem struct {
	Credential CredentialDescriptor `json:"credential"`
	Faq        Faq                  `json:"faq"`
}

// Faq contains FAQ information for a credential type.
type Faq struct {
	Intro   *TranslatedString `json:"intro"`
	Purpose *TranslatedString `json:"purpose"`
	Content *TranslatedString `json:"content"`
	HowTo   *TranslatedString `json:"how_to"`
}

// SelectableCredentialInstance represents a single credential instance that
// the user can select for disclosure.
type SelectableCredentialInstance struct {
	// The id for this credential. For IRMA/idemix credentials this would look like
	// "pbdf.sidn-pbdf.email", for EUDI credentials this is the VCT URL.
	CredentialId string `json:"credential_id"`
	// Hash over all attribute values and the credential id.
	Hash string `json:"hash"`
	// Base64-encoded image for this credential.
	Image *Image `json:"image,omitempty"`
	// The display name for this credential, localized.
	Name TranslatedString `json:"name"`
	// All information about the credential issuer.
	Issuer TrustedParty `json:"issuer"`
	// The credential format for this instance.
	Format CredentialFormat `json:"format"`
	// The number of credential instances left for this credential instance.
	BatchInstanceCountRemaining *uint `json:"batch_instance_count_remaining"`
	// The attributes selectable for disclosure, ordered by source metadata.
	// Requested SD claims appear first (in metadata order), non-SD claims after.
	Attributes []Attribute `json:"attributes"`

	// TODO: IssuanceData + ExpiryDate are mandatory for IRMA credentials, but optional for EUDI credentials.
	// We need to fix this, also in the frontend

	// The date and time (unix format) at which this credential was issued.
	IssuanceDate *int64 `json:"issuance_date"`
	// The date and time (unix format) when this credential expires.
	ExpiryDate *int64 `json:"expiry_date"`
	// Whether or not this credential has been revoked.
	Revoked bool `json:"revoked"`
	// Whether or not revocation is supported for this credential.
	RevocationSupported bool `json:"revocation_supported"`
	// URL at which this credential can be issued (if any).
	IssueURL *TranslatedString `json:"issue_url"`
}

// NewTranslatedString returns a TranslatedString containing the specified string for each supported language,
// or nil when attr is nil.
func NewTranslatedString(value *string) TranslatedString {
	if value == nil {
		return nil
	}
	return map[string]string{
		"":   *value, // raw value
		"en": *value,
		"nl": *value,
	}
}
