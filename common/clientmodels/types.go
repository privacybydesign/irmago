package clientmodels

import "fmt"

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
	// Absolute path to the image for this party stored on disk
	ImagePath *string `json:"image_path"`
	// The trust chain for this party (if any)
	Parent *TrustedParty `json:"parent"`
	// Whether this party is verified by the scheme manager
	Verified bool `json:"verified"`
}

// AttributeType indicates the type of an attribute value.
type AttributeType string

const (
	AttributeType_Object      AttributeType = "object"
	AttributeType_Array       AttributeType = "array"
	AttributeType_String      AttributeType = "string"
	AttributeType_Bool        AttributeType = "boolean"
	AttributeType_Int         AttributeType = "integer"
	AttributeType_Image       AttributeType = "image"
	AttributeType_Base64Image AttributeType = "base64_image"
)

// AttributeValue holds a typed attribute value.
type AttributeValue struct {
	Type AttributeType `json:"type"`

	Int         *int64           `json:"int,omitempty"`
	Bool        *bool            `json:"bool,omitempty"`
	String      *string          `json:"string,omitempty"`
	Array       []AttributeValue `json:"array,omitempty"`
	Object      []Attribute      `json:"object,omitempty"`
	ImagePath   *string          `json:"image_path,omitempty"`
	Base64Image *string          `json:"base64_image,omitempty"`
}

// NewAttributeValue converts a Go value (typically from JSON unmarshalling) into
// an AttributeValue. Supported types: string, bool, float64, int64, []any,
// map[string]any. Returns nil for nil input.
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
	case []any:
		arr := make([]AttributeValue, len(v))
		for i, elem := range v {
			if av := NewAttributeValue(elem); av != nil {
				arr[i] = *av
			}
		}
		return &AttributeValue{Type: AttributeType_Array, Array: arr}
	case map[string]any:
		var obj []Attribute
		for key, elem := range v {
			obj = append(obj, Attribute{
				Id:    key,
				Value: NewAttributeValue(elem),
			})
		}
		return &AttributeValue{Type: AttributeType_Object, Object: obj}
	default:
		s := fmt.Sprintf("%v", v)
		return &AttributeValue{Type: AttributeType_String, String: &s}
	}
}

// HasValue returns true if this AttributeValue carries an actual value (not just a type constraint).
func (v *AttributeValue) HasValue() bool {
	return v.Int != nil || v.Bool != nil || v.String != nil ||
		len(v.Array) > 0 || len(v.Object) > 0 || v.ImagePath != nil || v.Base64Image != nil
}

// Attribute represents a single credential attribute with display metadata.
type Attribute struct {
	// Id for this attribute (only the last part in case of irma/idemix)
	Id string `json:"id"`
	// The name for this attribute as displayed to the end user
	DisplayName TranslatedString `json:"display_name"`
	// The description for this attribute if any
	Description *TranslatedString `json:"description,omitempty"`
	// The value that this attribute has as provided by the issuer (absent when it's just an attribute description)
	Value *AttributeValue `json:"value,omitempty"`
	// The value that was requested by a verifier (if any)
	RequestedValue *AttributeValue `json:"requested_value,omitempty"`
}

// Credential represents a full credential with all its metadata and attribute values.
type Credential struct {
	// The id for this credential. For irma/idemix credentials this would look like
	// `pbdf.sidn-pbdf.email`, for EUDI credentials this would be in the form of `https://example.credential.com`
	CredentialId string `json:"credential_id"`
	// Hash over all attribute values and the credential id.
	Hash string `json:"hash"`
	// Absolute path to the image for this credential stored on disk
	ImagePath *string `json:"image_path"`
	// The display name for this credential
	Name TranslatedString `json:"name"`
	// All information about the credential issuer
	Issuer TrustedParty `json:"issuer"`
	// The IDs for all instances of this credential in all different formats it's available in.
	CredentialInstanceIds map[CredentialFormat]string `json:"credential_instance_ids"`
	// The number of credential instances left per credential format (in case they were issued in batches)
	BatchInstanceCountsRemaining map[CredentialFormat]*uint `json:"batch_instance_counts_remaining"`
	// All the attributes and their values in this credential
	Attributes []Attribute `json:"attributes"`
	// The date and time (unix format) at which this credential was issued
	IssuanceDate int64 `json:"issuance_date"`
	// The date and time (unix format) when this credential expires
	ExpiryDate int64 `json:"expiry_date"` // TODO: should be optional
	// Whether or not this credential has been revoked
	Revoked bool `json:"revoked"`
	// Whether or not revocation is supported for this credential
	RevocationSupported bool `json:"revocation_supported"`
	// Url at which this credential can be issued (if any)
	IssueURL *TranslatedString `json:"issue_url"`
}

// CredentialDescriptor describes a credential type without any instance-specific values.
type CredentialDescriptor struct {
	CredentialId string            `json:"credential_id"`
	Name         TranslatedString  `json:"name"`
	Issuer       TrustedParty      `json:"issuer"`
	Category     *TranslatedString `json:"category,omitempty"`
	ImagePath    *string           `json:"image_path,omitempty"`
	Attributes   []Attribute       `json:"attributes"`
	IssueURL     *TranslatedString `json:"issue_url,omitempty"`
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
	// The id for this credential. For irma/idemix credentials this would look like
	// `pbdf.sidn-pbdf.email`, for EUDI credentials this would be in the form of `https://example.credential.com`
	CredentialId string `json:"credential_id"`
	// Hash over all attribute values and the credential id.
	Hash string `json:"hash"`
	// Absolute path to the image for this credential stored on disk
	ImagePath *string `json:"image_path"`
	// The display name for this credential
	Name TranslatedString `json:"name"`
	// All information about the credential issuer
	Issuer TrustedParty `json:"issuer"`
	// The credential format for this instance
	Format CredentialFormat `json:"format"`
	// The number of credential instances left for this credential instance
	BatchInstanceCountRemaining *uint `json:"batch_instance_count_remaining"`
	// All the attributes and their values in this credential that are selectable
	Attributes []Attribute `json:"attributes"`
	// The date and time (unix format) at which this credential was issued
	IssuanceDate int64 `json:"issuance_date"`
	// The date and time (unix format) when this credential expires
	ExpiryDate int64 `json:"expiry_date"`
	// Whether or not this credential has been revoked
	Revoked bool `json:"revoked"`
	// Whether or not revocation is supported for this credential
	RevocationSupported bool `json:"revocation_supported"`
	// Url at which this credential can be issued (if any)
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
