package metadata

import (
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"golang.org/x/text/language"
	"gorm.io/datatypes"
)

type CredentialIssuerMetadata struct {
	CredentialIssuer                  string                             `json:"credential_issuer"`
	AuthorizationServers              []string                           `json:"authorization_servers,omitempty"`
	CredentialEndpoint                string                             `json:"credential_endpoint"`
	NonceEndpoint                     string                             `json:"nonce_endpoint,omitempty"`
	DeferredCredentialEndpoint        string                             `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint              string                             `json:"notification_endpoint,omitempty"`
	CredentialRequestEncryption       *CredentialRequestEncryption       `json:"credential_request_encryption,omitempty"`
	CredentialResponseEncryption      *CredentialResponseEncryption      `json:"credential_response_encryption,omitempty"`
	BatchCredentialIssuance           *BatchCredentialIssuance           `json:"batch_credential_issuance,omitempty"`
	Display                           CredentialIssuerDisplays           `json:"display,omitempty"`
	CredentialConfigurationsSupported map[string]CredentialConfiguration `json:"credential_configurations_supported,omitempty"`
}

type CredentialRequestEncryption struct {
	Jwks               jwk.Set  `json:"jwks"`
	EncValuesSupported []string `json:"enc_values_supported"`
	ZipValuesSupported []string `json:"zip_values_supported,omitempty"`
	EncryptionRequired bool     `json:"encryption_required"`
}

type CredentialResponseEncryption struct {
	AlgValuesSupported []string `json:"alg_values_supported"`
	EncValuesSupported []string `json:"enc_values_supported"`
	ZipValuesSupported []string `json:"zip_values_supported,omitempty"`
	EncryptionRequired *bool    `json:"encryption_required"`
}

type BatchCredentialIssuance struct {
	BatchSize uint `json:"batch_size"`
}

type CredentialIssuerDisplay struct {
	Display
	Logo *RemoteImage `json:"logo,omitempty"`
}
type CredentialIssuerDisplays []CredentialIssuerDisplay

type RemoteImage struct {
	Uri     string `json:"uri"`
	AltText string `json:"alt_text,omitempty"`
}

type CredentialFormatIdentifier string
type CredentialDataModel string
type CredentialSigningAlgorithm string
type ProofTypeIdentifier string
type Proofs map[ProofTypeIdentifier][]any

type CredentialConfiguration struct {
	Format                               CredentialFormatIdentifier          `json:"format"`
	Scope                                *string                             `json:"scope,omitempty"`
	CredentialSigningAlgValuesSupported  []any                               `json:"credential_signing_alg_values_supported,omitempty"` // Can be string values for SD-JWTs, or objects for ISO mDoc
	CryptographicBindingMethodsSupported []proofs.CryptographicBindingMethod `json:"cryptographic_binding_methods_supported,omitempty"`
	ProofTypesSupported                  map[ProofTypeIdentifier]ProofType   `json:"proof_types_supported,omitempty"`
	CredentialMetadata                   *CredentialMetadata                 `json:"credential_metadata,omitempty"`

	// The following fields are present/absent, depending on the credential data model
	VerifiableCredentialType *string                  `json:"vct,omitempty"`                   // SD-JWT VC
	CredentialDefinition     *W3CCredentialDefinition `json:"credential_definition,omitempty"` // W3C VC
}

func (c CredentialConfiguration) GetCredentialDataModel() (error, CredentialDataModel) {
	if c.VerifiableCredentialType != nil {
		return nil, CredentialDataModel_IETF_SDJWTVC
	} else if c.CredentialDefinition != nil {
		if len(c.CredentialDefinition.Context) > 0 && c.CredentialDefinition.Context[0] == "https://www.w3.org/2018/credentials/v1" {
			return nil, CredentialDataModel_W3CVC_JSONLD
		}

		return nil, CredentialDataModel_W3CVC_JWT
	}
	return errors.New("unknown credential data model"), ""
}

func (c CredentialConfiguration) GetCredentialId() (error, string) {
	err, dm := c.GetCredentialDataModel()
	if err != nil {
		return err, ""
	}

	switch dm {
	case CredentialDataModel_IETF_SDJWTVC:
		if c.VerifiableCredentialType != nil {
			return nil, *c.VerifiableCredentialType
		}
	case CredentialDataModel_W3CVC_JWT:
		if c.CredentialDefinition != nil && len(c.CredentialDefinition.Type) > 0 {
			return nil, c.CredentialDefinition.Type[0]
		}
	case CredentialDataModel_W3CVC_JSONLD:
		return errors.New("W3C VC JSON-LD is not yet supported"), ""
	}

	return errors.New("unknown credential data model"), ""
}

type ProofType struct {
	ProofSigningAlgValuesSupported []string                   `json:"proof_signing_alg_values_supported"`
	KeyAttestationsRequired        *KeyAttestationRequirement `json:"key_attestations_required,omitempty"`
}

type KeyAttestationRequirement struct {
	KeyStorage         []AttestationAttackResistance `json:"key_storage,omitempty"`
	UserAuthentication []AttestationAttackResistance `json:"user_authentication,omitempty"`
}

type AttestationAttackResistance string

type CredentialMetadata struct {
	Display CredentialDisplays  `json:"display,omitempty"`
	Claims  []ClaimsDescription `json:"claims,omitempty"`
}

type CredentialDisplay struct {
	Display
	Logo            *RemoteImage `json:"logo,omitempty"`
	Description     string       `json:"description,omitempty"`
	BackgroundColor string       `json:"background_color,omitempty"`
	BackgroundImage *RemoteImage `json:"background_image,omitempty"`
	TextColor       string       `json:"text_color,omitempty"`
}
type CredentialDisplays []CredentialDisplay

type ClaimsPathPointer []any

type ClaimsDescription struct {
	Path      ClaimsPathPointer `json:"path"`
	Mandatory *bool             `json:"mandatory,omitempty"`
	Display   []Display         `json:"display,omitempty"`
}

type Translateable interface {
	GetName() string
	GetLocale() *string
}

type Display struct {
	Name   string  `json:"name,omitempty"`
	Locale *string `json:"locale,omitempty"`
}

type W3CCredentialDefinition struct {
	Context []string `json:"@context,omitempty"` // W3C VC using JSON-LD
	Type    []string `json:"type"`
}

type CredentialConfigurationVerifier interface {
	Verify(credentialConfiguration *CredentialConfiguration) error
}

const (
	Iso18045_High          AttestationAttackResistance = "iso_18045_high"
	Iso18045_Moderate      AttestationAttackResistance = "iso_18045_moderate"
	Iso18045_EnhancedBasic AttestationAttackResistance = "iso_18045_enhanced-basic"
	Iso18045_Basic         AttestationAttackResistance = "iso_18045_basic"

	CredentialFormatIdentifier_W3CVC              CredentialFormatIdentifier = "jwt_vc_json"
	CredentialFormatIdentifier_W3CVCLD            CredentialFormatIdentifier = "jwt_vc_json-ld"
	CredentialFormatIdentifier_W3CVCLD_ProofSuite CredentialFormatIdentifier = "ldp_vc"
	CredentialFormatIdentifier_MsoMdoc            CredentialFormatIdentifier = "mso_mdoc"
	CredentialFormatIdentifier_SdJwtVc            CredentialFormatIdentifier = "dc+sd-jwt"
	CredentialFormatIdentifier_SdJwtVc_Legacy     CredentialFormatIdentifier = "vc+sd-jwt"

	CredentialDataModel_IETF_SDJWTVC CredentialDataModel = "ietf_sd-jwt_vc"
	CredentialDataModel_W3CVC_JSONLD CredentialDataModel = "w3c_vc_json-ld"
	CredentialDataModel_W3CVC_JWT    CredentialDataModel = "w3c_vc_jwt"

	MediaType_SdJwtVc     string = "application/dc+sd-jwt"
	MediaType_SdJwtVc_Typ string = "dc+sd-jwt"

	ProofTypeIdentifier_JWT         ProofTypeIdentifier = "jwt"
	ProofTypeIdentifier_DIVP        ProofTypeIdentifier = "di_vp"
	ProofTypeIdentifier_Attestation ProofTypeIdentifier = "attestation"
)

const FallbackLocale = "en"

func (d Display) GetName() string {
	return d.Name
}
func (d Display) GetLocale() *string {
	return d.Locale
}

func (d CredentialDisplay) GetName() string {
	return d.Name
}
func (d CredentialDisplay) GetLocale() *string {
	return d.Locale
}
func (d CredentialIssuerDisplay) GetName() string {
	return d.Name
}
func (d CredentialIssuerDisplay) GetLocale() *string {
	return d.Locale
}

func (m CredentialIssuerMetadata) GetAllBaseLanguages() []string {
	// TODO: We need to make the app be aware of full locales, not just base languages
	languageSet := []string{}

	// Credential issuer display languages
	for _, display := range m.Display {
		if display.Locale != nil && *display.Locale != "" {
			baseLang, err := language.Parse(*display.Locale)
			if err != nil {
				continue
			}
			lang, _ := baseLang.Base()

			if !slices.Contains(languageSet, lang.String()) {
				languageSet = append(languageSet, lang.String())
			}
		}
	}

	return languageSet
}

func TryGetBaseLanguageFromLocale(locale string) (string, bool) {
	if locale == "" {
		return "", false
	}

	baseLang, err := language.Parse(locale)
	if err != nil {
		return "", false
	}
	lang, _ := baseLang.Base()

	return lang.String(), true
}

func (m CredentialIssuerMetadata) GetAllLanguages() []string {
	languageSet := make([]string, len(m.Display))

	// Credential issuer display languages
	for i, display := range m.Display {
		if display.Locale != nil && *display.Locale != "" {
			languageSet[i] = *display.Locale
		}
	}

	return languageSet
}

func (r *RemoteImage) UnmarshalJSON(data []byte) error {
	type BackwardsCompatibleRemoteImage struct {
		Uri     string `json:"uri"`
		Url     string `json:"url"`
		AltText string `json:"alt_text"`
	}

	var raw BackwardsCompatibleRemoteImage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	r.AltText = raw.AltText

	// Handle 'url' field for EUDIPLO backward compatibility
	if raw.Uri == "" && raw.Url != "" {
		r.Uri = raw.Url
	} else {
		r.Uri = raw.Uri
	}

	return nil
}

func (c *CredentialRequestEncryption) UnmarshalJSON(data []byte) error {
	// First unmarshal into map, to find out if 'jwks' is present
	var obj map[string]any
	err := json.Unmarshal(data, &obj)

	if err != nil {
		return err
	}

	if rawJwks, ok := obj["jwks"]; ok {
		// Workaround to extract jwk.Set from JSON
		// Marshal back to JSON string and parse that string
		rawJwksBytes, err := json.Marshal(rawJwks)
		if err != nil {
			return fmt.Errorf("invalid 'jwks': %w", err)
		}
		if jwks, err := jwk.Parse(rawJwksBytes); err != nil {
			return fmt.Errorf("invalid 'jwks': %w", err)
		} else {
			c.Jwks = jwks
		}
	}

	// Next, we'll unmarshal again for the rest of the fields
	type AliasStruct struct {
		EncValuesSupported []string `json:"enc_values_supported"`
		ZipValuesSupported []string `json:"zip_values_supported,omitempty"`
		EncryptionRequired bool     `json:"encryption_required"`
	}

	var aux AliasStruct
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	c.EncValuesSupported = aux.EncValuesSupported
	c.ZipValuesSupported = aux.ZipValuesSupported
	c.EncryptionRequired = aux.EncryptionRequired

	return nil
}

func ToTranslateableList[T Display | CredentialDisplay | CredentialIssuerDisplay](displays []T) []Translateable {
	translations := make([]Translateable, len(displays))
	for i, display := range displays {
		translations[i] = any(display).(Translateable)
	}
	return translations
}

func ConvertDisplayToTranslatedString(displays []Translateable) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	var nonLocaleValue *string = nil

	for _, display := range displays {
		locale := display.GetLocale()
		if locale == nil {
			result[""] = display.GetName() // If no locale is provided, we can still include the translation with an empty string as the key, but it won't be used for display
			t := display.GetName()         // Store the non-locale value to use as fallback if no translation for the fallback locale is provided
			nonLocaleValue = &t
			continue
		}

		lang, err := language.Parse(*locale)
		if err != nil {
			continue
		}

		base, _ := lang.Base()

		// TODO: this overwrites translations for the same base language (i.e. en-US would overwrite en-GB), because the app only handles base languages
		result[base.String()] = display.GetName()
	}

	if _, exists := result[FallbackLocale]; !exists && nonLocaleValue != nil {
		result[FallbackLocale] = *nonLocaleValue
	}

	return result
}

// IsUniqueStrings checks if all strings in the slice are unique (case-sensitive or insensitive)
func IsUniqueStrings(slice []string, caseInsensitive bool) bool {
	seen := make(map[string]bool)

	for _, str := range slice {
		// Normalize case if case-insensitive check is required
		key := str
		if caseInsensitive {
			key = strings.ToLower(str)
		}

		if seen[key] {
			return false // Duplicate found
		}
		seen[key] = true
	}
	return true
}

func (d CredentialIssuerDisplays) ToStorageModelIterator() iter.Seq[models.IssuerMetadataDisplay] {
	return func(yield func(models.IssuerMetadataDisplay) bool) {
		for _, item := range d {
			locale := datatypes.NullString{}
			if item.Locale != nil {
				locale.V = *item.Locale
				locale.Valid = true
			}

			m := models.IssuerMetadataDisplay{
				Name:   item.Name,
				Locale: locale,
			}

			if item.Logo != nil {
				m.LogoURI = datatypes.NullString{Valid: true, V: item.Logo.Uri}
				m.LogoAltText = datatypes.NullString{Valid: true, V: item.Logo.AltText}
			}

			if !yield(m) {
				return
			}
		}
	}
}

func (d CredentialDisplays) ToStorageModelIterator() iter.Seq[models.CredentialDisplay] {
	return func(yield func(models.CredentialDisplay) bool) {
		for _, item := range d {
			locale := datatypes.NullString{}
			if item.Locale != nil {
				locale.V = *item.Locale
				locale.Valid = true
			}

			m := models.CredentialDisplay{
				Name:            item.Name,
				Locale:          locale,
				Description:     item.Description,
				BackgroundColor: item.BackgroundColor,
				TextColor:       item.TextColor,
			}

			if item.BackgroundImage != nil {
				m.BackgroundImageURI = item.BackgroundImage.Uri
				m.BackgroundImageAltText = item.BackgroundImage.AltText
			}

			if item.Logo != nil {
				m.LogoURI = item.Logo.Uri
				m.LogoAltText = item.Logo.AltText
			}

			if !yield(m) {
				return
			}
		}
	}
}
