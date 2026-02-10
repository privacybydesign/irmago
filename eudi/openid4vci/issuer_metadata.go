package openid4vci

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"golang.org/x/text/language"
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
type CredentialSigningAlgorithm string
type CryptographicBindingMethod string
type ProofTypeIdentifier string

const (
	CryptographicBindingMethod_JWK  CryptographicBindingMethod = "jwk"
	CryptographicBindingMethod_DID  CryptographicBindingMethod = "did"
	CryptographicBindingMethod_COSE CryptographicBindingMethod = "cose_key"
)

type CredentialConfiguration struct {
	Format                               CredentialFormatIdentifier        `json:"format"`
	Scope                                string                            `json:"scope,omitempty"`
	CredentialSigningAlgValuesSupported  []string                          `json:"credential_signing_alg_values_supported,omitempty"`
	CryptographicBindingMethodsSupported []CryptographicBindingMethod      `json:"cryptographic_binding_methods_supported,omitempty"`
	ProofTypesSupported                  map[ProofTypeIdentifier]ProofType `json:"proof_types_supported,omitempty"`
	CredentialMetadata                   *CredentialMetadata               `json:"credential_metadata,omitempty"`

	// The following fields are present/absent, depending on the credential format
	VerifiableCredentialType string                   `json:"vct,omitempty"`                   // SD-JWT VC
	CredentialDefinition     *W3CCredentialDefinition `json:"credential_definition,omitempty"` // W3C VC Signed as JWT, no JSON-LD
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

type ClaimsPathPointer []string

type ClaimsDescription struct {
	Path      ClaimsPathPointer `json:"path"`
	Mandatory *bool             `json:"mandatory,omitempty"`
	Display   []Display         `json:"display,omitempty"`
}

type Translateable interface {
	GetName() string
	GetLocale() string
}

type Display struct {
	Name   string `json:"name,omitempty"`
	Locale string `json:"locale,omitempty"`
}

type W3CCredentialDefinition struct {
	Context []string `json:"@context,omitempty"` // W3C VC using JSON-LD
	Type    []string `json:"type"`
}

type CredentialConfigurationVerifier interface {
	Verify(credentialConfiguration *CredentialConfiguration) error
}

type W3CVCFormatVerifier struct{}
type W3CVCLDFormatVerifier struct{}
type W3CDILDFormatVerifier struct{}
type MdocFormatVerifier struct{}
type SdJwtVcFormatVerifier struct{}

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

	ProofTypeIdentifier_JWT         ProofTypeIdentifier = "jwt"
	ProofTypeIdentifier_DIVP        ProofTypeIdentifier = "di_vp"
	ProofTypeIdentifier_Attestation ProofTypeIdentifier = "attestation"
)

func (d Display) GetName() string {
	return d.Name
}
func (d Display) GetLocale() string {
	return d.Locale
}

func (d CredentialDisplay) GetName() string {
	return d.Name
}
func (d CredentialDisplay) GetLocale() string {
	return d.Locale
}
func (d CredentialIssuerDisplay) GetName() string {
	return d.Name
}
func (d CredentialIssuerDisplay) GetLocale() string {
	return d.Locale
}

func DisplaysToTranslateableList[T Display | CredentialDisplay | CredentialIssuerDisplay](displays []T) []Translateable {
	result := make([]Translateable, len(displays))
	for i, d := range displays {
		if x, ok := any(d).(Display); ok {
			result[i] = &x
		} else if x, ok := any(d).(CredentialDisplay); ok {
			result[i] = &x
		} else if x, ok := any(d).(CredentialIssuerDisplay); ok {
			result[i] = &x
		}
	}
	return result
}

// Verify validates the Credential Issuer metadata against the OpenID for Verifiable Credential Issuance specification.
func (m *CredentialIssuerMetadata) Verify() error {
	// Required field validation
	if m.CredentialIssuer == "" {
		return fmt.Errorf("missing 'credential_issuer'")
	}
	if m.CredentialEndpoint == "" {
		return fmt.Errorf("missing 'credential_endpoint'")
	}
	if len(m.CredentialConfigurationsSupported) == 0 {
		return fmt.Errorf("missing 'credential_configurations_supported'")
	}

	// --- Authorization server(s) validation ---
	for _, authServer := range m.AuthorizationServers {
		if _, err := url.Parse(authServer); err != nil {
			return fmt.Errorf("invalid 'authorization_server' URL %q", authServer)
		}
	}

	// --- Endpoints validation ---
	// Credential endpoint
	if credentialEndpoint, err := url.Parse(m.CredentialEndpoint); err != nil {
		return fmt.Errorf("invalid 'credential_endpoint' URL %q", m.CredentialEndpoint)
	} else if credentialEndpoint.Fragment != "" {
		return fmt.Errorf("invalid 'credential_endpoint' URL %q: fragment is not allowed", m.CredentialEndpoint)
	}

	// Nonce endpoint
	if m.NonceEndpoint != "" {
		if nonceEndpoint, err := url.Parse(m.NonceEndpoint); err != nil {
			return fmt.Errorf("invalid 'nonce_endpoint' URL %q", m.NonceEndpoint)
		} else if nonceEndpoint.Fragment != "" {
			return fmt.Errorf("invalid 'nonce_endpoint' URL %q: fragment is not allowed", m.NonceEndpoint)
		}
	}

	// Deferred credential endpoint
	if m.DeferredCredentialEndpoint != "" {
		if deferredCredentialEndpoint, err := url.Parse(m.DeferredCredentialEndpoint); err != nil {
			return fmt.Errorf("invalid 'deferred_credential_endpoint' URL %q", m.DeferredCredentialEndpoint)
		} else if deferredCredentialEndpoint.Fragment != "" {
			return fmt.Errorf("invalid 'deferred_credential_endpoint' URL %q: fragment is not allowed", m.DeferredCredentialEndpoint)
		}
	}

	// Notification endpoint
	if m.NotificationEndpoint != "" {
		if notificationEndpoint, err := url.Parse(m.NotificationEndpoint); err != nil {
			return fmt.Errorf("invalid 'notification_endpoint' URL %q", m.NotificationEndpoint)
		} else if notificationEndpoint.Fragment != "" {
			return fmt.Errorf("invalid 'notification_endpoint' URL %q: fragment is not allowed", m.NotificationEndpoint)
		}
	}

	// --- Request encryption validation ---
	if m.CredentialRequestEncryption != nil {
		if m.CredentialRequestEncryption.Jwks == nil || m.CredentialRequestEncryption.Jwks.Len() == 0 {
			return fmt.Errorf("missing or empty 'jwks' in 'credential_request_encryption'")
		}
		if len(m.CredentialRequestEncryption.EncValuesSupported) == 0 {
			return fmt.Errorf("missing or empty 'enc_values_supported' in 'credential_request_encryption'")
		}
	}

	// // --- Response encryption validation ---
	// if m.CredentialResponseEncryption != nil {
	// 	// TODO
	// }

	// --- Batch issuance validation ---
	// TODO: determine if we want to support credentials WITHOUT batch issuance
	if m.BatchCredentialIssuance != nil && m.BatchCredentialIssuance.BatchSize <= 1 {
		return fmt.Errorf("'batch_size' in 'batch_credential_issuance' must be > 1")
	}

	// --- Credential configurations supported validation ---
	for name, credConfig := range m.CredentialConfigurationsSupported {
		if err := credConfig.Verify(); err != nil {
			return fmt.Errorf("invalid credential configuration %q: %w", name, err)
		}
	}

	// --- Verify display information ---
	if err := m.Display.verify(); err != nil {
		return err
	}

	return nil
}

func (m *CredentialIssuerMetadata) ValidateAgainstCredentialOffer(credentialOffer *CredentialOffer) error {
	// If the credential issuer is not equal to the issuer which initiated the Credential Offer, the metadata is invalid
	// This assumes the caller has already verified that credentialIssuer is a valid URL
	if m.CredentialIssuer != credentialOffer.CredentialIssuer {
		return fmt.Errorf("'credential_issuer' in metadata does not match 'credential_issuer' from the credential offer")
	}

	// If the credential offer contains credential configuration IDs not present in the metadata, we cannot process the offer
	for _, credConfigId := range credentialOffer.CredentialConfigurationIds {
		if credConfig, ok := m.CredentialConfigurationsSupported[credConfigId]; ok {
			// Validate that we support the credential configuration
			if err := credConfig.ValidateSupportedFeatures(); err != nil {
				return fmt.Errorf("credential configuration %q is not supported: %v", credConfigId, err)
			}
		} else {
			return fmt.Errorf("unsupported credential configuration %q in credential offer", credConfigId)
		}
	}
	return nil
}

// Verify validates a single Credential Configuration to the specification, according to its format profile
func (c *CredentialConfiguration) Verify() error {
	// Verify credential metadata, if present
	if c.CredentialMetadata != nil {
		if err := c.CredentialMetadata.verify(); err != nil {
			return fmt.Errorf("invalid 'credential_metadata': %w", err)
		}
	}

	if len(c.CryptographicBindingMethodsSupported) > 0 {
		if len(c.ProofTypesSupported) == 0 {
			return fmt.Errorf("missing 'proof_types_supported' while cryptographic binding methods are present")
		}
	}

	// Verify the credential configuration according to its format profile
	var verifier CredentialConfigurationVerifier
	switch c.Format {
	case CredentialFormatIdentifier_W3CVC:
		verifier = &W3CVCFormatVerifier{}
	case CredentialFormatIdentifier_W3CVCLD:
		verifier = &W3CVCLDFormatVerifier{}
	case CredentialFormatIdentifier_W3CVCLD_ProofSuite:
		verifier = &W3CDILDFormatVerifier{}
	case CredentialFormatIdentifier_MsoMdoc:
		verifier = &MdocFormatVerifier{}
	case CredentialFormatIdentifier_SdJwtVc:
		verifier = &SdJwtVcFormatVerifier{}
	case CredentialFormatIdentifier_SdJwtVc_Legacy:
		verifier = &SdJwtVcFormatVerifier{}
	default:
		return fmt.Errorf("unsupported credential format %q", c.Format)
	}

	return verifier.Verify(c)
}

// ValidateSupportedFeatures verifies that the credential configuration is supported by our client. It is split from the credential configuration validation, so it can be used at the moment a configuration is used to request credentials,
// because it makes no sense to validate configurations up front, which will not be requested either way.
func (c *CredentialConfiguration) ValidateSupportedFeatures() error {
	// We only support SD-JWT VC, for now
	if c.Format != CredentialFormatIdentifier_SdJwtVc && c.Format != CredentialFormatIdentifier_SdJwtVc_Legacy {
		return fmt.Errorf("unsupported credential format %q", c.Format)
	}

	// We only support authorization requests for credential requests using the `scope` parameter, for now
	if len(c.Scope) == 0 {
		return fmt.Errorf("missing 'scope' parameter")
	}

	// Validate at least one credential signing algorithms is supported
	if len(c.CredentialSigningAlgValuesSupported) != 0 &&
		len(getSupportedSignatureAlgorithms(c.CredentialSigningAlgValuesSupported)) == 0 {
		return fmt.Errorf("no supported signing algorithms in 'credential_signing_alg_values_supported'")
	}

	// We only support JWK cryptographic binding method, for now
	if len(c.CryptographicBindingMethodsSupported) > 0 {
		if !slices.Contains(c.CryptographicBindingMethodsSupported, CryptographicBindingMethod_JWK) {
			return fmt.Errorf("unsupported cryptographic binding method(s) %q", c.CryptographicBindingMethodsSupported)
		}

		// We only support JWT proof type, for now
		if jwtProofType, ok := c.ProofTypesSupported[ProofTypeIdentifier_JWT]; !ok {
			return fmt.Errorf("missing 'proof_types_supported' for JWT")
		} else {
			if len(getSupportedSignatureAlgorithms(jwtProofType.ProofSigningAlgValuesSupported)) == 0 {
				return fmt.Errorf("no supported signing algorithms in 'proof_signing_alg_values_supported' for JWT proof type")
			}

			// We don't support key attestations, for now
			if jwtProofType.KeyAttestationsRequired != nil {
				return fmt.Errorf("unsupported 'key_attestations_required' in 'proof_types_supported' for JWT proof type")
			}
		}
	}

	return nil
}

// Verify SD-JWT VC credential configuration according to the Credential Format Profile specification
func (v *SdJwtVcFormatVerifier) Verify(credentialConfiguration *CredentialConfiguration) error {
	if credentialConfiguration.VerifiableCredentialType == "" {
		return fmt.Errorf("missing 'vct' field for SD-JWT VC credential format")
	}
	return nil
}

// Verify returns nil for now, as we don't support W3C Verifiable Credentials, so just return nil and accept any metadata that we get
func (v *W3CVCFormatVerifier) Verify(credentialConfiguration *CredentialConfiguration) error {
	return nil
}

// Verify returns nil for now, as we don't support W3C Verifiable Credentials, so just return nil and accept any metadata that we get
func (v *W3CVCLDFormatVerifier) Verify(credentialConfiguration *CredentialConfiguration) error {
	return nil
}

// Verify returns nil for now, as we don't support W3C Verifiable Credentials, so just return nil and accept any metadata that we get
func (v *W3CDILDFormatVerifier) Verify(credentialConfiguration *CredentialConfiguration) error {
	return nil
}

// Verify returns nil for now, as we don't support mDoc Credentials, so just return nil and accept any metadata that we get
func (v *MdocFormatVerifier) Verify(credentialConfiguration *CredentialConfiguration) error {
	return nil
}

// Verify validates the Credential Metadata according to the specification
func (m *CredentialMetadata) verify() error {
	if err := m.Display.verify(); err != nil {
		return fmt.Errorf("invalid 'display': %w", err)
	}

	// Validate claims descriptions
	for _, claim := range m.Claims {
		if err := claim.verify(); err != nil {
			return fmt.Errorf("invalid claim description: %w", err)
		}
	}

	return nil
}

func (r *RemoteImage) verify() error {
	if r.Uri == "" {
		return fmt.Errorf("missing 'uri'")
	}
	if _, err := url.Parse(r.Uri); err != nil {
		return fmt.Errorf("invalid 'uri': %v", err)
	}
	return nil
}

func (c *ClaimsDescription) verify() error {
	if len(c.Path) == 0 {
		return fmt.Errorf("missing 'path'")
	}

	// If 'mandatory' is not set, default to false
	if c.Mandatory == nil {
		c.Mandatory = new(bool)
		*c.Mandatory = false
	}

	// Validate locale, and check for duplicates
	translations := DisplaysToTranslateableList(c.Display)
	for _, display := range c.Display {
		if err := validateLocale(translations, &display); err != nil {
			return err
		}
	}

	return nil
}

func validateLocale(availableTranslations []Translateable, translation Translateable) error {
	// Validate that the locale is a valid BCP 47 language tag
	if _, err := language.Parse(translation.GetLocale()); err != nil {
		return fmt.Errorf("invalid 'locale' tag %q in 'display' item with name %q: %w", translation.GetLocale(), translation.GetName(), err)
	}

	// Validate that the locale is present only once in the list of translations
	counter := 0
	for _, existingTranslation := range availableTranslations {
		if existingTranslation.GetLocale() == translation.GetLocale() {
			counter++
		}

		if counter > 1 {
			return fmt.Errorf("duplicate 'locale' tag %q in 'display' item with name %q", translation.GetLocale(), translation.GetName())
		}
	}

	return nil
}

func (d CredentialIssuerDisplays) verify() error {
	translations := DisplaysToTranslateableList(d)
	for _, display := range d {
		if display.Logo != nil {
			if err := display.Logo.verify(); err != nil {
				return fmt.Errorf("invalid 'logo' in 'display': %w", err)
			}
		}

		if display.Locale != "" {
			if err := validateLocale(translations, &display); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d CredentialDisplays) verify() error {
	translations := DisplaysToTranslateableList(d)

	for _, display := range d {
		if display.Name == "" {
			return fmt.Errorf("missing 'name'")
		}
		if display.Logo != nil {
			if err := display.Logo.verify(); err != nil {
				return fmt.Errorf("invalid 'logo': %w", err)
			}
		}
		if display.BackgroundImage != nil {
			if err := display.BackgroundImage.verify(); err != nil {
				return fmt.Errorf("invalid 'background_image': %w", err)
			}
		}

		// Validate locale, and check for duplicates
		if display.Locale != "" {
			if err := validateLocale(translations, &display); err != nil {
				return err
			}
		}

		// Validate background color, if present
		if display.BackgroundColor != "" {
			if !isValidCSSColorLevel3(display.BackgroundColor) {
				return fmt.Errorf("invalid 'background_color' %q", display.BackgroundColor)
			}
		}

		// Validate text color, if present
		if display.TextColor != "" {
			if !isValidCSSColorLevel3(display.TextColor) {
				return fmt.Errorf("invalid 'text_color' %q", display.TextColor)
			}
		}
	}

	return nil
}

// IsValidCSSColorLevel3 checks if the input is a valid CSS Color Module Level 3 numerical color value.
func isValidCSSColorLevel3(s string) bool {
	s = strings.TrimSpace(s)
	// Hexadecimal color regexes
	hex3 := regexp.MustCompile(`^#([0-9a-fA-F]{3})$`)
	hex4 := regexp.MustCompile(`^#([0-9a-fA-F]{4})$`)
	hex6 := regexp.MustCompile(`^#([0-9a-fA-F]{6})$`)
	hex8 := regexp.MustCompile(`^#([0-9a-fA-F]{8})$`)

	// Functional color regexes
	rgb := regexp.MustCompile(`^rgb\(\s*((\b([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])|\b([0-9]|[1-9][0-9]|100)%)\s*,\s*){2}(\b([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])|\b([0-9]|[1-9][0-9]|100)%)\s*\)$`)
	rgba := regexp.MustCompile(`^rgba\(\s*((\b([01]?[0-9][0-9]?|2[0-4][0-9]|25[0-5])|\b([0-9]|[1-9][0-9]|100)%)\s*,\s*){3}(0|1|1\.0|0?\.\d+)\s*\)$`)
	hsl := regexp.MustCompile(`^hsl\(\s*\b([012]?[0-9][0-9]?|3[0-5][0-9]|360)\s*,\s*\b([0-9]|[1-9][0-9]|100)%\s*,\s*\b([0-9]|[1-9][0-9]|100)%\s*\)$`)
	hsla := regexp.MustCompile(`^hsla\(\s*\b([012]?[0-9][0-9]?|3[0-5][0-9]|360)\s*,\s*\b([0-9]|[1-9][0-9]|100)%\s*,\s*\b([0-9]|[1-9][0-9]|100)%\s*,\s*(0|1|1\.0|0?\.\d+)\s*\)$`)

	return hex6.MatchString(s) || hex3.MatchString(s) || hex4.MatchString(s) || hex8.MatchString(s) ||
		rgb.MatchString(s) || rgba.MatchString(s) || hsl.MatchString(s) || hsla.MatchString(s)
}

func (m CredentialIssuerMetadata) GetAllBaseLanguages() []string {
	// TODO: We need to make the app be aware of full locales, not just base languages
	languageSet := []string{}

	// Credential issuer display languages
	for _, display := range m.Display {
		if display.Locale != "" {
			baseLang, err := language.Parse(display.Locale)
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

func (m CredentialIssuerMetadata) GetAllLanguages() []string {
	languageSet := make([]string, len(m.Display))

	// Credential issuer display languages
	for i, display := range m.Display {
		if display.Locale != "" {
			languageSet[i] = display.Locale
		}
	}

	return languageSet
}

func getSupportedSignatureAlgorithms(input []string) []string {
	supportedAlgs := []string{}
	for _, alg := range input {
		if _, ok := jwa.LookupSignatureAlgorithm(alg); ok {
			supportedAlgs = append(supportedAlgs, alg)
		}
	}
	return supportedAlgs
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

func (cre *CredentialRequestEncryption) UnmarshalJSON(data []byte) error {
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
			cre.Jwks = jwks
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

	cre.EncValuesSupported = aux.EncValuesSupported
	cre.ZipValuesSupported = aux.ZipValuesSupported
	cre.EncryptionRequired = aux.EncryptionRequired

	return nil
}
