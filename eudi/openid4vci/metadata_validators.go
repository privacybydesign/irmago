package openid4vci

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/internal/arrays"
	"golang.org/x/text/language"
)

type CredentialIssuerMetadataValidator struct{}
type CredentialConfigurationValidator struct{}
type CredentialMetadataValidator struct{}
type CredentialIssuerDisplaysValidator struct{}
type CredentialDisplaysValidator struct{}
type ClaimsDescriptionValidator struct{}
type RemoteImageValidator struct{}

// Verify validates the Credential Issuer metadata against the OpenID for Verifiable Credential Issuance specification.
func (v *CredentialIssuerMetadataValidator) Verify(m metadata.CredentialIssuerMetadata) error {
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
	if m.BatchCredentialIssuance != nil && m.BatchCredentialIssuance.BatchSize <= 1 {
		return fmt.Errorf("'batch_size' in 'batch_credential_issuance' must be > 1")
	}

	// --- Verify display information ---
	credentialIssuerDisplaysValidator := CredentialIssuerDisplaysValidator{}
	if err := credentialIssuerDisplaysValidator.verify(m.Display); err != nil {
		return err
	}

	return nil
}

func (v CredentialIssuerMetadataValidator) ValidateAgainstCredentialOffer(m *metadata.CredentialIssuerMetadata, credentialOffer *CredentialOffer) error {
	// If the credential issuer is not equal to the issuer which initiated the Credential Offer, the metadata is invalid
	// This assumes the caller has already verified that credentialIssuer is a valid URL
	if m.CredentialIssuer != credentialOffer.CredentialIssuer {
		return fmt.Errorf("'credential_issuer' in metadata does not match 'credential_issuer' from the credential offer")
	}

	// If the credential offer contains credential configuration IDs not present in the metadata, we cannot process the offer
	credentialConfigurationValidator := CredentialConfigurationValidator{}
	for _, credConfigId := range credentialOffer.CredentialConfigurationIds {
		if credConfig, ok := m.CredentialConfigurationsSupported[credConfigId]; ok {
			// Verify the issuer metadata for this credential configuration
			if err := credentialConfigurationValidator.Verify(&credConfig); err != nil {
				return fmt.Errorf("invalid credential configuration %q: %w", credConfigId, err)
			}

			// Validate that we support the credential configuration
			if err := credentialConfigurationValidator.ValidateSupportedFeatures(&credConfig); err != nil {
				return fmt.Errorf("credential configuration %q is not supported: %v", credConfigId, err)
			}
		} else {
			return fmt.Errorf("unsupported credential configuration %q in credential offer", credConfigId)
		}
	}
	return nil
}

// Verify validates a single Credential Configuration to the specification, according to its format profile
func (v *CredentialConfigurationValidator) Verify(c *metadata.CredentialConfiguration) error {
	// Verify credential metadata, if present
	if c.CredentialMetadata != nil {
		credentialMetadataValidator := CredentialMetadataValidator{}
		if err := credentialMetadataValidator.Verify(c.CredentialMetadata); err != nil {
			return fmt.Errorf("invalid 'credential_metadata': %w", err)
		}
	}

	if len(c.CryptographicBindingMethodsSupported) > 0 {
		if len(c.ProofTypesSupported) == 0 {
			return fmt.Errorf("missing 'proof_types_supported' while cryptographic binding methods are present")
		}
	}

	// Verify the credential configuration according to its format profile
	var verifier metadata.CredentialConfigurationVerifier
	switch c.Format {
	case metadata.CredentialFormatIdentifier_W3CVC:
		verifier = &W3CVCFormatVerifier{}
	case metadata.CredentialFormatIdentifier_W3CVCLD:
		verifier = &W3CVCLDFormatVerifier{}
	case metadata.CredentialFormatIdentifier_W3CVCLD_ProofSuite:
		verifier = &W3CDILDFormatVerifier{}
	case metadata.CredentialFormatIdentifier_MsoMdoc:
		verifier = &MdocFormatVerifier{}
	case metadata.CredentialFormatIdentifier_SdJwtVc:
		verifier = &SdJwtVcFormatVerifier{}
	default:
		return fmt.Errorf("unsupported credential format %q", c.Format)
	}

	return verifier.Verify(c)
}

// ValidateSupportedFeatures verifies that the credential configuration is supported by our client. It is split from the credential configuration validation, so it can be used at the moment a configuration is used to request credentials,
// because it makes no sense to validate configurations up front, which will not be requested either way.
func (v *CredentialConfigurationValidator) ValidateSupportedFeatures(c *metadata.CredentialConfiguration) error {
	// We only support SD-JWT VC, for now
	if c.Format != metadata.CredentialFormatIdentifier_SdJwtVc &&
		c.Format != metadata.CredentialFormatIdentifier_W3CVC {
		return fmt.Errorf("unsupported credential format %q", c.Format)
	}

	// Validate at least one credential signing algorithms is supported (which should be string values for SD-JWTs)
	credentialSigningAlgValuesStrings := arrays.ConvertTo(c.CredentialSigningAlgValuesSupported, func(v any) (string, bool) {
		str, ok := v.(string)
		return str, ok
	})
	if len(c.CredentialSigningAlgValuesSupported) != 0 &&
		len(getSupportedSignatureAlgorithms(credentialSigningAlgValuesStrings)) == 0 {
		return fmt.Errorf("no supported signing algorithms in 'credential_signing_alg_values_supported'")
	}

	// We only support JWK and DID cryptographic binding method, for now
	if len(c.CryptographicBindingMethodsSupported) > 0 {
		if !slices.Contains(c.CryptographicBindingMethodsSupported, proofs.CryptographicBindingMethod_JWK) &&
			!slices.Contains(c.CryptographicBindingMethodsSupported, proofs.CryptographicBindingMethod_DID_KEY) {
			return fmt.Errorf("unsupported cryptographic binding method(s) %q", c.CryptographicBindingMethodsSupported)
		}

		// We only support JWT proof type, for now
		if jwtProofType, ok := c.ProofTypesSupported[metadata.ProofTypeIdentifier_JWT]; !ok {
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

type W3CVCFormatVerifier struct{}
type W3CVCLDFormatVerifier struct{}
type W3CDILDFormatVerifier struct{}
type MdocFormatVerifier struct{}
type SdJwtVcFormatVerifier struct{}

// Verify SD-JWT VC credential configuration according to the Credential Format Profile specification
func (v *SdJwtVcFormatVerifier) Verify(credentialConfiguration *metadata.CredentialConfiguration) error {
	if credentialConfiguration.VerifiableCredentialType == "" {
		return fmt.Errorf("missing 'vct' field for SD-JWT VC credential format")
	}
	return nil
}

// Verify returns nil for now, as we don't support W3C Verifiable Credentials, so just return nil and accept any metadata that we get
func (v *W3CVCFormatVerifier) Verify(credentialConfiguration *metadata.CredentialConfiguration) error {
	if credentialConfiguration.CredentialDefinition == nil {
		return fmt.Errorf("missing 'credential_definition' field for W3C VC credential format")
	} else if len(credentialConfiguration.CredentialDefinition.Type) == 0 {
		return fmt.Errorf("'credential_definition.type' field for W3C VC credential format is empty")
	}
	return nil
}

// Verify returns nil for now, as we don't support W3C Verifiable Credentials JSON-LD, so just return nil and accept any metadata that we get
func (v *W3CVCLDFormatVerifier) Verify(credentialConfiguration *metadata.CredentialConfiguration) error {
	return nil
}

// Verify returns nil for now, as we don't support W3C Verifiable Credentials, so just return nil and accept any metadata that we get
func (v *W3CDILDFormatVerifier) Verify(credentialConfiguration *metadata.CredentialConfiguration) error {
	return nil
}

// Verify returns nil for now, as we don't support mDoc Credentials, so just return nil and accept any metadata that we get
func (v *MdocFormatVerifier) Verify(credentialConfiguration *metadata.CredentialConfiguration) error {
	return nil
}

// Verify validates the Credential Metadata according to the specification
func (v *CredentialMetadataValidator) Verify(m *metadata.CredentialMetadata) error {
	credentialDisplaysValidator := CredentialDisplaysValidator{}
	if err := credentialDisplaysValidator.verify(m.Display); err != nil {
		return fmt.Errorf("invalid 'display': %w", err)
	}

	// Validate claims descriptions
	claimDescriptionValidator := ClaimsDescriptionValidator{}
	for _, claim := range m.Claims {
		if err := claimDescriptionValidator.verify(&claim); err != nil {
			return fmt.Errorf("invalid claim description: %w", err)
		}
	}

	return nil
}

func (v *RemoteImageValidator) Verify(r *metadata.RemoteImage) error {
	if r.Uri == "" {
		return fmt.Errorf("missing 'uri'")
	}
	if _, err := url.Parse(r.Uri); err != nil {
		return fmt.Errorf("invalid 'uri': %v", err)
	}
	return nil
}

func (v *ClaimsDescriptionValidator) verify(c *metadata.ClaimsDescription) error {
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

func validateLocale(availableTranslations []metadata.Translateable, translation metadata.Translateable) error {
	locale := translation.GetLocale()
	if locale == nil {
		return nil
	}

	// Validate that the locale is a valid BCP 47 language tag
	if _, err := language.Parse(*locale); err != nil {
		return fmt.Errorf("invalid 'locale' tag %q in 'display' item with name %q: %w", *locale, translation.GetName(), err)
	}

	// Validate that the locale is present only once in the list of translations
	counter := 0
	for _, existingTranslation := range availableTranslations {
		if existingTranslation.GetLocale() != nil && *existingTranslation.GetLocale() == *locale {
			counter++
		}

		if counter > 1 {
			return fmt.Errorf("duplicate 'locale' tag %q in 'display' item with name %q", *locale, translation.GetName())
		}
	}

	return nil
}

func (v CredentialIssuerDisplaysValidator) verify(d metadata.CredentialIssuerDisplays) error {
	translations := DisplaysToTranslateableList(d)
	imageValidator := RemoteImageValidator{}
	for _, display := range d {
		if display.Logo != nil {
			if err := imageValidator.Verify(display.Logo); err != nil {
				return fmt.Errorf("invalid 'logo' in 'display': %w", err)
			}
		}

		if display.Locale != nil && *display.Locale != "" {
			if err := validateLocale(translations, &display); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *CredentialDisplaysValidator) verify(d metadata.CredentialDisplays) error {
	translations := DisplaysToTranslateableList(d)
	imageValidator := RemoteImageValidator{}

	for _, display := range d {
		if display.Name == "" {
			return fmt.Errorf("missing 'name'")
		}
		if display.Logo != nil {
			if err := imageValidator.Verify(display.Logo); err != nil {
				return fmt.Errorf("invalid 'logo': %w", err)
			}
		}
		if display.BackgroundImage != nil {
			if err := imageValidator.Verify(display.BackgroundImage); err != nil {
				return fmt.Errorf("invalid 'background_image': %w", err)
			}
		}

		// Validate locale, and check for duplicates
		if display.Locale != nil && *display.Locale != "" {
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

func getSupportedSignatureAlgorithms(input []string) []string {
	supportedAlgs := []string{}
	for _, alg := range input {
		// Skip ES256K for now, since it's not widely supported among JWT libraries and we tests have shown to fail
		if alg == "ES256K" {
			continue
		}
		if _, ok := jwa.LookupSignatureAlgorithm(alg); ok {
			supportedAlgs = append(supportedAlgs, alg)
		}
	}
	return supportedAlgs
}

func DisplaysToTranslateableList[T metadata.Display | metadata.CredentialDisplay | metadata.CredentialIssuerDisplay](displays []T) []metadata.Translateable {
	result := make([]metadata.Translateable, 0, len(displays))
	for _, d := range displays {
		if x, ok := any(d).(metadata.Display); ok {
			result = append(result, &x)
		} else if x, ok := any(d).(metadata.CredentialDisplay); ok {
			result = append(result, &x)
		} else if x, ok := any(d).(metadata.CredentialIssuerDisplay); ok {
			result = append(result, &x)
		}
	}
	return result
}
