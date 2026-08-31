package openid4vci

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/internal/arrays"
	cose "github.com/veraison/go-cose"
	"golang.org/x/text/language"
)

type CredentialIssuerMetadataValidator struct {
	allowInsecureHttp bool
}
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
	} else {
		// According to OID4VCI §12.2.1, the Credential Issuer Identifier should always be a https schemed uri.
		if u, err := url.Parse(m.CredentialIssuer); err != nil {
			return fmt.Errorf("invalid 'credential_issuer' URL %q", m.CredentialIssuer)
		} else if !v.allowInsecureHttp && u.Scheme != "https" {
			return fmt.Errorf("invalid 'credential_issuer' URL %q: scheme must be https", m.CredentialIssuer)
		}
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
			// Verify the minimum requirements for this credential configuration
			if err := credentialConfigurationValidator.Verify(&credConfig); err != nil {
				return fmt.Errorf("invalid credential configuration %q: %w", credConfigId, err)
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
	case metadata.CredentialFormatIdentifier_SdJwtVc_Legacy:
		verifier = &SdJwtVcFormatVerifier{}
	default:
		return fmt.Errorf("unsupported credential format %q", c.Format)
	}

	return verifier.Verify(c)
}

// ValidateAndGetSupportedFeatures verifies that the credential configuration is supported by our client. It is split from the credential configuration validation, so it can be used at the moment a configuration is used to request credentials,
// because it makes no sense to validate configurations up front, which will not be requested either way.
func (v *CredentialConfigurationValidator) ValidateAndGetSupportedFeatures(c *metadata.CredentialConfiguration) (*sessionCredentialRequestPreferences, error) {
	s := &sessionCredentialRequestPreferences{}

	// We only support SD-JWT VC and mso_mdoc, for now
	if c.Format != metadata.CredentialFormatIdentifier_SdJwtVc &&
		c.Format != metadata.CredentialFormatIdentifier_SdJwtVc_Legacy &&
		c.Format != metadata.CredentialFormatIdentifier_MsoMdoc {
		return nil, fmt.Errorf("unsupported credential format %q", c.Format)
	}

	// Validate at least one advertised credential signing algorithm is supported.
	// Delegated because the check is format-dependent: mso_mdoc advertises COSE
	// algorithm identifiers as integers and dc+sd-jwt advertises JWS algorithm
	// names as strings, so reading every format as strings made an mdoc
	// configuration look as though it advertised nothing at all.
	if err := validateCredentialSigningAlgValues(c); err != nil {
		return nil, err
	}

	// We support JWK, did:key and did:jwk as cryptographic binding method, for now
	if len(c.CryptographicBindingMethodsSupported) > 0 {
		// Order of preferred cryptographic binding methods: JWK > DID > COSE, based on ease of implementation and expected level of support among issuers
		var bindingMethod proofs.CryptographicBindingMethod
		if slices.Contains(c.CryptographicBindingMethodsSupported, proofs.CryptographicBindingMethod_JWK) {
			bindingMethod = proofs.CryptographicBindingMethod_JWK
		} else if slices.Contains(c.CryptographicBindingMethodsSupported, proofs.CryptographicBindingMethod_DID_KEY) {
			bindingMethod = proofs.CryptographicBindingMethod_DID_KEY
		} else if slices.Contains(c.CryptographicBindingMethodsSupported, proofs.CryptographicBindingMethod_DID_JWK) {
			bindingMethod = proofs.CryptographicBindingMethod_DID_JWK
		} else {
			return nil, fmt.Errorf("no supported cryptographic binding method found in 'cryptographic_binding_methods_supported'")
		}

		s.cryptographicBindingMethod = &bindingMethod

		// We only support JWT proof type, for now
		if jwtProofType, ok := c.ProofTypesSupported[metadata.ProofTypeIdentifier_JWT]; !ok {
			return nil, fmt.Errorf("no supported proof-type found in 'proof_types_supported'")
		} else {
			if len(jwtProofType.ProofSigningAlgValuesSupported) == 0 {
				return nil, fmt.Errorf("no proof signing algorithm found in 'proof_signing_alg_values_supported'")
			}

			// For now, we only support `ES256` as proof signing algorithm, because our current keybinder only uses P-256 key type. This is a temporary limitation until we implement support for other key types. See keybinder_service.go for more details on the current keybinder implementation.
			if !slices.Contains(jwtProofType.ProofSigningAlgValuesSupported, jwa.ES256().String()) {
				return nil, fmt.Errorf("no supported proof signing algorithm found, only 'ES256' is supported")
			}

			s.proofSigningAlg = jwa.ES256()

			// TODO: For the future: keep in mind restrictions for the did:key cryptographic binding method
			// if bindingMethod == proofs.CryptographicBindingMethod_DID_KEY {
			// 	// If cryptographic binding method is did:key, the signature algorithm must be compatible,
			// 	// as did:key only supports: Ed25519, Ed25519+X25519, secp256k1, P-256, P-384, BLS12-381
			// 	supportedAlgs := supported-algs(jwtProofType.ProofSigningAlgValuesSupported)
			// }

			// We don't support key attestations, for now
			if jwtProofType.KeyAttestationsRequired != nil {
				return nil, fmt.Errorf("unsupported 'key_attestations_required' in 'proof_types_supported' for JWT proof type")
			}
		}
	}

	return s, nil
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

// Verify checks the mso_mdoc format-specific issuer metadata.
//
// doctype is REQUIRED for mso_mdoc by OpenID4VCI's credential format profile,
// exactly as vct is for dc+sd-jwt above, and it is the only value the wallet can
// hold an issued credential against: the docType inside the MSO is signed, but
// signed by whoever signed it, so on its own it says only "this is what the
// issuer chose to send", never "this is what I asked for". Rejecting a
// configuration without it is what makes that comparison possible at all — see
// the check in session.obtainCredential.
func (v *MdocFormatVerifier) Verify(credentialConfiguration *metadata.CredentialConfiguration) error {
	if credentialConfiguration.Doctype == "" {
		return fmt.Errorf("missing 'doctype' field for mso_mdoc credential format")
	}
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

// mdocAllowedSigningAlgorithms lists the COSE algorithm identifiers (RFC 9053)
// that ISO/IEC 18013-5 permits for the MSO signature over issuerAuth: ES256,
// ES384, ES512 and EdDSA. An mso_mdoc configuration advertising nothing from
// this set — only RS256 (-257), PS256 (-37), a MAC or encryption identifier —
// is not describing a document any 18013-5 verifier could accept, so it is
// reported as malformed metadata rather than as merely unsupported here.
var mdocAllowedSigningAlgorithms = []int64{
	int64(cose.AlgorithmES256), // -7
	int64(cose.AlgorithmEdDSA), // -8, Ed25519/Ed448
	int64(cose.AlgorithmES384), // -35
	int64(cose.AlgorithmES512), // -36
}

// mdocVerifiableSigningAlgorithms is the subset of mdocAllowedSigningAlgorithms
// that this wallet can check today: eudi/credentials/mdoc builds its COSE
// verifier with ES256 for both issuerAuth and the device signature. It is this
// list, not the wider one above, that decides whether an offer is accepted —
// see validateMdocCredentialSigningAlgValues. Teaching the mdoc verifier a
// further algorithm is therefore a matter of moving its identifier here.
var mdocVerifiableSigningAlgorithms = []int64{
	int64(cose.AlgorithmES256),
}

// validateCredentialSigningAlgValues checks that at least one advertised
// credential signing algorithm is legal for the credential's format.
//
// OID4VCI's format annexes make this parameter REQUIRED and non-empty, but they
// type its elements per format: mso_mdoc advertises COSE algorithm identifiers
// as integers (-7 for ES256, RFC 9053), while dc+sd-jwt advertises JWS
// algorithm names as strings ("ES256"). Reading every format as strings made an
// mdoc configuration look as though it advertised no algorithm at all, so mdoc
// issuance was refused here before the first network call — including from the
// EUDI reference issuer, whose every mdoc configuration advertises exactly [-7].
//
// For mso_mdoc the gate is the set this wallet can actually verify, which is
// what "supported features" means here. Admitting a spec-legal algorithm we
// cannot check would not make such a credential obtainable — it would only move
// the failure to the MSO signature check, after the user has consented and the
// pre-authorized code has been spent, and report it as an opaque invalid
// signature. The wider ISO 18013-5 set is still consulted, to say which kind of
// wrong an offer is: beyond this wallet, or beyond the standard.
//
// An absent or empty array stays acceptable, as it was before: the spec
// requires the parameter, but treating a lax issuer's omission as fatal would
// reject credentials this wallet can verify perfectly well.
func validateCredentialSigningAlgValues(c *metadata.CredentialConfiguration) error {
	if len(c.CredentialSigningAlgValuesSupported) == 0 {
		return nil
	}

	if c.Format == metadata.CredentialFormatIdentifier_MsoMdoc {
		return validateMdocCredentialSigningAlgValues(c.CredentialSigningAlgValuesSupported)
	}

	credentialSigningAlgValuesStrings := arrays.ConvertTo(c.CredentialSigningAlgValuesSupported, func(v any) (string, bool) {
		str, ok := v.(string)
		return str, ok
	})
	if _, err := getSupportedCredentialSigningAlgorithm(credentialSigningAlgValuesStrings); err != nil {
		return err
	}
	return nil
}

// validateMdocCredentialSigningAlgValues requires at least one advertised value
// to be an algorithm this wallet can verify, and distinguishes the two ways an
// offer can fail that: advertising only algorithms ISO 18013-5 permits but we
// have yet to implement, which is our gap to close, and advertising nothing
// 18013-5 permits for an MSO at all, which is a defect in the issuer's metadata.
// Values that are not COSE algorithm identifiers to begin with — a JWS name like
// "ES256", a non-integral number — count as neither, so a configuration made up
// entirely of them is reported as the latter.
func validateMdocCredentialSigningAlgValues(advertised []any) error {
	var allowed []int64
	for _, raw := range advertised {
		if alg, ok := toCoseAlgorithmIdentifier(raw); ok && slices.Contains(mdocAllowedSigningAlgorithms, alg) {
			allowed = append(allowed, alg)
		}
	}

	if len(allowed) == 0 {
		return fmt.Errorf(
			"no allowed signing algorithms in 'credential_signing_alg_values_supported': mso_mdoc advertises COSE algorithm identifiers and ISO 18013-5 permits only %v, got %v",
			mdocAllowedSigningAlgorithms, advertised,
		)
	}

	if !slices.ContainsFunc(allowed, func(alg int64) bool {
		return slices.Contains(mdocVerifiableSigningAlgorithms, alg)
	}) {
		return fmt.Errorf(
			"no supported signing algorithms in 'credential_signing_alg_values_supported': %v is permitted by ISO 18013-5 but this wallet verifies only %v",
			allowed, mdocVerifiableSigningAlgorithms,
		)
	}
	return nil
}

// toCoseAlgorithmIdentifier reads one advertised mso_mdoc signing algorithm as a
// COSE algorithm identifier. float64 is the shape that actually arrives from a
// fetched metadata document, since encoding/json decodes every JSON number into
// `any` as float64; the integer cases cover values constructed in Go. A
// non-integral number is not an identifier and is reported as unusable rather
// than silently truncated.
func toCoseAlgorithmIdentifier(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		i := int64(n)
		if float64(i) != n {
			return 0, false
		}
		return i, true
	case int:
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}

// getSupportedCredentialSigningAlgorithm returns the first algorithm from the input list whose
// signatures we can actually verify, so that we do not request a credential we would then have to
// reject. The accepted set is shared with JWT verification; see eudi_jwt.SupportedSignatureAlgorithms.
//
// This is the dc+sd-jwt half only. mso_mdoc advertises COSE algorithm
// identifiers rather than JWS names and is checked by
// validateMdocCredentialSigningAlgValues instead.
func getSupportedCredentialSigningAlgorithm(input []string) (*jwa.SignatureAlgorithm, error) {
	for _, x := range input {
		if alg, found := eudi_jwt.LookupSupportedSignatureAlgorithm(x); found {
			return &alg, nil
		}
	}

	return nil, fmt.Errorf("no supported credential signing algorithms found")
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
