package openid4vci

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
)

var locale_EN = "en"
var locale_EN_US = "en-US"
var invalid_Locale = "invalid_locale"

var scope = "https://pid-issuer/vct/pid"

func TestValidateCredentialConfiguration_SupportedFormats(t *testing.T) {
	tests := []struct {
		name    string
		format  metadata.CredentialFormatIdentifier
		wantErr bool
	}{
		{"W3CVC", metadata.CredentialFormatIdentifier_W3CVC, false},
		{"W3CVCLD", metadata.CredentialFormatIdentifier_W3CVCLD, false},
		{"W3CVCLD_ProofSuite", metadata.CredentialFormatIdentifier_W3CVCLD_ProofSuite, false},
		{"MsoMdoc", metadata.CredentialFormatIdentifier_MsoMdoc, false},
		{"SdJwtVc", metadata.CredentialFormatIdentifier_SdJwtVc, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &metadata.CredentialConfiguration{
				Format:                   tt.format,
				Doctype:                  "eu.europa.ec.av.1",
				VerifiableCredentialType: "https://issuer.example.com/credential/my-type",
			}
			validator := CredentialConfigurationValidator{}
			err := validator.Verify(c)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCredentialConfiguration_UnsupportedFormat(t *testing.T) {
	c := &metadata.CredentialConfiguration{
		Format: "unsupported_format",
	}
	validator := CredentialConfigurationValidator{}
	err := validator.Verify(c)
	if err == nil {
		t.Errorf("Expected error for unsupported format, got nil")
	}
	want := `unsupported credential format "unsupported_format"`
	if err.Error() != want {
		t.Errorf("Expected error %q, got %q", want, err.Error())
	}
}

func TestValidateCredentialConfiguration_SdJwtVc_InvalidCredentialMetadata(t *testing.T) {
	c := &metadata.CredentialConfiguration{
		Format:                              metadata.CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []any{"ES256"},
		CredentialMetadata: &metadata.CredentialMetadata{
			Display: []metadata.CredentialDisplay{
				{
					Name: "",
				},
			},
		},
	}
	validator := CredentialConfigurationValidator{}
	err := validator.Verify(c)
	if err == nil {
		t.Errorf("Expected error for missing name in display, got nil")
	}
	if err != nil && err.Error() != "invalid 'credential_metadata': invalid 'display': missing 'name'" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestValidateCredentialConfiguration_SdJwtVc_ValidCredentialMetadata(t *testing.T) {
	c := &metadata.CredentialConfiguration{
		Format:                              metadata.CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []any{"ES256"},
		CredentialMetadata: &metadata.CredentialMetadata{
			Display: []metadata.CredentialDisplay{
				{
					Name:   "Test Credential",
					Locale: &locale_EN,
				},
			},
		},
		VerifiableCredentialType: "https://issuer.example.com/credential/my-type",
	}
	validator := CredentialConfigurationValidator{}
	err := validator.Verify(c)
	if err != nil {
		t.Errorf("Expected no error for valid credential metadata, got %v", err)
	}
}

func TestCredentialIssuerMetadata_Verify(t *testing.T) {
	validCredentialConfig := metadata.CredentialConfiguration{
		Format:                              metadata.CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []any{"ES256"},
		CredentialMetadata: &metadata.CredentialMetadata{
			Display: []metadata.CredentialDisplay{
				{
					Name:   "Test Credential",
					Locale: &locale_EN,
				},
			},
		},
		VerifiableCredentialType: "https://issuer.example.com/credential/my-type",
	}
	tests := []struct {
		name              string
		metadata          metadata.CredentialIssuerMetadata
		offer             *CredentialOffer
		allowInsecureHttp bool
		wantErr           string
	}{
		{
			name: "missing credential_issuer",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "missing 'credential_issuer'",
		},
		{
			name: "invalid credential_issuer (non-HTTPS)",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "http://issuer.example.com/",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "invalid 'credential_issuer' URL \"http://issuer.example.com/\": scheme must be https",
		},
		{
			name: "invalid credential_issuer (non-HTTPS), valid with `allowInsecureHttp` enabled",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "http://issuer.example.com/",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			allowInsecureHttp: true,
			wantErr:           "",
		},
		{
			name: "invalid credential_issuer (non-URI)",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  ":|invalid uri|:",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "invalid 'credential_issuer' URL \":|invalid uri|:\"",
		},
		{
			name: "missing credential_endpoint",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "missing 'credential_endpoint'",
		},
		{
			name: "missing credential_configurations_supported",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
			},
			wantErr: "missing 'credential_configurations_supported'",
		},
		{
			name: "empty credential_configurations_supported",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{},
			},
			wantErr: "missing 'credential_configurations_supported'",
		},
		{
			name: "invalid authorization_server URL",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				AuthorizationServers:              []string{"://invalid-url"},
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'authorization_server' URL "://invalid-url"`,
		},
		{
			name: "invalid credential_endpoint URL",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "://invalid-url",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'credential_endpoint' URL "://invalid-url"`,
		},
		{
			name: "credential_endpoint with fragment",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential#frag",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'credential_endpoint' URL "https://issuer.example.com/credential#frag": fragment is not allowed`,
		},
		{
			name: "nonce_endpoint with fragment",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				NonceEndpoint:                     "https://issuer.example.com/nonce#frag",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'nonce_endpoint' URL "https://issuer.example.com/nonce#frag": fragment is not allowed`,
		},
		{
			name: "deferred_credential_endpoint with fragment",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				DeferredCredentialEndpoint:        "https://issuer.example.com/deferred#frag",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'deferred_credential_endpoint' URL "https://issuer.example.com/deferred#frag": fragment is not allowed`,
		},
		{
			name: "notification_endpoint with fragment",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				NotificationEndpoint:              "https://issuer.example.com/notify#frag",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'notification_endpoint' URL "https://issuer.example.com/notify#frag": fragment is not allowed`,
		},
		{
			name: "batch_credential_issuance batch_size <= 1",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
				BatchCredentialIssuance: &metadata.BatchCredentialIssuance{
					BatchSize: 1,
				},
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "'batch_size' in 'batch_credential_issuance' must be > 1",
		},
		{
			name: "valid batch_credential_issuance batch_size (>1)",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
				BatchCredentialIssuance: &metadata.BatchCredentialIssuance{
					BatchSize: 2,
				},
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "",
		},
		{
			name: "valid metadata",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := CredentialIssuerMetadataValidator{
				allowInsecureHttp: tt.allowInsecureHttp,
			}
			err := validator.Verify(tt.metadata)
			if tt.wantErr == "" && err != nil {
				t.Errorf("Verify() unexpected error: %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("Verify() expected error %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("Verify() expected error %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}

func TestCredentialIssuerMetadata_ValidateAgainstCredentialOffer(t *testing.T) {
	validCredentialConfig := metadata.CredentialConfiguration{
		Format:                              metadata.CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []any{"ES256"},
		CredentialMetadata: &metadata.CredentialMetadata{
			Display: []metadata.CredentialDisplay{
				{
					Name:   "Test Credential",
					Locale: &locale_EN,
				},
			},
		},
	}
	validCredentialOffer := &CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIds: []string{"test"},
	}

	tests := []struct {
		name     string
		metadata metadata.CredentialIssuerMetadata
		offer    *CredentialOffer
		wantErr  string
	}{
		{
			name: "credential_issuer mismatch with credential offer",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://mismatched-issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			offer:   validCredentialOffer,
			wantErr: "'credential_issuer' in metadata does not match 'credential_issuer' from the credential offer",
		},
		{
			name: "credential offer mismatch against metadata",
			metadata: metadata.CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"test": validCredentialConfig},
			},
			offer: &CredentialOffer{
				CredentialIssuer:           "https://issuer.example.com",
				CredentialConfigurationIds: []string{"unavailable"},
			},
			wantErr: `unsupported credential configuration "unavailable" in credential offer`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := CredentialIssuerMetadataValidator{
				allowInsecureHttp: false,
			}
			err := validator.ValidateAgainstCredentialOffer(&tt.metadata, tt.offer)
			if tt.wantErr == "" && err != nil {
				t.Errorf("Verify() unexpected error: %v", err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Errorf("Verify() expected error %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("Verify() expected error %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}

func TestCredentialConfiguration_Verify(t *testing.T) {
	validConfiguration := metadata.CredentialConfiguration{
		Format: metadata.CredentialFormatIdentifier_SdJwtVc,
		CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{
			proofs.CryptographicBindingMethod_JWK,
		},
		ProofTypesSupported:      map[metadata.ProofTypeIdentifier]metadata.ProofType{metadata.ProofTypeIdentifier_JWT: {ProofSigningAlgValuesSupported: []string{"test"}}},
		VerifiableCredentialType: "https://issuer.example.com/credential/my-type",
	}

	tests := []struct {
		name        string
		config      metadata.CredentialConfiguration
		wantErr     bool
		expectedErr string
	}{
		{
			name: "cryptographic_binding_methods_supported present, missing 'proof_types_supported'",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_SdJwtVc,
				CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{
					proofs.CryptographicBindingMethod_JWK,
				},
			},
			wantErr:     true,
			expectedErr: "missing 'proof_types_supported' while cryptographic binding methods are present",
		},
		{
			name:    "valid credential configuration",
			config:  validConfiguration,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := CredentialConfigurationValidator{}
			err := validator.Verify(&tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Verify() expected error, got nil")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Verify() error = %q, want %q", err.Error(), tt.expectedErr)
				}
			} else {
				if err != nil {
					t.Errorf("Verify() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCredentialConfiguration_ValidateAndGetSupportedFeatures(t *testing.T) {
	validFullConfiguration := metadata.CredentialConfiguration{
		Format: metadata.CredentialFormatIdentifier_SdJwtVc,
		Scope:  &scope,
		CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{
			proofs.CryptographicBindingMethod_JWK,
		},
		CredentialSigningAlgValuesSupported: []any{"ES256"},
		ProofTypesSupported: map[metadata.ProofTypeIdentifier]metadata.ProofType{
			metadata.ProofTypeIdentifier_JWT: {
				ProofSigningAlgValuesSupported: []string{"ES256"},
			},
		},
	}

	unsupportedCredentialConfig := metadata.CredentialConfiguration{
		Format: metadata.CredentialFormatIdentifier_W3CVC,
		Scope:  &scope,
	}

	tests := []struct {
		name        string
		config      metadata.CredentialConfiguration
		wantErr     bool
		expectedErr string
	}{
		{
			name:        "unsupported credential format",
			config:      unsupportedCredentialConfig,
			wantErr:     true,
			expectedErr: `unsupported credential format "jwt_vc_json"`,
		},
		{
			name: "credential signing algorithms can be nil",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:  &scope,
			},
			wantErr: false,
		},
		{
			name: "mso_mdoc is a supported format",
			config: metadata.CredentialConfiguration{
				Format:  metadata.CredentialFormatIdentifier_MsoMdoc,
				Doctype: "eu.europa.ec.av.1",
				Scope:   &scope,
			},
			wantErr: false,
		},
		{
			name: "credential signing algorithms can be empty",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{},
			},
			wantErr: false,
		},
		// OID4VCI types credential_signing_alg_values_supported per format: COSE
		// algorithm identifiers as integers for mso_mdoc, JWS algorithm names as
		// strings for dc+sd-jwt. Reading mdoc's integers as strings rejected every
		// mdoc configuration here, before any network call.
		{
			name: "mso_mdoc COSE ES256 identifier as float64, the shape encoding/json produces",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{float64(-7)},
			},
			wantErr: false,
		},
		{
			name: "mso_mdoc COSE ES256 identifier as int",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{-7},
			},
			wantErr: false,
		},
		{
			name: "mso_mdoc with several COSE identifiers, one of them ES256",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{float64(-8), float64(-7)},
			},
			wantErr: false,
		},
		// An mso_mdoc offer can miss in two distinct ways, and the error says
		// which: it advertises an algorithm ISO 18013-5 permits (-7 ES256, -8
		// EdDSA, -35 ES384, -36 ES512) that this wallet has yet to implement, or
		// it advertises nothing 18013-5 permits for an MSO at all. Both are
		// refused here, before any token or credential request.
		{
			name: "mso_mdoc advertising EdDSA, permitted by 18013-5 but not verifiable here",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{float64(-8)},
			},
			wantErr:     true,
			expectedErr: "no supported signing algorithms in 'credential_signing_alg_values_supported': [-8] is permitted by ISO 18013-5 but this wallet verifies only [-7 -35 -36]",
		},
		{
			// ES384 and ES512 became verifiable when the mdoc verifier started reading
			// alg from the COSE protected header. Turning such an offer away here would
			// refuse a credential the wallet can now check.
			name: "mso_mdoc advertising only ES384",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{float64(-35)},
			},
			wantErr: false,
		},
		{
			name: "mso_mdoc advertising ES384 and ES512, both verifiable",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{float64(-35), float64(-36)},
			},
			wantErr: false,
		},
		{
			name: "mso_mdoc mixing a disallowed identifier with an allowed one",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:  &scope,
				// -257 is RS256, which 18013-5 does not permit for the MSO.
				CredentialSigningAlgValuesSupported: []any{float64(-257), float64(-7)},
			},
			wantErr: false,
		},
		{
			name: "mso_mdoc advertising only identifiers 18013-5 does not permit",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:  &scope,
				// -257 is RS256, -37 is PS256; neither may sign an MSO.
				CredentialSigningAlgValuesSupported: []any{float64(-257), float64(-37)},
			},
			wantErr:     true,
			expectedErr: "no allowed signing algorithms in 'credential_signing_alg_values_supported': mso_mdoc advertises COSE algorithm identifiers and ISO 18013-5 permits only [-7 -8 -35 -36], got [-257 -37]",
		},
		{
			name: "mso_mdoc advertising a JWS string instead of a COSE identifier",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{"ES256"},
			},
			wantErr:     true,
			expectedErr: "no allowed signing algorithms in 'credential_signing_alg_values_supported': mso_mdoc advertises COSE algorithm identifiers and ISO 18013-5 permits only [-7 -8 -35 -36], got [ES256]",
		},
		{
			name: "mso_mdoc with a non-integral number, which is not an identifier",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{-7.5},
			},
			wantErr:     true,
			expectedErr: "no allowed signing algorithms in 'credential_signing_alg_values_supported': mso_mdoc advertises COSE algorithm identifiers and ISO 18013-5 permits only [-7 -8 -35 -36], got [-7.5]",
		},
		{
			name: "mso_mdoc credential signing algorithms can be empty",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_MsoMdoc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{},
			},
			wantErr: false,
		},
		{
			name: "dc+sd-jwt still rejects a COSE integer, which is the wrong shape for it",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{float64(-7)},
			},
			wantErr: true,
			// The dc+sd-jwt path defers to getSupportedCredentialSigningAlgorithm,
			// so this is that helper's wording rather than the mdoc branch's.
			expectedErr: "no supported credential signing algorithms found",
		},
		{
			name: "single credential signing algorithm - unsupported",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{"invalid-alg"},
			},
			wantErr:     true,
			expectedErr: "no supported credential signing algorithms found",
		},
		{
			name: "single credential signing algorithm - supported",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{"ES256"},
			},
			wantErr: false,
		},
		{
			name: "multiple credential signing algorithms - at least one supported",
			config: metadata.CredentialConfiguration{
				Format:                              metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:                               &scope,
				CredentialSigningAlgValuesSupported: []any{"ES256", "invalid-alg"},
			},
			wantErr: false,
		},
		{
			name: "unsupported cryptographic binding method",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:  &scope,
				CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{
					proofs.CryptographicBindingMethod_COSE,
				},
			},
			wantErr:     true,
			expectedErr: `no supported cryptographic binding method found in 'cryptographic_binding_methods_supported'`,
		},
		{
			name: "cryptographic binding method present, no proof type supported present",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:  &scope,
				CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{
					proofs.CryptographicBindingMethod_JWK,
				},
			},
			wantErr:     true,
			expectedErr: `no supported proof-type found in 'proof_types_supported'`,
		},
		{
			name: "cryptographic binding method present, no proof type JWT available",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:  &scope,
				CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{
					proofs.CryptographicBindingMethod_JWK,
				},
				ProofTypesSupported: map[metadata.ProofTypeIdentifier]metadata.ProofType{
					metadata.ProofTypeIdentifier_DIVP: {
						ProofSigningAlgValuesSupported: []string{"ES256"},
					},
				},
			},
			wantErr:     true,
			expectedErr: `no supported proof-type found in 'proof_types_supported'`,
		},
		{
			name: "cryptographic binding method present, proof type JWT, unsupported proof signing algorithms",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:  &scope,
				CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{
					proofs.CryptographicBindingMethod_JWK,
				},
				ProofTypesSupported: map[metadata.ProofTypeIdentifier]metadata.ProofType{
					metadata.ProofTypeIdentifier_JWT: {
						ProofSigningAlgValuesSupported: []string{"invalid-alg"},
					},
				},
			},
			wantErr:     true,
			expectedErr: "no supported proof signing algorithm found, only 'ES256' is supported",
		},
		{
			name: "cryptographic binding method present, proof type JWT, multiple proof signing algorithms, at least one supported",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:  &scope,
				CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{
					proofs.CryptographicBindingMethod_JWK,
				},
				ProofTypesSupported: map[metadata.ProofTypeIdentifier]metadata.ProofType{
					metadata.ProofTypeIdentifier_JWT: {
						ProofSigningAlgValuesSupported: []string{"ES256", "invalid-alg"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "cryptographic binding method present, proof type JWT, key attestations required - unsupported",
			config: metadata.CredentialConfiguration{
				Format: metadata.CredentialFormatIdentifier_SdJwtVc,
				Scope:  &scope,
				CryptographicBindingMethodsSupported: []proofs.CryptographicBindingMethod{
					proofs.CryptographicBindingMethod_JWK,
				},
				ProofTypesSupported: map[metadata.ProofTypeIdentifier]metadata.ProofType{
					metadata.ProofTypeIdentifier_JWT: {
						ProofSigningAlgValuesSupported: []string{"ES256"},
						KeyAttestationsRequired: &metadata.KeyAttestationRequirement{
							KeyStorage:         []metadata.AttestationAttackResistance{metadata.Iso18045_Basic},
							UserAuthentication: []metadata.AttestationAttackResistance{metadata.Iso18045_Basic},
						},
					},
				},
			},
			wantErr:     true,
			expectedErr: `unsupported 'key_attestations_required' in 'proof_types_supported' for JWT proof type`,
		},
		{
			name:    "valid credential configuration",
			config:  validFullConfiguration,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := CredentialConfigurationValidator{}
			_, err := validator.ValidateAndGetSupportedFeatures(&tt.config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateAndGetSupportedFeatures() expected error, got nil")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("ValidateAndGetSupportedFeatures() error = %q, want %q", err.Error(), tt.expectedErr)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateAndGetSupportedFeatures() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCredentialDisplays_verify(t *testing.T) {
	tests := []struct {
		name        string
		displays    metadata.CredentialDisplays
		wantErr     bool
		expectedErr string
	}{
		{
			name: "valid single display",
			displays: metadata.CredentialDisplays{
				{
					Name:   "Credential Name",
					Locale: &locale_EN,
				},
			},
			wantErr: false,
		},
		{
			name: "valid single display, extended locale",
			displays: metadata.CredentialDisplays{
				{
					Name:   "Credential Name",
					Locale: &locale_EN_US,
				},
			},
			wantErr: false,
		},
		{
			name: "missing name in display",
			displays: metadata.CredentialDisplays{
				{
					Name:   "",
					Locale: &locale_EN,
				},
			},
			wantErr:     true,
			expectedErr: "missing 'name'",
		},
		{
			name: "display without locale, should be ignored",
			displays: metadata.CredentialDisplays{
				{
					Name:   "Issuer Name",
					Locale: nil,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid logo uri",
			displays: metadata.CredentialDisplays{
				{
					Name:   "Credential Name",
					Locale: &locale_EN,
					Logo: &metadata.RemoteImage{
						Uri: "://invalid-url",
					},
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'logo': invalid 'uri': parse \"://invalid-url\": missing protocol scheme",
		},
		{
			name: "invalid background image uri",
			displays: metadata.CredentialDisplays{
				{
					Name:   "Credential Name",
					Locale: &locale_EN,
					BackgroundImage: &metadata.RemoteImage{
						Uri: "://invalid-url",
					},
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'background_image': invalid 'uri': parse \"://invalid-url\": missing protocol scheme",
		},
		{
			name: "duplicate locale",
			displays: metadata.CredentialDisplays{
				{
					Name:   "Credential Name",
					Locale: &locale_EN,
				},
				{
					Name:   "Another Name",
					Locale: &locale_EN,
				},
			},
			wantErr:     true,
			expectedErr: "duplicate 'locale' tag \"en\" in 'display' item with name \"Credential Name\"",
		},
		{
			name: "invalid locale tag",
			displays: metadata.CredentialDisplays{
				{
					Name:   "Credential Name",
					Locale: &invalid_Locale,
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'locale' tag \"invalid_locale\" in 'display' item with name \"Credential Name\": language: tag is not well-formed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := CredentialDisplaysValidator{}
			err := validator.verify(tt.displays)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestCredentialIssuerDisplay_UnmarshalJSON_HandleBackwardsCompatibilityUrl(t *testing.T) {
	input := `{
		"name": "Issuer Name",
		"locale": "en",
		"logo": {
			"url": "https://example.com/logo.png"
		}
	}`

	var display metadata.CredentialIssuerDisplay
	err := json.Unmarshal([]byte(input), &display)

	require.NoError(t, err)
	require.NotEmpty(t, display.Name)
	require.NotEmpty(t, display.Locale)
	require.NotNil(t, display.Logo)
	require.Equal(t, "https://example.com/logo.png", display.Logo.Uri)
}

func TestCredentialIssuerDisplays_verify(t *testing.T) {
	tests := []struct {
		name        string
		displays    metadata.CredentialIssuerDisplays
		wantErr     bool
		expectedErr string
	}{
		{
			name: "valid single display",
			displays: metadata.CredentialIssuerDisplays{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN,
				},
			},
			wantErr: false,
		},
		{
			name: "valid display with logo",
			displays: metadata.CredentialIssuerDisplays{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN,
					Logo: &metadata.RemoteImage{
						Uri: "https://example.com/logo.png",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid logo uri",
			displays: metadata.CredentialIssuerDisplays{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN,
					Logo: &metadata.RemoteImage{
						Uri: "://invalid-url",
					},
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'logo' in 'display': invalid 'uri': parse \"://invalid-url\": missing protocol scheme",
		},
		{
			name: "duplicate locale",
			displays: metadata.CredentialIssuerDisplays{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN,
				},
				{
					Name:   "Another Name",
					Locale: &locale_EN,
				},
			},
			wantErr:     true,
			expectedErr: "duplicate 'locale' tag \"en\" in 'display' item with name \"Issuer Name\"",
		},
		{
			name: "invalid locale tag",
			displays: metadata.CredentialIssuerDisplays{
				{
					Name:   "Issuer Name",
					Locale: &invalid_Locale,
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'locale' tag \"invalid_locale\" in 'display' item with name \"Issuer Name\": language: tag is not well-formed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := CredentialIssuerDisplaysValidator{}
			err := validator.verify(tt.displays)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
		})
	}
}

func TestIsValidCSSColorLevel3(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		// Hexadecimal colors
		{"#fff", true},
		{"#FFF", true},
		{"#123", true},
		{"#abcd", true},
		{"#ABCD", true},
		{"#123456", true},
		{"#abcdef", true},
		{"#ABCDEF", true},
		{"#12345678", true},
		{"#87654321", true},
		// Invalid hex
		{"#12", false},
		{"#12345", false},
		{"#1234567", false},
		{"#123456789", false},
		{"#ggg", false},
		{"#12g", false},
		{"123456", false},
		// rgb()
		{"rgb(255,255,255)", true},
		{"rgb(0, 0, 0)", true},
		{"rgb(100%, 0%, 0%)", true},
		{"rgb(  12 , 34 , 56 )", true},
		// Invalid rgb
		{"rgb(256,0,0)", false},
		{"rgb(0,256,0)", false},
		{"rgb(0,0,256)", false},
		{"rgb(0,0)", false},
		{"rgb(0,0,0,0)", false},
		{"rgb(0 0 0)", false},
		// rgba()
		{"rgba(255,255,255,1)", true},
		{"rgba(0,0,0,0)", true},
		{"rgba(100%,0%,0%,0.5)", true},
		{"rgba(12,34,56,0.75)", true},
		{"rgba(12,34,56,1.0)", true},
		// Invalid rgba
		{"rgba(0,0,0)", false},
		{"rgba(0,0,0,0,0)", false},
		{"rgba(0,0,0,2)", false},
		{"rgba(256,0,0,0)", false},
		{"rgba(0,256,0,0)", false},
		{"rgba(0,0,256,0)", false},
		// hsl()
		{"hsl(120,100%,50%)", true},
		{"hsl(0, 0%, 0%)", true},
		{"hsl(360,100%,100%)", true},
		{"hsl(  12 , 34% , 56% )", true},
		// Invalid hsl
		{"hsl(120,100,50)", false},
		{"hsl(120,100%,50%,0.5)", false},
		{"hsl(120,100%)", false},
		// hsla()
		{"hsla(120,100%,50%,1)", true},
		{"hsla(0,0%,0%,0)", true},
		{"hsla(360,100%,100%,0.5)", true},
		{"hsla(  12 , 34% , 56% , 0.75 )", true},
		// Invalid hsla
		{"hsla(120,100%,50%)", false},
		{"hsla(120,100%,50%,1,0)", false},
		// Whitespace and case
		{"  #fff  ", true},
		{"RGB(255,255,255)", false}, // case-sensitive
		// Completely invalid
		{"red", false},
		{"", false},
		{"#", false},
		{"notacolor", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isValidCSSColorLevel3(tt.input)
			if got != tt.expected {
				t.Errorf("isValidCSSColorLevel3(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestCredentialRequestEncryption_UnmarshalJSON_Success(t *testing.T) {
	input := `{
		"jwks": {
			"keys": [
				{
					"kty": "EC",
					"use": "enc",
					"crv": "P-256",
					"kid": "ccc9cfac-4b29-4931-a3cf-f95c8be9604e",
					"x": "zgxTur31IjFQBYQICLQIOvwhzoK7mkxl-UydEQVim3g",
					"y": "wSgkFI20hVrVbQ23GAtN_qRpd37S4quy2OAIuT6Paww",
					"alg": "ECDH-ES"
				}
			]
		},
		"enc_values_supported": [ "A128GCM" ],
		"zip_values_supported": [ "DEF" ],
		"encryption_required": true
	}`

	var creqEnc metadata.CredentialRequestEncryption
	err := json.Unmarshal([]byte(input), &creqEnc)

	require.NoError(t, err)
	require.NotNil(t, creqEnc.Jwks)
	require.Equal(t, []string{"A128GCM"}, creqEnc.EncValuesSupported)
	require.Equal(t, []string{"DEF"}, creqEnc.ZipValuesSupported)
	require.Equal(t, true, creqEnc.EncryptionRequired)
}

func TestGetSupportedCredentialSigningAlgorithm_Success(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  jwa.SignatureAlgorithm
	}{
		{
			name:  "valid algorithms",
			input: []string{"ES256"},
			want:  jwa.ES256(),
		},
		{
			name:  "multiple valid algorithms, should return ES512",
			input: []string{"ES512", "ES384", "PS512", "PS384", "ES256", "PS256", "ES256K"},
			want:  jwa.ES512(),
		},
		{
			name:  "multiple valid algorithms, should return ES384",
			input: []string{"ES384", "PS512", "PS384", "ES256", "PS256", "ES256K"},
			want:  jwa.ES384(),
		},
		{
			name:  "multiple valid algorithms, should return PS512",
			input: []string{"PS512", "PS384", "ES256", "PS256", "ES256K"},
			want:  jwa.PS512(),
		},
		{
			name:  "multiple valid algorithms, should return PS384",
			input: []string{"PS384", "ES256", "PS256", "ES256K"},
			want:  jwa.PS384(),
		},
		{
			name:  "multiple valid algorithms, should return ES256",
			input: []string{"ES256", "PS256", "ES256K"},
			want:  jwa.ES256(),
		},
		{
			name:  "multiple valid algorithms, should return PS256",
			input: []string{"PS256", "ES256K"},
			want:  jwa.PS256(),
		},
		{
			name:  "a rejected algorithm is skipped in favour of a usable one",
			input: []string{"HS256", "ES256", "RS256"},
			want:  jwa.ES256(),
		},
		{
			name:  "EdDSA is accepted",
			input: []string{"EdDSA"},
			want:  jwa.EdDSA(),
		},
		{
			name:  "Ed25519 is accepted",
			input: []string{"Ed25519"},
			want:  jwa.EdDSAEd25519(),
		},
		{
			name:  "mix of valid and invalid",
			input: []string{"ES256", "NOT_AN_ALG"},
			want:  jwa.ES256(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getSupportedCredentialSigningAlgorithm(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.want, *got)
		})
	}
}

// TestValidateAndGetSupportedFeatures_EudiReferenceAgeVerificationMdoc runs the
// validator against the credential configuration the EUDI reference issuer
// actually serves for the AV Blueprint's Proof of Age attestation, copied
// verbatim from age_verification_mdoc.json in
// ghcr.io/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py:0.9.4.
//
// It is decoded from JSON rather than built as Go literals on purpose: the bug
// this pins was entirely about the Go type a JSON number decodes to, so a test
// constructing []any{-7} by hand would have passed while the real thing failed.
//
// This is the configuration an mdoc integration test would request, so if this
// stops validating, mdoc issuance is broken again.
func TestValidateAndGetSupportedFeatures_EudiReferenceAgeVerificationMdoc(t *testing.T) {
	const eudiAgeVerificationMdoc = `{
		"format": "mso_mdoc",
		"doctype": "eu.europa.ec.av.1",
		"scope": "eu.europa.ec.eudi.age_verification_mdoc",
		"cryptographic_binding_methods_supported": ["jwk", "cose_key"],
		"credential_signing_alg_values_supported": [-7],
		"proof_types_supported": {
			"jwt": { "proof_signing_alg_values_supported": ["ES256"] }
		}
	}`

	var config metadata.CredentialConfiguration
	require.NoError(t, json.Unmarshal([]byte(eudiAgeVerificationMdoc), &config))

	// Guard the premise: -7 must have landed as a float64, the way
	// encoding/json decodes every JSON number into `any`.
	require.Len(t, config.CredentialSigningAlgValuesSupported, 1)
	require.IsType(t, float64(0), config.CredentialSigningAlgValuesSupported[0],
		"a JSON number decodes into any as float64; the validator has to cope with that")

	validator := CredentialConfigurationValidator{}
	prefs, err := validator.ValidateAndGetSupportedFeatures(&config)
	require.NoError(t, err,
		"the EUDI reference issuer's Proof of Age configuration must validate")
	require.NotNil(t, prefs)
}

func TestGetSupportedCredentialSigningAlgorithm_Failure(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		wantErr error
	}{
		{
			name:    "empty input",
			input:   []string{},
			wantErr: errors.New("no supported credential signing algorithms found"),
		},
		{
			name:    "unknown algorithm is excluded",
			input:   []string{"NOT_AN_ALG"},
			wantErr: errors.New("no supported credential signing algorithms found"),
		},
		{
			name:    "reject symmetric algorithm HS256",
			input:   []string{"HS256"},
			wantErr: errors.New("no supported credential signing algorithms found"),
		},
		{
			name:    "reject symmetric algorithm HS384",
			input:   []string{"HS384"},
			wantErr: errors.New("no supported credential signing algorithms found"),
		},
		{
			name:    "reject symmetric algorithm HS512",
			input:   []string{"HS512"},
			wantErr: errors.New("no supported credential signing algorithms found"),
		},
		{
			name:    "reject 'none'",
			input:   []string{"none"},
			wantErr: errors.New("no supported credential signing algorithms found"),
		},
		{
			name:    "reject Ed448, which jwx does not register",
			input:   []string{"Ed448"},
			wantErr: errors.New("no supported credential signing algorithms found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getSupportedCredentialSigningAlgorithm(tt.input)
			require.Error(t, err)
			require.Equal(t, tt.wantErr, err)
		})
	}
}

// ES256K's availability depends on the jwx_es256k build tag (see eudi_jwt.SupportedSignatureAlgorithms).
// The validator must follow that, so a build which can verify secp256k1 signatures does not turn
// away an issuer offering them, and a build which cannot does not accept a credential
// configuration it would later fail to verify.
func TestGetSupportedCredentialSigningAlgorithm_ES256K_FollowsBuildTag(t *testing.T) {
	got, err := getSupportedCredentialSigningAlgorithm([]string{"ES256K"})

	if eudi_jwt.IsSupportedSignatureAlgorithm(jwa.NewSignatureAlgorithm("ES256K")) {
		require.NoError(t, err)
		require.Equal(t, jwa.NewSignatureAlgorithm("ES256K"), *got)
		return
	}

	require.EqualError(t, err, "no supported credential signing algorithms found")
}

// TestMdocFormatVerifierRequiresDoctype pins the field that makes the docType
// consistency check in session.obtainCredential possible.
//
// doctype is REQUIRED for mso_mdoc by OpenID4VCI's credential format profile,
// but until it was parsed at all an issuer could advertise one docType and sign
// another with nothing to compare against — see the check in
// session.obtainCredential. Accepting a configuration without it would silently
// restore that.
func TestMdocFormatVerifierRequiresDoctype(t *testing.T) {
	verifier := MdocFormatVerifier{}

	t.Run("a configuration without doctype is rejected", func(t *testing.T) {
		err := verifier.Verify(&metadata.CredentialConfiguration{
			Format: metadata.CredentialFormatIdentifier_MsoMdoc,
		})
		require.Error(t, err, "mso_mdoc without doctype must not validate")
		require.Contains(t, err.Error(), "doctype",
			"the rejection has to name the missing field: it is the issuer, not the wallet, that has to act on it")
	})

	t.Run("a custom doctype is accepted", func(t *testing.T) {
		// Nothing here is an allowlist: the check is that the issuer declared a
		// docType, not that it declared one of ours. A Yivi-minted docType has
		// to validate exactly as an EU one does, or the wallet is limited to
		// doctypes someone hardcoded.
		require.NoError(t, verifier.Verify(&metadata.CredentialConfiguration{
			Format:  metadata.CredentialFormatIdentifier_MsoMdoc,
			Doctype: "nl.yivi.email.1",
		}))
	})

	t.Run("doctype is not required of other formats", func(t *testing.T) {
		validator := CredentialConfigurationValidator{}
		require.NoError(t, validator.Verify(&metadata.CredentialConfiguration{
			Format:                   metadata.CredentialFormatIdentifier_SdJwtVc,
			VerifiableCredentialType: "https://issuer.example.com/credential/my-type",
		}), "dc+sd-jwt names its type with vct; requiring doctype of it would reject every SD-JWT issuer")
	})
}

// TestCredentialConfigurationDoctypeRoundTrips guards the wiring rather than the
// policy: CredentialConfiguration has a custom UnmarshalJSON, so a new field
// reaches it only through the embedded alias type.
func TestCredentialConfigurationDoctypeRoundTrips(t *testing.T) {
	const emailMdoc = `{
		"format": "mso_mdoc",
		"doctype": "nl.yivi.email.1",
		"credential_signing_alg_values_supported": [-7],
		"credential_metadata": {
			"claims": [{ "path": ["nl.yivi.email.1", "email"] }]
		}
	}`

	var config metadata.CredentialConfiguration
	require.NoError(t, json.Unmarshal([]byte(emailMdoc), &config))
	require.Equal(t, "nl.yivi.email.1", config.Doctype,
		"doctype has to survive the custom UnmarshalJSON, or the check downstream compares against an empty string")

	validator := CredentialConfigurationValidator{}
	_, err := validator.ValidateAndGetSupportedFeatures(&config)
	require.NoError(t, err, "a non-EU mdoc configuration must validate")
}

// TestRequireMandatoryMdocElements covers the check that refuses an mdoc missing
// an element the issuer's own metadata marks mandatory.
//
// The motivating case is age verification: eu.europa.ec.av.1 marks age_over_18
// mandatory and every other age_over_NN optional, so a credential without
// age_over_18 is an age attestation that attests no age. The check is written
// against the metadata rather than the docType, so these cases also pin that a
// non-AV docType gets the same treatment from the same code.
func TestRequireMandatoryMdocElements(t *testing.T) {
	mandatory := true
	optional := false

	avConfig := func() *metadata.CredentialConfiguration {
		return &metadata.CredentialConfiguration{
			Format:  metadata.CredentialFormatIdentifier_MsoMdoc,
			Doctype: "eu.europa.ec.av.1",
			CredentialMetadata: &metadata.CredentialMetadata{
				Claims: []metadata.ClaimsDescription{
					{Path: metadata.ClaimsPathPointer{"eu.europa.ec.av.1", "age_over_18"}, Mandatory: &mandatory},
					{Path: metadata.ClaimsPathPointer{"eu.europa.ec.av.1", "age_over_65"}, Mandatory: &optional},
				},
			},
		}
	}
	credentialWith := func(t *testing.T, elements map[string]any) *services.ParsedCredential {
		t.Helper()
		return &services.ParsedCredential{Mdoc: &services.ParsedMdoc{
			DocType:    "eu.europa.ec.av.1",
			Namespaces: models.MdocNamespaces{"eu.europa.ec.av.1": elements},
		}}
	}

	t.Run("an AV credential without age_over_18 is refused", func(t *testing.T) {
		err := requireMandatoryMdocElements(avConfig(), credentialWith(t, map[string]any{
			"age_over_65": false,
		}))
		require.Error(t, err, "an age attestation missing its mandatory element must not be stored")
		require.Contains(t, err.Error(), "age_over_18",
			"the refusal has to name the missing element: it is the issuer that has to act on it")
	})

	t.Run("age_over_18 present is enough; optional thresholds may be absent", func(t *testing.T) {
		require.NoError(t, requireMandatoryMdocElements(avConfig(), credentialWith(t, map[string]any{
			"age_over_18": true,
		})), "every other age_over_NN is optional, so a credential carrying only the mandatory one is valid")
	})

	t.Run("a mandatory element present but false still satisfies the check", func(t *testing.T) {
		// Presence, not truthiness: age_over_18=false is a meaningful assertion
		// about the holder, not a missing claim.
		require.NoError(t, requireMandatoryMdocElements(avConfig(), credentialWith(t, map[string]any{
			"age_over_18": false,
		})))
	})

	t.Run("an issuer publishing no mandatory claims is unaffected", func(t *testing.T) {
		config := avConfig()
		for i := range config.CredentialMetadata.Claims {
			config.CredentialMetadata.Claims[i].Mandatory = nil
		}
		require.NoError(t, requireMandatoryMdocElements(config, credentialWith(t, map[string]any{})),
			"mandatory defaults to false, so this must reject nothing an issuer did not first promise")
	})

	t.Run("a namespace-less claim path is not guessed at", func(t *testing.T) {
		// A one-component path names an element but not where it lives. Guessing
		// the namespace and guessing wrong would reject a valid credential, so
		// such a path is skipped rather than enforced.
		config := avConfig()
		config.CredentialMetadata.Claims[0].Path = metadata.ClaimsPathPointer{"age_over_18"}
		require.NoError(t, requireMandatoryMdocElements(config, credentialWith(t, map[string]any{})))
	})

	t.Run("dc+sd-jwt is left alone", func(t *testing.T) {
		config := avConfig()
		config.Format = metadata.CredentialFormatIdentifier_SdJwtVc
		require.NoError(t, requireMandatoryMdocElements(config, credentialWith(t, map[string]any{})),
			"an SD-JWT payload is not a namespace map; this check does not apply to it")
	})

	t.Run("the rule is not AV-specific", func(t *testing.T) {
		config := &metadata.CredentialConfiguration{
			Format:  metadata.CredentialFormatIdentifier_MsoMdoc,
			Doctype: "nl.yivi.email.1",
			CredentialMetadata: &metadata.CredentialMetadata{
				Claims: []metadata.ClaimsDescription{
					{Path: metadata.ClaimsPathPointer{"nl.yivi.email.1", "email"}, Mandatory: &mandatory},
				},
			},
		}
		err := requireMandatoryMdocElements(config, &services.ParsedCredential{Mdoc: &services.ParsedMdoc{
			DocType:    "nl.yivi.email.1",
			Namespaces: models.MdocNamespaces{"nl.yivi.email.1": {"domain": "example.com"}},
		}})
		require.Error(t, err, "the check reads the metadata, so it covers any docType")
		require.Contains(t, err.Error(), "email")
	})
}

// The docType inside the MSO is signed by the issuer, so on its own it says only
// "this is what I sent". Binding it to the advertised doctype is what turns it
// into "this is what I asked for" -- and the value is load-bearing: it becomes
// the credential's type, which DCQL doctype_value matching and relying-party
// authorization both key off.
//
// Unit-tested rather than driven through the container on purpose: the EUDI
// reference issuer calls mdocFormatter with doctype=credential_metadata["doctype"],
// the same field it advertises, so the two cannot disagree there however the
// bind-mounted configuration is edited (measured 2026-08-31). A mismatch has to
// be built here.
func TestRequireMdocDocTypeMatchesMetadata(t *testing.T) {
	mdocConfig := func(doctype string) *metadata.CredentialConfiguration {
		return &metadata.CredentialConfiguration{
			Format:  metadata.CredentialFormatIdentifier_MsoMdoc,
			Doctype: doctype,
		}
	}
	signedAs := func(docType string) *services.ParsedCredential {
		return &services.ParsedCredential{VerifiableCredentialType: docType}
	}

	t.Run("a matching docType is accepted", func(t *testing.T) {
		require.NoError(t, requireMdocDocTypeMatchesMetadata(
			mdocConfig("eu.europa.ec.av.1"), signedAs("eu.europa.ec.av.1")))
	})

	t.Run("a different docType is refused", func(t *testing.T) {
		err := requireMdocDocTypeMatchesMetadata(
			mdocConfig("eu.europa.ec.av.1"), signedAs("org.iso.18013.5.1.mDL"))
		require.Error(t, err,
			"an issuer answering a request for one docType with another must not be stored")
		require.Contains(t, err.Error(), "org.iso.18013.5.1.mDL", "the refusal must name what was signed")
		require.Contains(t, err.Error(), "eu.europa.ec.av.1", "and what was advertised")
	})

	t.Run("a configuration declaring no doctype refuses everything", func(t *testing.T) {
		// MdocFormatVerifier already rejects such a configuration at metadata
		// validation, so this never runs in practice -- but failing closed is the
		// right behaviour if that gate is ever relaxed: an empty expectation must
		// not silently match every docType.
		require.Error(t, requireMdocDocTypeMatchesMetadata(
			mdocConfig(""), signedAs("eu.europa.ec.av.1")))
	})

	t.Run("dc+sd-jwt is untouched", func(t *testing.T) {
		// Doctype is empty for SD-JWT VC, whose cross-instance vct consistency
		// check lives in storeCredentials. Applying this one would reject every
		// SD-JWT credential.
		config := &metadata.CredentialConfiguration{
			Format:                   metadata.CredentialFormatIdentifier_SdJwtVc,
			VerifiableCredentialType: "urn:eudi:pid:1",
		}
		require.NoError(t, requireMdocDocTypeMatchesMetadata(
			config, &services.ParsedCredential{VerifiableCredentialType: "urn:eudi:pid:1"}))
	})
}
