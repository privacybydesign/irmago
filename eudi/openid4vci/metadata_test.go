package openid4vci

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateCredentialConfiguration_SupportedFormats(t *testing.T) {
	tests := []struct {
		name    string
		format  CredentialFormatIdentifier
		wantErr bool
	}{
		{"W3CVC", CredentialFormatIdentifier_W3CVC, false},
		{"W3CVCLD", CredentialFormatIdentifier_W3CVCLD, false},
		{"W3CVCLD_ProofSuite", CredentialFormatIdentifier_W3CVCLD_ProofSuite, false},
		{"MsoMdoc", CredentialFormatIdentifier_MsoMdoc, false},
		{"SdJwtVc", CredentialFormatIdentifier_SdJwtVc, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CredentialConfiguration{
				Format:                   tt.format,
				VerifiableCredentialType: "https://issuer.example.com/credential/my-type",
			}
			err := c.Verify()
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCredentialConfiguration_UnsupportedFormat(t *testing.T) {
	c := &CredentialConfiguration{
		Format: "unsupported_format",
	}
	err := c.Verify()
	if err == nil {
		t.Errorf("Expected error for unsupported format, got nil")
	}
	want := `unsupported credential format "unsupported_format"`
	if err.Error() != want {
		t.Errorf("Expected error %q, got %q", want, err.Error())
	}
}

func TestValidateCredentialConfiguration_SdJwtVc_InvalidCredentialMetadata(t *testing.T) {
	c := &CredentialConfiguration{
		Format:                              CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []string{"ES256"},
		CredentialMetadata: &CredentialMetadata{
			Display: []CredentialDisplay{
				{
					Display: Display{
						Name: "",
					},
				},
			},
		},
	}
	err := c.Verify()
	if err == nil {
		t.Errorf("Expected error for missing name in display, got nil")
	}
	if err != nil && err.Error() != "invalid 'credential_metadata': invalid 'display': missing 'name'" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestValidateCredentialConfiguration_SdJwtVc_ValidCredentialMetadata(t *testing.T) {
	c := &CredentialConfiguration{
		Format:                              CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []string{"ES256"},
		CredentialMetadata: &CredentialMetadata{
			Display: []CredentialDisplay{
				{
					Display: Display{
						Name:   "Test Credential",
						Locale: "en",
					},
				},
			},
		},
		VerifiableCredentialType: "https://issuer.example.com/credential/my-type",
	}
	err := c.Verify()
	if err != nil {
		t.Errorf("Expected no error for valid credential metadata, got %v", err)
	}
}

func TestCredentialIssuerMetadata_Verify(t *testing.T) {
	validCredentialConfig := CredentialConfiguration{
		Format:                              CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []string{"ES256"},
		CredentialMetadata: &CredentialMetadata{
			Display: []CredentialDisplay{
				{
					Display: Display{
						Name:   "Test Credential",
						Locale: "en",
					},
				},
			},
		},
		VerifiableCredentialType: "https://issuer.example.com/credential/my-type",
	}
	tests := []struct {
		name     string
		metadata CredentialIssuerMetadata
		offer    *CredentialOffer
		wantErr  string
	}{
		{
			name: "missing credential_issuer",
			metadata: CredentialIssuerMetadata{
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "missing 'credential_issuer'",
		},
		{
			name: "missing credential_endpoint",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "missing 'credential_endpoint'",
		},
		{
			name: "missing credential_configurations_supported",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
			},
			wantErr: "missing 'credential_configurations_supported'",
		},
		{
			name: "empty credential_configurations_supported",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{},
			},
			wantErr: "missing 'credential_configurations_supported'",
		},
		{
			name: "invalid authorization_server URL",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				AuthorizationServers:              []string{"://invalid-url"},
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'authorization_server' URL "://invalid-url"`,
		},
		{
			name: "invalid credential_endpoint URL",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "://invalid-url",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'credential_endpoint' URL "://invalid-url"`,
		},
		{
			name: "credential_endpoint with fragment",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential#frag",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'credential_endpoint' URL "https://issuer.example.com/credential#frag": fragment is not allowed`,
		},
		{
			name: "nonce_endpoint with fragment",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				NonceEndpoint:                     "https://issuer.example.com/nonce#frag",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'nonce_endpoint' URL "https://issuer.example.com/nonce#frag": fragment is not allowed`,
		},
		{
			name: "deferred_credential_endpoint with fragment",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				DeferredCredentialEndpoint:        "https://issuer.example.com/deferred#frag",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'deferred_credential_endpoint' URL "https://issuer.example.com/deferred#frag": fragment is not allowed`,
		},
		{
			name: "notification_endpoint with fragment",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				NotificationEndpoint:              "https://issuer.example.com/notify#frag",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: `invalid 'notification_endpoint' URL "https://issuer.example.com/notify#frag": fragment is not allowed`,
		},
		{
			name: "batch_credential_issuance batch_size <= 1",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
				BatchCredentialIssuance: &BatchCredentialIssuance{
					BatchSize: 1,
				},
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "'batch_size' in 'batch_credential_issuance' must be > 1",
		},
		{
			name: "valid batch_credential_issuance batch_size (>1)",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
				BatchCredentialIssuance: &BatchCredentialIssuance{
					BatchSize: 2,
				},
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "",
		},
		{
			name: "invalid credential configuration",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{
					"test": {
						Format: "invalid_format",
					},
				},
			},
			wantErr: `invalid credential configuration "test": unsupported credential format "invalid_format"`,
		},
		{
			name: "valid metadata",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.metadata.Verify()
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
	validCredentialConfig := CredentialConfiguration{
		Format:                              CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []string{"ES256"},
		CredentialMetadata: &CredentialMetadata{
			Display: []CredentialDisplay{
				{
					Display: Display{
						Name:   "Test Credential",
						Locale: "en",
					},
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
		metadata CredentialIssuerMetadata
		offer    *CredentialOffer
		wantErr  string
	}{
		{
			name: "credential_issuer mismatch with credential offer",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://mismatched-issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			offer:   validCredentialOffer,
			wantErr: "'credential_issuer' in metadata does not match 'credential_issuer' from the credential offer",
		},
		{
			name: "credential offer mismatch against metadata",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
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
			err := tt.metadata.ValidateAgainstCredentialOffer(tt.offer)
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
	validConfiguration := CredentialConfiguration{
		Format: CredentialFormatIdentifier_SdJwtVc,
		CryptographicBindingMethodsSupported: []CryptographicBindingMethod{
			CryptographicBindingMethod_JWK,
		},
		ProofTypesSupported:      map[ProofTypeIdentifier]ProofType{ProofTypeIdentifier_JWT: {ProofSigningAlgValuesSupported: []string{"test"}}},
		VerifiableCredentialType: "https://issuer.example.com/credential/my-type",
	}

	tests := []struct {
		name        string
		config      CredentialConfiguration
		wantErr     bool
		expectedErr string
	}{
		{
			name: "cryptographic_binding_methods_supported present, missing 'proof_types_supported'",
			config: CredentialConfiguration{
				Format: CredentialFormatIdentifier_SdJwtVc,
				CryptographicBindingMethodsSupported: []CryptographicBindingMethod{
					CryptographicBindingMethod_JWK,
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
			err := tt.config.Verify()
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

func TestCredentialConfiguration_ValidateSupportedFeatures(t *testing.T) {
	validFullConfiguration := CredentialConfiguration{
		Format: CredentialFormatIdentifier_SdJwtVc,
		CryptographicBindingMethodsSupported: []CryptographicBindingMethod{
			CryptographicBindingMethod_JWK,
		},
		CredentialSigningAlgValuesSupported: []string{"ES256"},
		ProofTypesSupported: map[ProofTypeIdentifier]ProofType{
			ProofTypeIdentifier_JWT: {
				ProofSigningAlgValuesSupported: []string{"ES256"},
			},
		},
	}

	unsupportedCredentialConfig := CredentialConfiguration{
		Format: CredentialFormatIdentifier_W3CVC,
	}

	tests := []struct {
		name        string
		config      CredentialConfiguration
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
			config: CredentialConfiguration{
				Format: CredentialFormatIdentifier_SdJwtVc,
			},
			wantErr: false,
		},
		{
			name: "credential signing algorithms can be empty",
			config: CredentialConfiguration{
				Format:                              CredentialFormatIdentifier_SdJwtVc,
				CredentialSigningAlgValuesSupported: []string{},
			},
			wantErr: false,
		},
		{
			name: "single credential signing algorithm - unsupported",
			config: CredentialConfiguration{
				Format:                              CredentialFormatIdentifier_SdJwtVc,
				CredentialSigningAlgValuesSupported: []string{"invalid-alg"},
			},
			wantErr:     true,
			expectedErr: "no supported signing algorithms in 'credential_signing_alg_values_supported'",
		},
		{
			name: "single credential signing algorithm - supported",
			config: CredentialConfiguration{
				Format:                              CredentialFormatIdentifier_SdJwtVc,
				CredentialSigningAlgValuesSupported: []string{"ES256"},
			},
			wantErr: false,
		},
		{
			name: "multiple credential signing algorithms - at least one supported",
			config: CredentialConfiguration{
				Format:                              CredentialFormatIdentifier_SdJwtVc,
				CredentialSigningAlgValuesSupported: []string{"ES256", "invalid-alg"},
			},
			wantErr: false,
		},
		{
			name: "unsupported cryptographic binding method",
			config: CredentialConfiguration{
				Format: CredentialFormatIdentifier_SdJwtVc,
				CryptographicBindingMethodsSupported: []CryptographicBindingMethod{
					CryptographicBindingMethod_COSE,
				},
			},
			wantErr:     true,
			expectedErr: `unsupported cryptographic binding method(s) ["cose_key"]`,
		},
		{
			name: "cryptographic binding method present, no proof type supported present",
			config: CredentialConfiguration{
				Format: CredentialFormatIdentifier_SdJwtVc,
				CryptographicBindingMethodsSupported: []CryptographicBindingMethod{
					CryptographicBindingMethod_JWK,
				},
			},
			wantErr:     true,
			expectedErr: `missing 'proof_types_supported' for JWT`,
		},
		{
			name: "cryptographic binding method present, no proof type JWT available",
			config: CredentialConfiguration{
				Format: CredentialFormatIdentifier_SdJwtVc,
				CryptographicBindingMethodsSupported: []CryptographicBindingMethod{
					CryptographicBindingMethod_JWK,
				},
				ProofTypesSupported: map[ProofTypeIdentifier]ProofType{
					ProofTypeIdentifier_DIVP: {
						ProofSigningAlgValuesSupported: []string{"ES256"},
					},
				},
			},
			wantErr:     true,
			expectedErr: `missing 'proof_types_supported' for JWT`,
		},
		{
			name: "cryptographic binding method present, proof type JWT, unsupported proof signing algorithms",
			config: CredentialConfiguration{
				Format: CredentialFormatIdentifier_SdJwtVc,
				CryptographicBindingMethodsSupported: []CryptographicBindingMethod{
					CryptographicBindingMethod_JWK,
				},
				ProofTypesSupported: map[ProofTypeIdentifier]ProofType{
					ProofTypeIdentifier_JWT: {
						ProofSigningAlgValuesSupported: []string{"invalid-alg"},
					},
				},
			},
			wantErr:     true,
			expectedErr: "no supported signing algorithms in 'proof_signing_alg_values_supported' for JWT proof type",
		},
		{
			name: "cryptographic binding method present, proof type JWT, multiple proof signing algorithms, at least one supported",
			config: CredentialConfiguration{
				Format: CredentialFormatIdentifier_SdJwtVc,
				CryptographicBindingMethodsSupported: []CryptographicBindingMethod{
					CryptographicBindingMethod_JWK,
				},
				ProofTypesSupported: map[ProofTypeIdentifier]ProofType{
					ProofTypeIdentifier_JWT: {
						ProofSigningAlgValuesSupported: []string{"ES256", "invalid-alg"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "cryptographic binding method present, proof type JWT, key attestations required - unsupported",
			config: CredentialConfiguration{
				Format: CredentialFormatIdentifier_SdJwtVc,
				CryptographicBindingMethodsSupported: []CryptographicBindingMethod{
					CryptographicBindingMethod_JWK,
				},
				ProofTypesSupported: map[ProofTypeIdentifier]ProofType{
					ProofTypeIdentifier_JWT: {
						ProofSigningAlgValuesSupported: []string{"ES256"},
						KeyAttestationsRequired: &KeyAttestationRequirement{
							KeyStorage:         []AttestationAttackResistance{Iso18045_Basic},
							UserAuthentication: []AttestationAttackResistance{Iso18045_Basic},
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
			err := tt.config.ValidateSupportedFeatures()
			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateSupportedFeatures() expected error, got nil")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("ValidateSupportedFeatures() error = %q, want %q", err.Error(), tt.expectedErr)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateSupportedFeatures() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCredentialDisplays_verify(t *testing.T) {
	tests := []struct {
		name        string
		displays    CredentialDisplays
		wantErr     bool
		expectedErr string
	}{
		{
			name: "valid single display",
			displays: CredentialDisplays{
				{
					Display: Display{
						Name:   "Credential Name",
						Locale: "en",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid single display, extended locale",
			displays: CredentialDisplays{
				{
					Display: Display{
						Name:   "Credential Name",
						Locale: "en-US",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing name in display",
			displays: CredentialDisplays{
				{
					Display: Display{
						Name:   "",
						Locale: "en",
					},
				},
			},
			wantErr:     true,
			expectedErr: "missing 'name'",
		},
		{
			name: "invalid logo uri",
			displays: CredentialDisplays{
				{
					Display: Display{
						Name:   "Credential Name",
						Locale: "en",
					},
					Logo: &RemoteImage{
						Uri: "://invalid-url",
					},
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'logo': invalid 'uri': parse \"://invalid-url\": missing protocol scheme",
		},
		{
			name: "invalid background image uri",
			displays: CredentialDisplays{
				{
					Display: Display{
						Name:   "Credential Name",
						Locale: "en",
					},
					BackgroundImage: &RemoteImage{
						Uri: "://invalid-url",
					},
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'background_image': invalid 'uri': parse \"://invalid-url\": missing protocol scheme",
		},
		{
			name: "duplicate locale",
			displays: CredentialDisplays{
				{
					Display: Display{
						Name:   "Credential Name",
						Locale: "en",
					},
				},
				{
					Display: Display{
						Name:   "Another Name",
						Locale: "en",
					},
				},
			},
			wantErr:     true,
			expectedErr: "duplicate 'locale' tag \"en\" in 'display' item with name \"Credential Name\"",
		},
		{
			name: "invalid locale tag",
			displays: CredentialDisplays{
				{
					Display: Display{
						Name:   "Credential Name",
						Locale: "invalid_locale",
					},
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'locale' tag \"invalid_locale\" in 'display' item with name \"Credential Name\": language: tag is not well-formed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.displays.verify()
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

	var display CredentialIssuerDisplay
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
		displays    CredentialIssuerDisplays
		wantErr     bool
		expectedErr string
	}{
		{
			name: "valid single display",
			displays: CredentialIssuerDisplays{
				{
					Display: Display{
						Name:   "Issuer Name",
						Locale: "en",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid display with logo",
			displays: CredentialIssuerDisplays{
				{
					Display: Display{
						Name:   "Issuer Name",
						Locale: "en",
					},
					Logo: &RemoteImage{
						Uri: "https://example.com/logo.png",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid logo uri",
			displays: CredentialIssuerDisplays{
				{
					Display: Display{
						Name:   "Issuer Name",
						Locale: "en",
					},
					Logo: &RemoteImage{
						Uri: "://invalid-url",
					},
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'logo' in 'display': invalid 'uri': parse \"://invalid-url\": missing protocol scheme",
		},
		{
			name: "duplicate locale",
			displays: CredentialIssuerDisplays{
				{
					Display: Display{
						Name:   "Issuer Name",
						Locale: "en",
					},
				},
				{
					Display: Display{
						Name:   "Another Name",
						Locale: "en",
					},
				},
			},
			wantErr:     true,
			expectedErr: "duplicate 'locale' tag \"en\" in 'display' item with name \"Issuer Name\"",
		},
		{
			name: "invalid locale tag",
			displays: CredentialIssuerDisplays{
				{
					Display: Display{
						Name:   "Issuer Name",
						Locale: "invalid_locale",
					},
				},
			},
			wantErr:     true,
			expectedErr: "invalid 'locale' tag \"invalid_locale\" in 'display' item with name \"Issuer Name\": language: tag is not well-formed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.displays.verify()
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

func TestCredentialIssuerMetadata_GetAllBaseLanguages(t *testing.T) {
	tests := []struct {
		name     string // description of this test case
		metadata CredentialIssuerMetadata
		want     []string
	}{
		{
			name: "single display, single locale",
			metadata: CredentialIssuerMetadata{
				Display: CredentialIssuerDisplays{
					{
						Display: Display{
							Name:   "Issuer Name",
							Locale: "en",
						},
					},
				},
			},
			want: []string{"en"},
		},
		{
			name: "multiple displays, multiple locales",
			metadata: CredentialIssuerMetadata{
				Display: CredentialIssuerDisplays{
					{
						Display: Display{
							Name:   "Issuer Name",
							Locale: "en-US",
						},
					},
					{
						Display: Display{
							Name:   "Nom de l'émetteur",
							Locale: "fr-FR",
						},
					},
					{
						Display: Display{
							Name:   "Nombre del emisor",
							Locale: "es",
						},
					},
				},
			},
			want: []string{"en", "fr", "es"},
		},
		{
			name: "displays with duplicate base languages",
			metadata: CredentialIssuerMetadata{
				Display: CredentialIssuerDisplays{
					{
						Display: Display{
							Name:   "Issuer Name",
							Locale: "en-US",
						},
					},
					{
						Display: Display{
							Name:   "Another Issuer Name",
							Locale: "en-GB",
						},
					},
					{
						Display: Display{
							Name:   "Nom de l'émetteur",
							Locale: "fr",
						},
					},
				},
			},
			want: []string{"en", "fr"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.metadata.GetAllBaseLanguages()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetAllBaseLanguages() = %v, want %v", got, tt.want)
			}
		})
	}
}
