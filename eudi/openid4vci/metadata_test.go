package openid4vci

import (
	"reflect"
	"testing"
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
				Format: tt.format,
			}
			err := c.validateCredentialConfiguration()
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCredentialConfiguration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateCredentialConfiguration_UnsupportedFormat(t *testing.T) {
	c := &CredentialConfiguration{
		Format: "unsupported_format",
	}
	err := c.validateCredentialConfiguration()
	if err == nil {
		t.Errorf("Expected error for unsupported format, got nil")
	}
	want := `unsupported credential format "unsupported_format"`
	if err.Error() != want {
		t.Errorf("Expected error %q, got %q", want, err.Error())
	}
}

func TestValidateCredentialConfiguration_SdJwtVc_InvalidSigningAlg(t *testing.T) {
	c := &CredentialConfiguration{
		Format:                              CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []string{"invalid-alg"},
	}
	err := c.validateCredentialConfiguration()
	if err == nil {
		t.Errorf("Expected error for invalid signing algorithm, got nil")
	}
	if err != nil && err.Error() != `unsupported signing algorithm "invalid-alg" in 'credential_signing_alg_values_supported'` {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestValidateCredentialConfiguration_SdJwtVc_ValidSigningAlg(t *testing.T) {
	c := &CredentialConfiguration{
		Format:                              CredentialFormatIdentifier_SdJwtVc,
		CredentialSigningAlgValuesSupported: []string{"ES256"},
	}
	err := c.validateCredentialConfiguration()
	if err != nil {
		t.Errorf("Expected no error for valid signing algorithm, got %v", err)
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
	err := c.validateCredentialConfiguration()
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
	}
	err := c.validateCredentialConfiguration()
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
			name: "missing credential_issuer",
			metadata: CredentialIssuerMetadata{
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			offer:   validCredentialOffer,
			wantErr: "missing 'credential_issuer'",
		},
		{
			name: "missing credential_endpoint",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			offer:   validCredentialOffer,
			wantErr: "missing 'credential_endpoint'",
		},
		{
			name: "missing credential_configurations_supported",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:   "https://issuer.example.com",
				CredentialEndpoint: "https://issuer.example.com/credential",
			},
			offer:   validCredentialOffer,
			wantErr: "missing 'credential_configurations_supported'",
		},
		{
			name: "credential_issuer mismatch",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://other-issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			offer:   validCredentialOffer,
			wantErr: "'credential_issuer' in metadata does not match 'credential_issuer' from the credential offer",
		},
		{
			name: "invalid authorization_server URL",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				AuthorizationServers:              []string{"://invalid-url"},
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			offer:   validCredentialOffer,
			wantErr: `invalid 'authorization_server' URL "://invalid-url"`,
		},
		{
			name: "invalid credential_endpoint URL",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "://invalid-url",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			offer:   validCredentialOffer,
			wantErr: `invalid 'credential_endpoint' URL "://invalid-url"`,
		},
		{
			name: "credential_endpoint with fragment",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential#frag",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			offer:   validCredentialOffer,
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
			offer:   validCredentialOffer,
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
			offer:   validCredentialOffer,
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
			offer:   validCredentialOffer,
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
			offer:   validCredentialOffer,
			wantErr: "'batch_size' in 'batch_credential_issuance' must be > 1",
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
			offer:   validCredentialOffer,
			wantErr: `invalid credential configuration "test": unsupported credential format "invalid_format"`,
		},
		{
			name: "valid metadata",
			metadata: CredentialIssuerMetadata{
				CredentialIssuer:                  "https://issuer.example.com",
				CredentialEndpoint:                "https://issuer.example.com/credential",
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{"test": validCredentialConfig},
			},
			offer:   validCredentialOffer,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.metadata.Verify(tt.offer)
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

func TestCredentialIssuerMetadata_ValidateSupportedFeatures(t *testing.T) {
	validCredentialConfig := CredentialConfiguration{
		Format: CredentialFormatIdentifier_SdJwtVc,
	}
	unsupportedCredentialConfig := CredentialConfiguration{
		Format: CredentialFormatIdentifier_W3CVC,
	}

	tests := []struct {
		name        string
		metadata    CredentialIssuerMetadata
		offer       *CredentialOffer
		wantErr     bool
		expectedErr string
	}{
		{
			name: "all credential configurations supported (SD-JWT VC)",
			metadata: CredentialIssuerMetadata{
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{
					"cred1": validCredentialConfig,
				},
			},
			offer: &CredentialOffer{
				CredentialConfigurationIds: []string{"cred1"},
			},
			wantErr: false,
		},
		{
			name: "unsupported credential format in offer",
			metadata: CredentialIssuerMetadata{
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{
					"cred1": unsupportedCredentialConfig,
				},
			},
			offer: &CredentialOffer{
				CredentialConfigurationIds: []string{"cred1"},
			},
			wantErr:     true,
			expectedErr: `unsupported credential format "jwt_vc_json"`,
		},
		{
			name: "multiple credential configurations, one unsupported",
			metadata: CredentialIssuerMetadata{
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{
					"cred1": validCredentialConfig,
					"cred2": unsupportedCredentialConfig,
				},
			},
			offer: &CredentialOffer{
				CredentialConfigurationIds: []string{"cred1", "cred2"},
			},
			wantErr:     true,
			expectedErr: `unsupported credential format "jwt_vc_json"`,
		},
		{
			name: "credential configuration id not present in supported configurations",
			metadata: CredentialIssuerMetadata{
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{
					"cred1": validCredentialConfig,
				},
			},
			offer: &CredentialOffer{
				CredentialConfigurationIds: []string{"unknown"},
			},
			wantErr: false, // Should not error, as the code only checks present configs
		},
		{
			name: "no credential configuration ids in offer",
			metadata: CredentialIssuerMetadata{
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{
					"cred1": validCredentialConfig,
				},
			},
			offer: &CredentialOffer{
				CredentialConfigurationIds: []string{},
			},
			wantErr: false,
		},
		{
			name: "empty supported configurations",
			metadata: CredentialIssuerMetadata{
				CredentialConfigurationsSupported: map[string]CredentialConfiguration{},
			},
			offer: &CredentialOffer{
				CredentialConfigurationIds: []string{"cred1"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.metadata.ValidateSupportedFeatures(tt.offer)
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
