package metadata

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

var locale_EN = "en"
var locale_EN_US = "en-US"
var locale_EN_GB = "en-GB"
var locale_FR = "fr"
var locale_FR_FR = "fr-FR"
var locale_ES = "es"

func Test_convertDisplayToTranslatedString(t *testing.T) {
	tests := []struct {
		name     string
		displays []Display
		want     clientmodels.TranslatedString
	}{
		{
			name: "single display, single locale",
			displays: []Display{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN,
				},
			},
			want: clientmodels.TranslatedString{
				"en": "Issuer Name",
			},
		},
		{
			name: "multiple displays, multiple locales",
			displays: []Display{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN_US,
				},
				{
					Name:   "Nom de l'émetteur",
					Locale: &locale_FR_FR,
				},
				{
					Name:   "Nombre del emisor",
					Locale: &locale_ES,
				},
			},
			want: clientmodels.TranslatedString{
				"en": "Issuer Name",
				"fr": "Nom de l'émetteur",
				"es": "Nombre del emisor",
			},
		},
		{
			name: "displays with duplicate base languages",
			displays: []Display{
				{
					Name:   "Issuer Name",
					Locale: &locale_EN_US,
				},
				{
					Name:   "Another Issuer Name",
					Locale: &locale_EN_GB,
				},
				{
					Name:   "Nom de l'émetteur",
					Locale: &locale_FR,
				},
			},
			want: clientmodels.TranslatedString{
				"en": "Another Issuer Name", // Last one wins
				"fr": "Nom de l'émetteur",
			},
		},
		{
			name: "display without locale, should be ignored",
			displays: []Display{
				{
					Name:   "Issuer Name",
					Locale: nil,
				},
				{
					Name:   "Another Issuer Name",
					Locale: &locale_EN_US,
				},
			},
			want: clientmodels.TranslatedString{
				"":   "Issuer Name",
				"en": "Another Issuer Name",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			displays := ToTranslateableList(tt.displays)
			got := ConvertDisplayToTranslatedString(displays)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertDisplayToTranslatedString() = %v, want %v", got, tt.want)
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
						Name:   "Issuer Name",
						Locale: &locale_EN,
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
						Name:   "Issuer Name",
						Locale: &locale_EN_US,
					},
					{
						Name:   "Nom de l'émetteur",
						Locale: &locale_FR_FR,
					},
					{
						Name:   "Nombre del emisor",
						Locale: &locale_ES,
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
						Name:   "Issuer Name",
						Locale: &locale_EN_US,
					},
					{
						Name:   "Another Issuer Name",
						Locale: &locale_EN_GB,
					},
					{
						Name:   "Nom de l'émetteur",
						Locale: &locale_FR,
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

// jwx v4 by default keeps unparseable JWK Set entries as placeholder keys,
// where v3 rejected the whole set. Issuer metadata comes from an external
// party, so we keep the strict v3 behavior; this pins it.
func TestCredentialRequestEncryption_UnmarshalJSON_UnparseableKeyInJwks_ReturnsError(t *testing.T) {
	valid := `{"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]},"enc_values_supported":["A256GCM"],"encryption_required":false}`
	var cre CredentialRequestEncryption
	if err := json.Unmarshal([]byte(valid), &cre); err != nil {
		t.Fatalf("valid jwks should unmarshal, got error: %v", err)
	}

	withUnparseable := `{"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},{"kty":"EC","crv":"P-256"}]},"enc_values_supported":["A256GCM"],"encryption_required":false}`
	if err := json.Unmarshal([]byte(withUnparseable), &cre); err == nil {
		t.Fatal("jwks with an unparseable key should be rejected")
	}
}

// OpenID4VCI v1.0 (draft 16) nests a configuration's display metadata in
// credential_metadata; earlier drafts put display and claims on the configuration
// itself. Reading only the nested object left a credential from such an issuer
// nameless, and indistinguishable from an issuer that publishes no display text at
// all — the failure missingDisplayMetadataReason was written to explain.
func TestCredentialConfiguration_UnmarshalJSON_ReadsPreV1DisplayPlacement(t *testing.T) {
	raw := `{
		"format": "mso_mdoc",
		"display": [{"locale": "en", "name": "Proof of Age"}],
		"claims": [{
			"path": ["eu.europa.ec.av.1", "age_over_18"],
			"display": [{"locale": "en", "name": "Age Over 18"}]
		}]
	}`

	var config CredentialConfiguration
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if config.CredentialMetadata == nil {
		t.Fatal("display and claims on the configuration should normalise into credential_metadata")
	}
	if got := len(config.CredentialMetadata.Display); got != 1 {
		t.Fatalf("expected 1 credential display entry, got %d", got)
	}
	if got := config.CredentialMetadata.Display[0].Name; got != "Proof of Age" {
		t.Errorf("credential display name = %q, want %q", got, "Proof of Age")
	}
	if got := len(config.CredentialMetadata.Claims); got != 1 {
		t.Fatalf("expected 1 claim, got %d", got)
	}
	// The claim path is what joins a label to the value it names, so it has to
	// survive the move verbatim.
	wantPath := ClaimsPathPointer{"eu.europa.ec.av.1", "age_over_18"}
	if got := config.CredentialMetadata.Claims[0].Path; !reflect.DeepEqual(got, wantPath) {
		t.Errorf("claim path = %#v, want %#v", got, wantPath)
	}
	if got := config.CredentialMetadata.Claims[0].Display[0].Name; got != "Age Over 18" {
		t.Errorf("claim display name = %q, want %q", got, "Age Over 18")
	}
	// The format field must survive alongside the promoted fields, since the
	// embedded-struct trick that reads both placements is where it would get lost.
	if config.Format != CredentialFormatIdentifier_MsoMdoc {
		t.Errorf("format = %q, want %q", config.Format, CredentialFormatIdentifier_MsoMdoc)
	}
}

// An issuer publishing credential_metadata is speaking the current version, so
// what it says there wins and stray legacy fields are a leftover. Asserted with an
// *empty* credential_metadata because that is the case where the two rules differ:
// preferring the non-empty source would resurrect the leftover.
func TestCredentialConfiguration_UnmarshalJSON_NestedMetadataWinsEvenWhenEmpty(t *testing.T) {
	raw := `{
		"format": "dc+sd-jwt",
		"vct": "https://vct.example.com/MyCredential",
		"credential_metadata": {},
		"display": [{"locale": "en", "name": "Leftover"}]
	}`

	var config CredentialConfiguration
	if err := json.Unmarshal([]byte(raw), &config); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if config.CredentialMetadata == nil {
		t.Fatal("an explicit credential_metadata object should be kept")
	}
	if got := len(config.CredentialMetadata.Display); got != 0 {
		t.Errorf("expected the legacy display to be ignored, got %d entries", got)
	}
}

func TestCredentialConfiguration_UnmarshalJSON_NoDisplayMetadataAtAll(t *testing.T) {
	var config CredentialConfiguration
	if err := json.Unmarshal([]byte(`{"format": "mso_mdoc"}`), &config); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Left nil rather than an empty object, because missingDisplayMetadataReason
	// tells the two apart: nil means the issuer published nothing, empty means it
	// published an empty statement.
	if config.CredentialMetadata != nil {
		t.Errorf("credential_metadata = %#v, want nil", config.CredentialMetadata)
	}
}
