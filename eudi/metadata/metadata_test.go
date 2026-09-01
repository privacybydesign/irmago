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

// Pre-1.0 OpenID4VCI issuers place credential display and claims directly on the
// credential configuration, with no credential_metadata object. UnmarshalJSON
// must synthesize CredentialMetadata from them so downstream display resolution,
// which only consults CredentialMetadata, still works.
func TestCredentialConfiguration_UnmarshalJSON_LegacyTopLevelDisplayAndClaims(t *testing.T) {
	data := []byte(`{
		"format": "dc+sd-jwt",
		"vct": "urn:example:pid",
		"display": [{"name": "PID", "locale": "en"}],
		"claims": [{"path": ["given_name"], "display": [{"name": "First name", "locale": "en"}]}]
	}`)

	var c CredentialConfiguration
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if c.CredentialMetadata == nil {
		t.Fatal("expected CredentialMetadata to be synthesized from top-level display/claims, got nil")
	}
	if len(c.CredentialMetadata.Display) != 1 || c.CredentialMetadata.Display[0].GetName() != "PID" {
		t.Errorf("expected synthesized display name PID, got %+v", c.CredentialMetadata.Display)
	}
	if len(c.CredentialMetadata.Claims) != 1 {
		t.Errorf("expected 1 synthesized claim, got %d", len(c.CredentialMetadata.Claims))
	}
}

// When credential_metadata is present (OID4VCI v1.0), it is authoritative and
// the legacy top-level fields are ignored.
func TestCredentialConfiguration_UnmarshalJSON_CredentialMetadataTakesPrecedence(t *testing.T) {
	data := []byte(`{
		"format": "dc+sd-jwt",
		"display": [{"name": "Legacy", "locale": "en"}],
		"credential_metadata": {"display": [{"name": "Modern", "locale": "en"}]}
	}`)

	var c CredentialConfiguration
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if c.CredentialMetadata == nil {
		t.Fatal("expected CredentialMetadata from credential_metadata, got nil")
	}
	if got := c.CredentialMetadata.Display[0].GetName(); got != "Modern" {
		t.Errorf("expected credential_metadata to win with 'Modern', got %q", got)
	}
}

func TestCredentialConfiguration_UnmarshalJSON_NoDisplayLeavesMetadataNil(t *testing.T) {
	data := []byte(`{"format": "dc+sd-jwt", "vct": "urn:example:pid"}`)
	var c CredentialConfiguration
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if c.CredentialMetadata != nil {
		t.Errorf("expected nil CredentialMetadata when no display/claims, got %+v", c.CredentialMetadata)
	}
}

// A malformed legacy top-level display (here: not an array) was an unknown field
// the parser silently ignored before credential_metadata was synthesized from it.
// It must stay that way: the document still parses, it just yields no metadata.
func TestCredentialConfiguration_UnmarshalJSON_MalformedLegacyDisplayIsIgnored(t *testing.T) {
	data := []byte(`{"format": "dc+sd-jwt", "vct": "urn:example:pid", "display": "not-an-array"}`)

	var c CredentialConfiguration
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("malformed legacy display must not reject the document, got: %v", err)
	}
	if c.VerifiableCredentialType != "urn:example:pid" {
		t.Errorf("expected the rest of the document to parse, got vct %q", c.VerifiableCredentialType)
	}
	if c.CredentialMetadata != nil {
		t.Errorf("expected no metadata synthesized from a malformed legacy block, got %+v", c.CredentialMetadata)
	}
}

// Draft-13 issuers write legacy `claims` as an object keyed by claim name, which
// does not fit []ClaimsDescription. That type mismatch must not throw away the
// `display` decoded next to it — the legacy issuer's credential still gets its
// name; only the claims stay empty.
func TestCredentialConfiguration_UnmarshalJSON_LegacyClaimsObjectKeepsDisplay(t *testing.T) {
	data := []byte(`{
		"format": "dc+sd-jwt",
		"vct": "urn:example:pid",
		"display": [{"name": "PID", "locale": "en"}],
		"claims": {"given_name": {"display": [{"name": "First name", "locale": "en"}]}}
	}`)

	var c CredentialConfiguration
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("legacy claims object must not reject the document, got: %v", err)
	}
	if c.CredentialMetadata == nil {
		t.Fatal("expected CredentialMetadata synthesized from the legacy display, got nil")
	}
	if len(c.CredentialMetadata.Display) != 1 || c.CredentialMetadata.Display[0].GetName() != "PID" {
		t.Errorf("expected the legacy display to survive the claims type mismatch, got %+v", c.CredentialMetadata.Display)
	}
	if len(c.CredentialMetadata.Claims) != 0 {
		t.Errorf("expected no claims from an object-shaped legacy block, got %+v", c.CredentialMetadata.Claims)
	}
}
