package walletconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func catalogConfig(entries ...CatalogEntry) *Config {
	config := NewTestConfig("test", 1, time.Now())
	config.SchemaVersion = CurrentSchemaVersion
	config.CredentialCatalog = entries
	return config
}

func emailEntry() CatalogEntry {
	return CatalogEntry{
		VCT:            "https://example.com/vct/email",
		VCTMetadataURL: "https://example.com/.well-known/vct/email",
		InStore:        true,
		Offerings: []Offering{{
			IssuanceURLs:      map[string]string{"default": "https://issue.example.com/email", "nl": "https://issue.example.com/nl/email"},
			IssuerMetadataURL: "https://issuer.example.com",
		}},
	}
}

func TestCatalog_ValidatesAndLooksUpEntries(t *testing.T) {
	config := catalogConfig(emailEntry(), CatalogEntry{
		VCT:            "urn:eudi:pid:1",
		VCTMetadataURL: "https://metadata.example.com/pid.json",
		Offerings:      []Offering{{IssuanceURLs: map[string]string{"default": "https://pid.example.com/start"}}},
	})
	require.NoError(t, config.Validate())

	require.Equal(t, "https://example.com/vct/email", config.CatalogEntry("https://example.com/vct/email").VCT)
	require.Nil(t, config.CatalogEntry("https://example.com/vct/other"))
	require.True(t, config.CatalogEntry("https://example.com/vct/email").InStore)
	require.False(t, config.CatalogEntry("urn:eudi:pid:1").InStore)
}

func TestCatalog_ConfigsWithoutACatalogueStayValid(t *testing.T) {
	require.NoError(t, NewTestConfig("test", 1, time.Now()).Validate())
	require.NoError(t, catalogConfig().Validate())
}

func TestCatalog_RejectsEachMalformedEntry(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*CatalogEntry)
		want   string
	}{
		{"vct missing", func(e *CatalogEntry) { e.VCT = "" }, "vct is required"},
		{"metadata url not https", func(e *CatalogEntry) { e.VCTMetadataURL = "http://example.com/vct" }, "vct_metadata_url"},
		{"no offerings", func(e *CatalogEntry) { e.Offerings = nil }, "offerings is required"},
		{"no default issuance url", func(e *CatalogEntry) { delete(e.Offerings[0].IssuanceURLs, "default") }, `needs a "default" entry`},
		{"issuance url not https", func(e *CatalogEntry) { e.Offerings[0].IssuanceURLs["default"] = "http://issue.example.com" }, `issuance_urls["default"]`},
		{"issuance url key not a language tag", func(e *CatalogEntry) { e.Offerings[0].IssuanceURLs["dutch!"] = "https://issue.example.com/nl" }, `"dutch!" is not a language tag`},
		{"issuer metadata url not https", func(e *CatalogEntry) { e.Offerings[0].IssuerMetadataURL = "ftp://issuer.example.com" }, "issuer_metadata_url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entry := emailEntry()
			tc.mutate(&entry)
			require.ErrorContains(t, catalogConfig(entry).Validate(), tc.want)
		})
	}

	require.ErrorContains(t, catalogConfig(emailEntry(), emailEntry()).Validate(), "listed by another entry")
}

func TestCatalog_AcceptsRegionalLanguageTags(t *testing.T) {
	entry := emailEntry()
	entry.Offerings[0].IssuanceURLs["nl-BE"] = "https://issue.example.com/be/email"
	entry.Offerings[0].IssuanceURLs["zh-Hant-TW"] = "https://issue.example.com/tw/email"
	require.NoError(t, catalogConfig(entry).Validate())
}

func TestOffering_IssuanceURLFallsBackThroughBaseLanguageToDefault(t *testing.T) {
	offering := Offering{IssuanceURLs: map[string]string{
		"default": "https://issue.example.com/",
		"nl":      "https://issue.example.com/nl",
		"nl-BE":   "https://issue.example.com/be",
	}}
	require.Equal(t, "https://issue.example.com/be", offering.IssuanceURL("nl-BE"))
	require.Equal(t, "https://issue.example.com/nl", offering.IssuanceURL("nl-NL"), "the base language stands in for a region without a URL")
	require.Equal(t, "https://issue.example.com/nl", offering.IssuanceURL("nl"))
	require.Equal(t, "https://issue.example.com/", offering.IssuanceURL("de"))
	require.Equal(t, "https://issue.example.com/", offering.IssuanceURL(""))
}

func TestCatalogEntry_MetadataURL(t *testing.T) {
	listed := emailEntry()
	require.Equal(t, "https://example.com/.well-known/vct/email", listed.MetadataURL())

	httpVct := CatalogEntry{VCT: "https://example.com/vct/email"}
	require.Equal(t, "https://example.com/vct/email", httpVct.MetadataURL(), "an HTTP vct is its own metadata URL")

	urn := CatalogEntry{VCT: "urn:eudi:pid:1"}
	require.Empty(t, urn.MetadataURL(), "a URN vct without a listed metadata URL cannot be resolved")
	urn.VCTMetadataURL = "https://metadata.example.com/pid.json"
	require.Equal(t, "https://metadata.example.com/pid.json", urn.MetadataURL())
}

// A catalogue travels with the config through signing and verification, and a
// client reading an older minor still accepts a config that carries one.
func TestCatalog_SurvivesSigningAndVerification(t *testing.T) {
	signer := NewTestSigner(t)
	config := catalogConfig(emailEntry())

	verified, err := Verify(signer.Sign(t, config), signer.Environment("test", testConfigURL), time.Now())
	require.NoError(t, err)
	require.Len(t, verified.Config.CredentialCatalog, 1)
	require.Equal(t, "https://issue.example.com/nl/email", verified.Config.CredentialCatalog[0].Offerings[0].IssuanceURL("nl"))
}
