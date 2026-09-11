package services

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

func nullStr(s string) datatypes.NullString {
	return datatypes.NullString{V: s, Valid: true}
}

func TestCredentialLogoURIsByLanguage_MapsOnlyLogoCarryingDisplays(t *testing.T) {
	displays := []models.CredentialDisplay{
		{Name: "EN", Locale: nullStr("en"), LogoURI: "https://logos.example.com/en.png"},
		{Name: "NL", Locale: nullStr("nl")}, // no logo
		{Name: "DE", Locale: nullStr("de-DE"), LogoURI: "https://logos.example.com/de.png"},
	}

	uris := CredentialLogoURIsByLanguage(displays)

	require.Equal(t, clientmodels.TranslatedString{
		"en": "https://logos.example.com/en.png",
		"de": "https://logos.example.com/de.png",
	}, uris, "displays without a logo are skipped; regional locales collapse to base language")
}

func TestResolveLogoIndependentOfText(t *testing.T) {
	// The NL display exists but carries no logo: the logo must fall back to
	// the English display's logo instead of disappearing.
	displays := []models.CredentialDisplay{
		{Name: "EN", Locale: nullStr("en"), LogoURI: "https://logos.example.com/en.png"},
		{Name: "NL", Locale: nullStr("nl")},
	}

	uri := clientmodels.Resolve(CredentialLogoURIsByLanguage(displays), "nl")

	require.Equal(t, "https://logos.example.com/en.png", uri,
		"logo falls back across languages independently of the text bundle")
}

func TestLoadResolvedLogo_FallsBackToCachedLogoWhilePreferredIsMissing(t *testing.T) {
	fs := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir())
	manager := fs.Credentials().LogoManager()
	require.NoError(t, manager.Save("https://logos.example.com/en.png", []byte("en-logo"), ""))

	uris := clientmodels.TranslatedString{
		"en": "https://logos.example.com/en.png",
		"nl": "https://logos.example.com/nl.png", // resolves for nl, but not cached yet
	}

	img := LoadResolvedLogo(manager, uris, "nl")

	require.NotNil(t, img, "a cached logo should show while the backfill fetches the preferred one")

	require.NoError(t, manager.Save("https://logos.example.com/nl.png", []byte("nl-logo"), ""))
	img = LoadResolvedLogo(manager, uris, "nl")
	require.NotNil(t, img)
}

func TestLoadResolvedLogo_NoLogosCached_ReturnsNil(t *testing.T) {
	fs := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir())
	manager := fs.Credentials().LogoManager()

	img := LoadResolvedLogo(manager, clientmodels.TranslatedString{"en": "https://logos.example.com/en.png"}, "en")

	require.Nil(t, img)
}

// ---------------------------------------------------------------------------
// mdoc claim-path aliasing
// ---------------------------------------------------------------------------

// SD-JWT paths are namespace-free by nature, so a one-component path is already
// the real path and is indexed as published; nothing rewrites it.
func TestResolveBatchDisplay_KeepsOneComponentPaths(t *testing.T) {
	batch := &models.SdJwtVcBatch{
		Format:                   models.CredentialFormatSdJwtVc,
		VerifiableCredentialType: "https://vct.example/x",
		ProcessedSdJwtPayload:    datatypes.JSON(`{"age_over_18":true}`),
		CredentialMetadata: &models.CredentialMetadata{Claims: []models.CredentialClaim{{
			Path:    datatypes.JSON(`["age_over_18"]`),
			Display: []models.ClaimDisplay{{Name: "Label 0", Locale: nullStr("en")}},
		}}},
	}

	d := ResolveBatchDisplay(batch, "en")

	require.Equal(t, "Label 0", d.ClaimNames[clientmodels.ClaimPathKey([]any{"age_over_18"})])
	require.Len(t, d.ClaimNames, 1)
}

// CredentialDisplayIsFallback is the signal the frontend needs to know whether
// substituting its own label for a credential type it recognises is filling a gap
// or overriding what the issuer published. The resolved text cannot say: the
// fallback chain lands on English rather than on nothing.
func TestCredentialDisplayIsFallback(t *testing.T) {
	batch := &models.SdJwtVcBatch{
		Format:                   models.CredentialFormatSdJwtVc,
		VerifiableCredentialType: "https://vct.example/x",
		ProcessedSdJwtPayload:    datatypes.JSON(`{"age_over_18":true}`),
		CredentialMetadata: &models.CredentialMetadata{
			Display: []models.CredentialDisplay{{Name: "Proof of Age", Locale: nullStr("en")}},
		},
	}

	t.Run("the requested language was published", func(t *testing.T) {
		require.False(t, CredentialDisplayIsFallback(batch, "en"))
	})

	t.Run("the requested language was not published", func(t *testing.T) {
		// The en-only reference issuer against a Dutch wallet: the credential still
		// renders, in English, and this is what says so.
		require.True(t, CredentialDisplayIsFallback(batch, "nl"))
	})

	t.Run("a regional locale served by its base language is not a fallback", func(t *testing.T) {
		require.False(t, CredentialDisplayIsFallback(batch, "en-GB"))
	})

	t.Run("no display metadata at all", func(t *testing.T) {
		bare := &models.SdJwtVcBatch{Format: models.CredentialFormatSdJwtVc, ProcessedSdJwtPayload: datatypes.JSON(`{}`)}
		require.True(t, CredentialDisplayIsFallback(bare, "en"))
	})

	t.Run("ResolveBatchDisplay reports it alongside the text it resolved", func(t *testing.T) {
		require.True(t, ResolveBatchDisplay(batch, "nl").DisplayIsFallback)
		require.False(t, ResolveBatchDisplay(batch, "en").DisplayIsFallback)
		// Set even on the early return, where there is no name to resolve at all.
		bare := &models.SdJwtVcBatch{Format: models.CredentialFormatSdJwtVc, ProcessedSdJwtPayload: datatypes.JSON(`{}`)}
		require.True(t, ResolveBatchDisplay(bare, "en").DisplayIsFallback)
	})
}
