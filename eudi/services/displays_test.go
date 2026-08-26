package services

import (
	"encoding/json"
	"strconv"
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

// mdocBatch builds an mso_mdoc batch carrying one namespace with two elements,
// whose claim metadata uses the given paths.
func mdocBatch(claimPaths ...[]any) *models.CredentialBatch {
	claims := make([]models.CredentialClaim, 0, len(claimPaths))
	for i, path := range claimPaths {
		encoded, _ := json.Marshal(path)
		claims = append(claims, models.CredentialClaim{
			Path:    datatypes.JSON(encoded),
			Display: []models.ClaimDisplay{{Name: "Label " + strconv.Itoa(i), Locale: nullStr("en")}},
		})
	}
	return &models.CredentialBatch{
		Format:                   models.CredentialFormatMsoMdoc,
		VerifiableCredentialType: "eu.europa.ec.av.1",
		ProcessedSdJwtPayload: datatypes.JSON(
			`{"eu.europa.ec.av.1":{"age_over_18":true,"age_over_21":true}}`),
		CredentialMetadata: &models.CredentialMetadata{Claims: claims},
	}
}

// An issuer that publishes a bare element identifier still gets its labels
// rendered: OpenID4VCI's mso_mdoc profile specifies no display metadata, so the
// one-component form is not a bug the wallet can refuse to work around, and
// without the alias the credential list shows unlabelled rows for a credential
// whose disclosure screen labels them.
func TestResolveBatchDisplay_AliasesMdocBareElementPaths(t *testing.T) {
	d := ResolveBatchDisplay(mdocBatch([]any{"age_over_18"}, []any{"age_over_21"}), "en")

	require.Equal(t, "Label 0", d.ClaimNames[clientmodels.ClaimPathKey([]any{"eu.europa.ec.av.1", "age_over_18"})])
	require.Equal(t, "Label 1", d.ClaimNames[clientmodels.ClaimPathKey([]any{"eu.europa.ec.av.1", "age_over_21"})])

	// Issuer order carries over too, so the list shows the elements in the order
	// the metadata declares rather than alphabetically.
	require.Equal(t, 0, d.ClaimOrder[clientmodels.ClaimPathKey([]any{"eu.europa.ec.av.1", "age_over_18"})])
	require.Equal(t, 1, d.ClaimOrder[clientmodels.ClaimPathKey([]any{"eu.europa.ec.av.1", "age_over_21"})])
}

// A correctly published two-component path must win, so an issuer that publishes
// both forms is never labelled from the wrong one.
func TestResolveBatchDisplay_ExactMdocPathBeatsBareElementAlias(t *testing.T) {
	batch := mdocBatch([]any{"eu.europa.ec.av.1", "age_over_18"}, []any{"age_over_18"})

	d := ResolveBatchDisplay(batch, "en")

	require.Equal(t, "Label 0", d.ClaimNames[clientmodels.ClaimPathKey([]any{"eu.europa.ec.av.1", "age_over_18"})])
}

// The alias is only for elements the credential carries: metadata may describe
// claims from namespaces this batch never received.
func TestResolveBatchDisplay_DoesNotAliasElementsTheCredentialLacks(t *testing.T) {
	d := ResolveBatchDisplay(mdocBatch([]any{"age_over_65"}), "en")

	require.NotContains(t, d.ClaimNames, clientmodels.ClaimPathKey([]any{"eu.europa.ec.av.1", "age_over_65"}))
}

// SD-JWT paths are namespace-free by nature, so a one-component path there is
// already the real path and must not be rewritten into a two-component one.
func TestResolveBatchDisplay_LeavesSdJwtPathsAlone(t *testing.T) {
	batch := mdocBatch([]any{"age_over_18"})
	batch.Format = models.CredentialFormatSdJwtVc

	d := ResolveBatchDisplay(batch, "en")

	require.Equal(t, "Label 0", d.ClaimNames[clientmodels.ClaimPathKey([]any{"age_over_18"})])
	require.NotContains(t, d.ClaimNames, clientmodels.ClaimPathKey([]any{"eu.europa.ec.av.1", "age_over_18"}))
}

// CredentialDisplayIsFallback is the signal the frontend needs to know whether
// substituting its own label for a credential type it recognises is filling a gap
// or overriding what the issuer published. The resolved text cannot say: the
// fallback chain lands on English rather than on nothing.
func TestCredentialDisplayIsFallback(t *testing.T) {
	batch := mdocBatch([]any{"eu.europa.ec.av.1", "age_over_18"})
	batch.CredentialMetadata.Display = []models.CredentialDisplay{
		{Name: "Proof of Age", Locale: nullStr("en")},
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
		bare := mdocBatch([]any{"eu.europa.ec.av.1", "age_over_18"})
		bare.CredentialMetadata = nil
		require.True(t, CredentialDisplayIsFallback(bare, "en"))
	})

	t.Run("ResolveBatchDisplay reports it alongside the text it resolved", func(t *testing.T) {
		require.True(t, ResolveBatchDisplay(batch, "nl").DisplayIsFallback)
		require.False(t, ResolveBatchDisplay(batch, "en").DisplayIsFallback)
		// Set even on the early return, where there is no name to resolve at all.
		bare := mdocBatch([]any{"eu.europa.ec.av.1", "age_over_18"})
		bare.CredentialMetadata = nil
		require.True(t, ResolveBatchDisplay(bare, "en").DisplayIsFallback)
	})
}
