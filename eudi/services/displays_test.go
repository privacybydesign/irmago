package services

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func TestLoadCuratedLogo_DownloadsOnceAndCachesIt(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "image/svg+xml")
		_, _ = w.Write([]byte("<svg/>"))
	}))
	defer server.Close()

	manager := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()).Verifiers().LogoManager()

	img := LoadCuratedLogo(context.Background(), manager, server.Client(), server.URL)

	require.NotNil(t, img)
	require.Equal(t, base64.StdEncoding.EncodeToString([]byte("<svg/>")), img.Base64)
	require.NotNil(t, img.MimeType)
	require.Equal(t, "image/svg+xml", *img.MimeType, "an SVG logo has to stay distinguishable from a bitmap")

	// A second session meeting the same party reads the cache: nothing about
	// display composition may put a request on the network per session.
	again := LoadCuratedLogo(context.Background(), manager, server.Client(), server.URL)

	require.Equal(t, img, again)
	require.Equal(t, int32(1), hits.Load())
}

func TestLoadCuratedLogo_AFailedDownloadRendersWithoutALogo(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	manager := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()).Verifiers().LogoManager()

	require.Nil(t, LoadCuratedLogo(context.Background(), manager, server.Client(), server.URL),
		"a logo that will not download is an entry that carries none, not a failure")
}

func TestLoadCuratedLogo_NoUriAndNoManagerYieldNothing(t *testing.T) {
	manager := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()).Verifiers().LogoManager()

	require.Nil(t, LoadCuratedLogo(context.Background(), manager, http.DefaultClient, ""))
	require.Nil(t, LoadCuratedLogo(context.Background(), nil, http.DefaultClient, "https://logos.example.com/a.png"))
}
