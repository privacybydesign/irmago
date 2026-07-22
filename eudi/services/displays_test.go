package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
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
	require.NoError(t, manager.Save("https://logos.example.com/en.png", []byte("en-logo")))

	uris := clientmodels.TranslatedString{
		"en": "https://logos.example.com/en.png",
		"nl": "https://logos.example.com/nl.png", // resolves for nl, but not cached yet
	}

	img := LoadResolvedLogo(manager, uris, "nl")

	require.NotNil(t, img, "a cached logo should show while the backfill fetches the preferred one")

	require.NoError(t, manager.Save("https://logos.example.com/nl.png", []byte("nl-logo")))
	img = LoadResolvedLogo(manager, uris, "nl")
	require.NotNil(t, img)
}

func TestLoadResolvedLogo_NoLogosCached_ReturnsNil(t *testing.T) {
	fs := filesystem.NewFileSystemStorage([32]byte{}, t.TempDir())
	manager := fs.Credentials().LogoManager()

	img := LoadResolvedLogo(manager, clientmodels.TranslatedString{"en": "https://logos.example.com/en.png"}, "en")

	require.Nil(t, img)
}

type backfillTestStorage struct {
	db *gorm.DB
	fs filesystem.FileSystemStorage
}

func (s *backfillTestStorage) Db() *gorm.DB                             { return s.db }
func (s *backfillTestStorage) FileSystem() filesystem.FileSystemStorage { return s.fs }
func (s *backfillTestStorage) Close() error                             { return nil }
func (s *backfillTestStorage) RemoveAll() error                         { return nil }

func newBackfillTestStorage(t *testing.T) *backfillTestStorage {
	t.Helper()
	d, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("test-key-123"))}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, d.AutoMigrate(
		&models.HolderBindingKey{},
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
		&models.IssuerMetadataDisplay{},
		&models.CredentialMetadata{},
		&models.CredentialDisplay{},
		&models.CredentialClaim{},
		&models.ClaimDisplay{},
		&models.CredentialBatch{},
		&models.IssuedCredentialInstance{},
	))
	return &backfillTestStorage{db: d, fs: filesystem.NewFileSystemStorage([32]byte{}, t.TempDir())}
}

func TestBackfillLogos_FetchesOnlyMissingResolvingLogos(t *testing.T) {
	requests := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests[r.URL.Path]++
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("logo-bytes"))
	}))
	defer server.Close()

	s := newBackfillTestStorage(t)
	batch := &models.CredentialBatch{
		IssuerURL:                "https://issuer.example.com",
		VerifiableCredentialType: "https://vct.example.com/Test",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     "hash1",
		ProcessedSdJwtPayload:    datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                 datatypes.NullTime{V: time.Now(), Valid: true},
		BatchSize:                1,
		RemainingCount:           1,
		CredentialIssuer:         "https://issuer.example.com",
		IssuerDisplay: []models.IssuerMetadataDisplay{
			{Name: "Issuer EN", Locale: nullStr("en"), LogoURI: nullStr(server.URL + "/issuer-en.png")},
			{Name: "Issuer NL", Locale: nullStr("nl"), LogoURI: nullStr(server.URL + "/issuer-nl.png")},
		},
		CredentialMetadata: &models.CredentialMetadata{
			Display: []models.CredentialDisplay{
				{Name: "Cred EN", Locale: nullStr("en"), LogoURI: server.URL + "/cred-en.png"},
				{Name: "Cred NL", Locale: nullStr("nl"), LogoURI: server.URL + "/cred-nl.png"},
			},
		},
		Instances: []models.IssuedCredentialInstance{{RawCredential: []byte("raw")}},
	}
	require.NoError(t, db.NewCredentialStore(s.Db()).StoreBatch(batch))

	// Pre-cache the nl issuer logo: the sweep must not re-download it.
	require.NoError(t, s.FileSystem().Issuers().LogoManager().Save(server.URL+"/issuer-nl.png", []byte("cached")))

	added := BackfillLogos(s, server.Client(), "nl")

	require.Equal(t, 1, added, "only the missing nl credential logo should be fetched")
	require.Equal(t, map[string]int{"/cred-nl.png": 1}, requests,
		"the en logos do not resolve for locale nl and the nl issuer logo is already cached")

	exists, err := s.FileSystem().Credentials().LogoManager().Exists(server.URL + "/cred-nl.png")
	require.NoError(t, err)
	require.True(t, exists, "fetched logo must land in the cache")

	// A second sweep with a warm cache downloads nothing.
	added = BackfillLogos(s, server.Client(), "nl")
	require.Equal(t, 0, added)
	require.Equal(t, 1, requests["/cred-nl.png"])
}
