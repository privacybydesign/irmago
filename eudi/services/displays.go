package services

import (
	"net/http"
	"sort"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"gorm.io/datatypes"
)

// The helpers below reduce stored display lists to base-language-keyed maps
// so text and logos can be resolved through the locale fallback chain
// (clientmodels.Resolve). Names and logos are mapped separately: text
// resolves as one bundle per object, while the logo falls back across
// languages independently.

func displayLanguage(locale datatypes.NullString) string {
	if locale.Valid {
		if base, ok := metadata.TryGetBaseLanguageFromLocale(locale.V); ok {
			return base
		}
	}
	return clientmodels.DefaultFallbackLanguage
}

// IssuerNamesByLanguage maps base language → issuer display name.
func IssuerNamesByLanguage(displays []models.IssuerMetadataDisplay) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	for _, d := range displays {
		result[displayLanguage(d.Locale)] = d.Name
	}
	return result
}

// IssuerLogoURIsByLanguage maps base language → issuer logo URI over the
// displays that carry a logo.
func IssuerLogoURIsByLanguage(displays []models.IssuerMetadataDisplay) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	for _, d := range displays {
		if d.LogoURI.Valid && d.LogoURI.V != "" {
			result[displayLanguage(d.Locale)] = d.LogoURI.V
		}
	}
	return result
}

// CredentialNamesByLanguage maps base language → credential display name.
func CredentialNamesByLanguage(displays []models.CredentialDisplay) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	for _, d := range displays {
		result[displayLanguage(d.Locale)] = d.Name
	}
	return result
}

// CredentialLogoURIsByLanguage maps base language → credential logo URI over
// the displays that carry a logo.
func CredentialLogoURIsByLanguage(displays []models.CredentialDisplay) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	for _, d := range displays {
		if d.LogoURI != "" {
			result[displayLanguage(d.Locale)] = d.LogoURI
		}
	}
	return result
}

// ClaimNamesByLanguage maps base language → claim display name.
func ClaimNamesByLanguage(displays []models.ClaimDisplay) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	for _, d := range displays {
		result[displayLanguage(d.Locale)] = d.Name
	}
	return result
}

// LoadResolvedLogo loads the logo the fallback chain resolves for the locale
// from the given language→URI map. When that logo is not cached (yet — e.g.
// right after a locale switch, before the backfill sweep has fetched it), any
// other cached display logo is returned instead, in deterministic key order,
// so a logo still shows while the preferred one is on its way.
func LoadResolvedLogo(manager filesystem.LogoManager, uris clientmodels.TranslatedString, locale string) *clientmodels.Image {
	if img := eudi.LoadLogoImage(manager, clientmodels.Resolve(uris, locale)); img != nil {
		return img
	}
	keys := make([]string, 0, len(uris))
	for k := range uris {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if img := eudi.LoadLogoImage(manager, uris[k]); img != nil {
			return img
		}
	}
	return nil
}

// BackfillLogos downloads the logos that resolve for the given locale but are
// missing from the on-disk cache, for every stored credential batch. Returns
// the number of logos newly cached. Runs in the background on startup and on
// locale changes — never from a listing path, which must stay fast and work
// offline.
func BackfillLogos(s storage.Storage, httpClient *http.Client, locale string) int {
	batches, err := db.NewCredentialStore(s.Db()).GetCredentialBatchList()
	if err != nil {
		eudi.Logger.Warnf("logo backfill: failed to list credential batches: %v", err)
		return 0
	}

	credentialLogos := s.FileSystem().Credentials().LogoManager()
	issuerLogos := s.FileSystem().Issuers().LogoManager()

	added := 0
	for _, batch := range batches {
		if uri := clientmodels.Resolve(IssuerLogoURIsByLanguage(batch.IssuerDisplay), locale); uri != "" {
			added += fetchLogoIfMissing(issuerLogos, httpClient, uri)
		}
		if batch.CredentialMetadata != nil {
			if uri := clientmodels.Resolve(CredentialLogoURIsByLanguage(batch.CredentialMetadata.Display), locale); uri != "" {
				added += fetchLogoIfMissing(credentialLogos, httpClient, uri)
			}
		}
	}
	return added
}

// fetchLogoIfMissing downloads and caches a logo unless it is already cached.
// Returns 1 when a logo was newly cached, 0 otherwise.
func fetchLogoIfMissing(manager filesystem.LogoManager, httpClient *http.Client, uri string) int {
	if exists, err := manager.Exists(uri); err != nil || exists {
		return 0
	}
	data, _, err := helpers.DownloadRemoteImage(httpClient, uri)
	if err != nil {
		eudi.Logger.Warnf("logo backfill: failed to download logo from %q: %v", uri, err)
		return 0
	}
	if err := manager.Save(uri, data); err != nil {
		eudi.Logger.Warnf("logo backfill: failed to cache logo from %q: %v", uri, err)
		return 0
	}
	return 1
}
