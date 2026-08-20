package services

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/internal/helpers"
	"github.com/privacybydesign/irmago/eudi/metadata"
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
	for _, k := range slices.Sorted(maps.Keys(uris)) {
		if img := eudi.LoadLogoImage(manager, uris[k]); img != nil {
			return img
		}
	}
	return nil
}

// ResolvedBatchDisplay is a stored credential batch's display text, resolved
// once for one locale.
//
// Both the credential list and the activity log need the same handful of
// values per batch, and both used to rebuild them per item — but they depend
// only on (batch, locale), so a page of 50 log entries over 20 credentials
// rebuilt the same maps 50 times, JSON-decoding every claim path each round.
type ResolvedBatchDisplay struct {
	CredentialName string
	IssuerName     string
	IssuerId       string

	// IssuerNames backs the activity log's issuer-identity check, which has to
	// compare a log entry's snapshot name against every language the batch
	// carries.
	IssuerNames clientmodels.TranslatedString

	// ClaimNames maps clientmodels.ClaimPathKey to the resolved claim display
	// name. A claim whose metadata carries no translation for this locale maps
	// to "", which callers distinguish from an absent key: the credential list
	// treats a present-but-empty name as a label it should still emit, the log
	// treats it as "keep the snapshot".
	ClaimNames map[string]string

	// ClaimOrder maps clientmodels.ClaimPathKey to the claim's position in the
	// metadata, so attributes can be shown in issuer order rather than
	// alphabetically. Covers every claim, including those with no display.
	ClaimOrder map[string]int
}

// ResolveBatchDisplay resolves everything a batch's display metadata says, for
// one locale, in one pass.
func ResolveBatchDisplay(batch *models.CredentialBatch, locale string) ResolvedBatchDisplay {
	d := ResolvedBatchDisplay{
		IssuerId:    batch.CredentialIssuerIdentifier,
		IssuerNames: IssuerNamesByLanguage(batch.IssuerDisplay),
		ClaimNames:  map[string]string{},
		ClaimOrder:  map[string]int{},
	}
	d.IssuerName = clientmodels.Resolve(d.IssuerNames, locale)

	if batch.CredentialMetadata == nil {
		return d
	}
	d.CredentialName = clientmodels.Resolve(CredentialNamesByLanguage(batch.CredentialMetadata.Display), locale)

	for i, claim := range batch.CredentialMetadata.Claims {
		var path []any
		if err := json.Unmarshal(claim.Path, &path); err != nil {
			continue
		}
		key := clientmodels.ClaimPathKey(path)
		d.ClaimOrder[key] = i
		if len(claim.Display) > 0 {
			d.ClaimNames[key] = clientmodels.Resolve(ClaimNamesByLanguage(claim.Display), locale)
		}
	}
	return d
}

// CuratedLogoFetchTimeout bounds a curated logo download. Enforced here because
// this is the one logo fetch on a session's path, with the user waiting behind
// it, and the shared HTTP client carries no timeout of its own.
const CuratedLogoFetchTimeout = 10 * time.Second

// LoadCuratedLogo returns the logo a recognized trust list names for a party,
// downloading it on a cache miss. Unlike credential and issuer logos there is no
// backfill sweep behind it, so the first session that meets the party fills the
// cache; the URI comes out of a signed list rather than from the party, which is
// what makes fetching it here safe.
//
// A download that fails is not an error: the party renders without a logo and the
// next session tries again.
func LoadCuratedLogo(ctx context.Context, manager filesystem.LogoManager, httpClient *http.Client, uri string) *clientmodels.Image {
	if uri == "" || manager == nil {
		return nil
	}
	if img := eudi.LoadLogoImage(manager, uri); img != nil {
		return img
	}

	ctx, cancel := context.WithTimeout(ctx, CuratedLogoFetchTimeout)
	defer cancel()

	data, mimeType, err := helpers.DownloadRemoteImage(ctx, httpClient, uri)
	if err != nil {
		eudi.Logger.Warnf("failed to download curated logo %q: %v", uri, err)
		return nil
	}
	if err := manager.Save(uri, data, mimeType); err != nil {
		// The logo is in hand; only caching it failed.
		eudi.Logger.Warnf("failed to cache curated logo %q: %v", uri, err)
	}

	return clientmodels.NewImage(data, mimeType)
}
