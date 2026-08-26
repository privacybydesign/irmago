package services

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
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

	// DisplayIsFallback reports that the text above came from a language other
	// than the one asked for. See CredentialDisplayIsFallback.
	DisplayIsFallback bool

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

// CredentialDisplayIsFallback reports whether a batch's stored display metadata
// has nothing in the language asked for, so its text resolves from another one.
//
// Read off the credential's own display entries: an issuer publishing a locale
// publishes it for the credential, its claims and itself together, and the
// credential name is the entry that always exists when any do. The frontend needs
// one answer per credential, not one per string, since it substitutes a label set
// rather than individual words.
//
// True when there is no display metadata at all: there is then no issuer text in
// any language, which is the strongest case for a client using its own.
func CredentialDisplayIsFallback(batch *models.CredentialBatch, locale string) bool {
	if batch.CredentialMetadata == nil {
		return true
	}
	names := CredentialNamesByLanguage(batch.CredentialMetadata.Display)
	return clientmodels.IsFallbackLanguage(locale, clientmodels.BundleLanguage(locale, names))
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

	d.DisplayIsFallback = CredentialDisplayIsFallback(batch, locale)

	if batch.CredentialMetadata == nil {
		return d
	}
	d.CredentialName = clientmodels.Resolve(CredentialNamesByLanguage(batch.CredentialMetadata.Display), locale)

	bareElementClaims := map[string][]any{}
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
		if element, ok := bareElementPath(path); ok {
			if _, taken := bareElementClaims[element]; !taken {
				bareElementClaims[element] = path
			}
		}
	}
	aliasMdocBareElementPaths(&d, batch, bareElementClaims)
	return d
}

// aliasMdocBareElementPaths indexes an mdoc's one-component claim metadata under
// the two-component path its values actually live at.
//
// An mdoc claim path is [namespace, elementIdentifier], but OpenID4VCI's mso_mdoc
// profile specifies no display metadata at all, so nothing obliges an issuer to
// publish the two-component form -- and real ones publish the bare element.
// Callers look display names up by the path they walked to reach a value, which is
// always two components, so a bare-element entry matches nothing and the attribute
// renders with no label at all: the credential list shows a namespace-nested,
// unlabelled row while the disclosure screen for the very same credential labels it
// correctly, because eudi/openid4vp/mdoc_dcql applies this same fallback itself
// (see claimDisplayName there, which also logs the issuer-side fix once per
// disclosure -- deliberately not repeated here, since this runs on every list
// render).
//
// Aliases never overwrite: a correctly published [namespace, element] path always
// wins, and the alias is only added for namespaces the credential actually carries.
func aliasMdocBareElementPaths(d *ResolvedBatchDisplay, batch *models.CredentialBatch, bareElementClaims map[string][]any) {
	if batch.Format != models.CredentialFormatMsoMdoc || len(bareElementClaims) == 0 {
		return
	}

	// An mdoc's stored payload is namespace -> elementIdentifier -> value, which
	// is where the namespaces the issuer left out come from.
	var resolved map[string]map[string]any
	if err := json.Unmarshal(batch.ProcessedSdJwtPayload, &resolved); err != nil {
		return
	}

	for namespace, elements := range resolved {
		for element := range elements {
			barePath, published := bareElementClaims[element]
			if !published {
				continue
			}
			bareKey := clientmodels.ClaimPathKey(barePath)
			aliasKey := clientmodels.ClaimPathKey([]any{namespace, element})

			if name, ok := d.ClaimNames[bareKey]; ok {
				if _, exact := d.ClaimNames[aliasKey]; !exact {
					d.ClaimNames[aliasKey] = name
				}
			}
			if order, ok := d.ClaimOrder[bareKey]; ok {
				if _, exact := d.ClaimOrder[aliasKey]; !exact {
					d.ClaimOrder[aliasKey] = order
				}
			}
		}
	}
}

// bareElementPath reports whether a claim path is a single string component, the
// namespace-less form an mdoc issuer may publish.
func bareElementPath(path []any) (element string, ok bool) {
	if len(path) != 1 {
		return "", false
	}
	element, ok = path[0].(string)
	return element, ok
}
