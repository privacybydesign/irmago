package services

import (
	"encoding/json"
	"regexp"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// Display resolution for stored mdocs (models.MdocBatch).
//
// An mdoc batch carries its OpenID4VCI display metadata as two JSON snapshots —
// the issuer metadata's display[] and the credential configuration's
// credential_metadata — decoded here into the metadata types they were
// published as. There is no normalized tree and nothing to preload, so a
// missing preload cannot blank a name the way it can on the SD-JWT side.
//
// The output is the same ResolvedBatchDisplay the SD-JWT resolver produces: the
// struct is format-neutral (names and order keyed by claim path), and the
// credential list, the log service and the DCQL handlers consume it without
// knowing which format filled it.

// MdocIssuerDisplays decodes the batch's issuer display snapshot. Malformed or
// absent JSON reads as no display entries, the same degradation an issuer that
// published none gets.
func MdocIssuerDisplays(batch *models.MdocBatch) metadata.CredentialIssuerDisplays {
	if len(batch.IssuerDisplay) == 0 {
		return nil
	}
	var displays metadata.CredentialIssuerDisplays
	if err := json.Unmarshal(batch.IssuerDisplay, &displays); err != nil {
		return nil
	}
	return displays
}

// MdocCredentialMetadata decodes the batch's credential_metadata snapshot, or
// returns nil when the issuer advertised none (or the snapshot is unreadable).
func MdocCredentialMetadata(batch *models.MdocBatch) *metadata.CredentialMetadata {
	if len(batch.CredentialMetadata) == 0 {
		return nil
	}
	var cm metadata.CredentialMetadata
	if err := json.Unmarshal(batch.CredentialMetadata, &cm); err != nil {
		return nil
	}
	return &cm
}

func displayLanguageOf(locale *string) string {
	if locale != nil {
		if base, ok := metadata.TryGetBaseLanguageFromLocale(*locale); ok {
			return base
		}
	}
	return clientmodels.DefaultFallbackLanguage
}

// namesByLanguage maps base language → display name over any published display
// list.
func namesByLanguage[T metadata.Translateable](items []T) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	for _, item := range items {
		result[displayLanguageOf(item.GetLocale())] = item.GetName()
	}
	return result
}

// MdocIssuerNamesByLanguage maps base language → issuer display name.
func MdocIssuerNamesByLanguage(displays metadata.CredentialIssuerDisplays) clientmodels.TranslatedString {
	return namesByLanguage(displays)
}

// MdocIssuerLogoURIsByLanguage maps base language → issuer logo URI over the
// displays that carry a logo.
func MdocIssuerLogoURIsByLanguage(displays metadata.CredentialIssuerDisplays) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	for _, d := range displays {
		if d.Logo != nil && d.Logo.Uri != "" {
			result[displayLanguageOf(d.Locale)] = d.Logo.Uri
		}
	}
	return result
}

// MdocCredentialNamesByLanguage maps base language → credential display name.
func MdocCredentialNamesByLanguage(displays metadata.CredentialDisplays) clientmodels.TranslatedString {
	return namesByLanguage(displays)
}

// MdocCredentialLogoURIsByLanguage maps base language → credential logo URI
// over the displays that carry a logo.
func MdocCredentialLogoURIsByLanguage(displays metadata.CredentialDisplays) clientmodels.TranslatedString {
	result := clientmodels.TranslatedString{}
	for _, d := range displays {
		if d.Logo != nil && d.Logo.Uri != "" {
			result[displayLanguageOf(d.Locale)] = d.Logo.Uri
		}
	}
	return result
}

// MdocDisplayIsFallback reports whether the batch's display metadata has
// nothing in the language asked for, so its text resolves from another one.
// True when there is no credential display metadata at all. Same contract as
// CredentialDisplayIsFallback on the SD-JWT side.
func MdocDisplayIsFallback(batch *models.MdocBatch, locale string) bool {
	cm := MdocCredentialMetadata(batch)
	if cm == nil || len(cm.Display) == 0 {
		return true
	}
	names := MdocCredentialNamesByLanguage(cm.Display)
	return clientmodels.IsFallbackLanguage(locale, clientmodels.BundleLanguage(locale, names))
}

// ResolveMdocDisplay resolves everything an mdoc batch's display metadata says,
// for one locale, in one pass. CredentialName is "" when the batch carries no
// resolvable credential name, so callers can tell "no live name" from a real
// one; the credential list applies its docType fallback at its call site.
//
// Two mdoc-specific passes follow the published metadata. Issuers publish
// one-component claim paths (a bare element identifier) where the values live
// under [namespace, element], so those are aliased to the two-component path.
// And elements the metadata never named at all get a derived name, or failing
// that their identifier, so nothing the credential carries renders nameless.
func ResolveMdocDisplay(batch *models.MdocBatch, locale string) ResolvedBatchDisplay {
	issuerDisplays := MdocIssuerDisplays(batch)
	d := ResolvedBatchDisplay{
		IssuerId:    batch.CredentialIssuer,
		IssuerNames: MdocIssuerNamesByLanguage(issuerDisplays),
		ClaimNames:  map[string]string{},
		ClaimOrder:  map[string]int{},
	}
	d.IssuerName = clientmodels.Resolve(d.IssuerNames, locale)
	d.DisplayIsFallback = MdocDisplayIsFallback(batch, locale)

	if cm := MdocCredentialMetadata(batch); cm != nil {
		d.CredentialName = clientmodels.Resolve(MdocCredentialNamesByLanguage(cm.Display), locale)

		bareElementClaims := map[string][]any{}
		for i, claim := range cm.Claims {
			path := []any(claim.Path)
			key := clientmodels.ClaimPathKey(path)
			d.ClaimOrder[key] = i
			if len(claim.Display) > 0 {
				d.ClaimNames[key] = clientmodels.Resolve(namesByLanguage(claim.Display), locale)
			}
			if element, ok := bareElementPath(path); ok {
				if _, taken := bareElementClaims[element]; !taken {
					bareElementClaims[element] = path
				}
			}
		}
		aliasMdocBareElementPaths(&d, batch.Namespaces, bareElementClaims)
	}
	addDerivedMdocClaimNames(&d, batch.Namespaces)
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
// correctly.
//
// Aliases never overwrite: a correctly published [namespace, element] path always
// wins, and the alias is only added for namespaces the credential actually carries.
func aliasMdocBareElementPaths(d *ResolvedBatchDisplay, namespaces map[string]map[string]any, bareElementClaims map[string][]any) {
	if len(bareElementClaims) == 0 {
		return
	}
	for namespace, elements := range namespaces {
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

// mdocAgeOverElement matches the age_over_NN element identifier: the one mdoc
// element name whose meaning is carried entirely by the name itself.
//
// NN is at most two digits, so 99 is the highest threshold this names. That is
// the form ISO 18013-5 defines and the only one an age threshold has any use
// for; a three-digit element identifier is something else wearing the same
// prefix, and guessing a label for it would be inventing meaning rather than
// reading it. One digit is tolerated because refusing it would only cost a
// label -- the element is stored and shown either way.
var mdocAgeOverElement = regexp.MustCompile(`^age_over_([0-9]{1,2})$`)

// DerivedMdocClaimName derives a display name for an mdoc element from the
// element identifier alone, for elements the issuer published no usable name
// for. It reports false for every element it has no rule for, which is all of
// them but age_over_NN with NN at most two digits.
//
// Reporting false is not a rejection. An element this declines to name is still
// verified, stored and disclosed like any other — it renders as its own
// identifier, which is what every mdoc element without display metadata did
// before this existed. Nothing in irmago holds a list of permitted elements, and
// this must not become one.
//
// age_over_NN qualifies because it is the one element whose meaning is fully
// determined by its name, and the one set metadata cannot be relied on to cover.
// ISO 18013-5 and the EUDI age-verification profile both leave the thresholds
// open — an issuer may mint any NN — while OpenID4VCI metadata names only the
// ones that issuer chose to advertise, and nothing requires the two to agree.
// The derived name is mechanical ("Age Over 21"), matching the convention
// issuers' own display entries already use, so a derived label and a published
// one read alike.
//
// This is a cosmetic improvement rather than the thing keeping an element
// visible: addDerivedMdocClaimNames falls back to the raw element identifier for
// anything nothing else names, so an unadvertised threshold renders either way —
// "Age Over 91" with this, "age_over_91" without.
//
// Note for anyone reproducing the gap it covers: the EUDI reference issuer
// cannot. Measured on 2026-08-31, it mints only the thirteen thresholds it
// advertises (13, 15, 16, 18, 21, 23, 25, 27, 28, 40, 60, 65, 67) and silently
// discards any other claim it is asked for, an email address included. That is
// sound behaviour but not required behaviour — an issuer signing an element it
// never declared violates nothing in either specification — so the wallet cannot
// assume it. The realistic source is not a hostile issuer but metadata drift: an
// element added to issuance code and not to credential_configurations_supported.
// Build such a credential with mdoc.Issuer.Issue, which is format-generic, not
// by asking the reference issuer for it.
//
// English only, deliberately. This stands in for metadata the issuer did not
// publish; it is not a translation table, and the wallet's localized labels
// still belong app-side, keyed by docType and element — which is what
// display_is_fallback exists to signal. Issuer text always wins: every caller
// consults this only once the published metadata has been ruled out.
func DerivedMdocClaimName(elementIdentifier string) (string, bool) {
	m := mdocAgeOverElement.FindStringSubmatch(elementIdentifier)
	if m == nil {
		return "", false
	}
	return "Age Over " + m[1], true
}

// addDerivedMdocClaimNames names the mdoc elements no metadata entry covers,
// keyed by the two-component path their values actually live at.
//
// Runs last and never displaces text: a published name wins, including a
// bare-element one aliased in by aliasMdocBareElementPaths. A key present but
// empty is not text — it means the issuer declared the claim and published no
// name this locale can use — so a derived name replaces it rather than leaving
// the credential list to emit a blank label.
func addDerivedMdocClaimNames(d *ResolvedBatchDisplay, namespaces map[string]map[string]any) {
	for namespace, elements := range namespaces {
		for element := range elements {
			key := clientmodels.ClaimPathKey([]any{namespace, element})
			if published, taken := d.ClaimNames[key]; taken && published != "" {
				continue
			}
			name, ok := DerivedMdocClaimName(element)
			if !ok {
				// Nothing names this element: the issuer's metadata never
				// declared it, and it is not an age_over_NN. Use the element
				// identifier rather than leaving it nameless.
				//
				// An mdoc's stored namespaces are what the issuer signed, not
				// what it advertised, and nothing rejects an element the metadata
				// omits: the docType binding in session.obtainCredential works one
				// level up, and the document signer's EKU one level up from that.
				// So an undeclared element is stored and is disclosable through
				// DCQL, while reaching the app as an Attribute with a nil
				// DisplayName — FlattenClaimValue's scalar case appends it either
				// way. Whether a nameless attribute then renders as a blank row or
				// as nothing at all is the app's decision, not ours, which is what
				// makes "present but invisible" possible. The raw identifier is
				// poor text, but it is honest, and it keeps a credential's true
				// contents visible to the person holding it.
				//
				// Deliberately narrow: only elements nothing else names. A claim
				// the issuer declared but left untranslated for this locale keeps
				// its published (possibly empty) name, so the app's own label
				// table still governs those — see display_is_fallback.
				name = element
			}
			d.ClaimNames[key] = name
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
