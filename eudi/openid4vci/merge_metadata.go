package openid4vci

import (
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc/typemetadata"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"golang.org/x/text/language"
)

// Merge combines an SD-JWT VC type metadata document (vct) with an
// OpenID4VCI credential_metadata block (vci) into a single
// CredentialMetadata view. VCT is the authoritative source per OID4VCI
// v1.0 § 12.2.4; VCI fills locales and claims that VCT does not cover.
//
// Granularity is per-locale-entry, not per-field: a locale present in VCT
// is taken from VCT in its entirety, dropping the corresponding VCI entry
// (including VCI-only fields such as BackgroundImage). Locales absent
// from VCT survive from VCI unchanged.
//
// Locale matching is BCP 47 base-language only (en-US and en collapse
// to "en"); on collision the VCT entry wins and the canonical tag
// retained on the output is whatever the winning source supplied. VCI
// nil and empty-string locales share the untagged-locale key with each
// other and with VCT entries that have an empty locale (which the VCT
// parser rejects, so in practice only VCI contributes such entries).
//
// Claim sets are unioned: any claim defined in either source appears in
// the output. Claim paths match strictly element-by-element with numeric
// coercion (JSON-unmarshaled float64 matches Go int). Wildcard null
// elements only match other null elements. On match, Path is taken from
// VCT (cosmetic — both inputs canonicalise equal), Mandatory is taken
// from VCI (VCT has no notion of it), and Display arrays are merged via
// the same per-locale rules.
//
// Output order is VCT-first with VCI-only entries appended in VCI's
// relative order, applied to credential-level Display, Claims, and per-
// claim Display alike.
//
// Either input may be nil. Merge(nil, nil) returns an empty value.
func Merge(vct *typemetadata.VctTypeMetadata, vci *metadata.CredentialMetadata) metadata.CredentialMetadata {
	return metadata.CredentialMetadata{
		Display: mergeCredentialDisplays(vct, vci),
		Claims:  mergeClaims(vct, vci),
	}
}

func mergeCredentialDisplays(vct *typemetadata.VctTypeMetadata, vci *metadata.CredentialMetadata) metadata.CredentialDisplays {
	var out metadata.CredentialDisplays
	emitted := map[string]struct{}{}

	if vct != nil {
		for _, d := range vct.Display {
			key := canonicalLocaleKey(d.Locale)
			if _, seen := emitted[key]; seen {
				continue
			}
			emitted[key] = struct{}{}
			out = append(out, vctDisplayToCredentialDisplay(d))
		}
	}

	if vci != nil {
		for _, d := range vci.Display {
			key := canonicalLocaleKeyFromPtr(d.Locale)
			if _, seen := emitted[key]; seen {
				continue
			}
			emitted[key] = struct{}{}
			out = append(out, d)
		}
	}

	return out
}

func mergeClaims(vct *typemetadata.VctTypeMetadata, vci *metadata.CredentialMetadata) []metadata.ClaimsDescription {
	var out []metadata.ClaimsDescription
	emittedKeys := map[string]struct{}{}

	var vciClaims []metadata.ClaimsDescription
	if vci != nil {
		vciClaims = vci.Claims
	}
	vciByKey := map[string]int{}
	for i, c := range vciClaims {
		if len(c.Path) == 0 {
			continue
		}
		key := clientmodels.ClaimPathKey(c.Path)
		if _, exists := vciByKey[key]; !exists {
			vciByKey[key] = i
		}
	}

	if vct != nil {
		for _, c := range vct.Claims {
			if len(c.Path) == 0 {
				out = append(out, vctClaimToClaimsDescription(c, nil))
				continue
			}
			key := clientmodels.ClaimPathKey(c.Path)
			if _, already := emittedKeys[key]; already {
				continue
			}
			emittedKeys[key] = struct{}{}
			var match *metadata.ClaimsDescription
			if idx, found := vciByKey[key]; found {
				match = &vciClaims[idx]
			}
			out = append(out, vctClaimToClaimsDescription(c, match))
		}
	}

	for _, c := range vciClaims {
		if len(c.Path) == 0 {
			out = append(out, c)
			continue
		}
		key := clientmodels.ClaimPathKey(c.Path)
		if _, already := emittedKeys[key]; already {
			continue
		}
		emittedKeys[key] = struct{}{}
		out = append(out, c)
	}

	return out
}

func vctClaimToClaimsDescription(vct typemetadata.ClaimMetadata, vciMatch *metadata.ClaimsDescription) metadata.ClaimsDescription {
	out := metadata.ClaimsDescription{
		Path: metadata.ClaimsPathPointer(vct.Path),
	}
	var vciDisplay []metadata.Display
	if vciMatch != nil {
		out.Mandatory = vciMatch.Mandatory
		vciDisplay = vciMatch.Display
	}
	out.Display = mergeClaimDisplays(vct.Display, vciDisplay)
	return out
}

func mergeClaimDisplays(vct []typemetadata.ClaimDisplayEntry, vci []metadata.Display) []metadata.Display {
	var out []metadata.Display
	emitted := map[string]struct{}{}
	for _, d := range vct {
		key := canonicalLocaleKey(d.Locale)
		if _, seen := emitted[key]; seen {
			continue
		}
		emitted[key] = struct{}{}
		out = append(out, vctClaimDisplayToDisplay(d))
	}
	for _, d := range vci {
		key := canonicalLocaleKeyFromPtr(d.Locale)
		if _, seen := emitted[key]; seen {
			continue
		}
		emitted[key] = struct{}{}
		out = append(out, d)
	}
	return out
}

func vctDisplayToCredentialDisplay(d typemetadata.DisplayEntry) metadata.CredentialDisplay {
	out := metadata.CredentialDisplay{
		Display:         metadata.Display{Name: d.Name},
		Description:     d.Description,
		BackgroundColor: d.BackgroundColor,
		TextColor:       d.TextColor,
	}
	if d.Locale != "" {
		locale := d.Locale
		out.Display.Locale = &locale
	}
	if d.Logo != nil {
		out.Logo = &metadata.RemoteImage{Uri: d.Logo.URI, AltText: d.Logo.AltText}
	}
	return out
}

func vctClaimDisplayToDisplay(d typemetadata.ClaimDisplayEntry) metadata.Display {
	out := metadata.Display{Name: d.Name}
	if d.Locale != "" {
		locale := d.Locale
		out.Locale = &locale
	}
	return out
}

// canonicalLocaleKey returns the matching key for a locale string. The
// empty string maps to "" (the untagged-locale bucket). Other tags are
// parsed as BCP 47 and reduced to their base-language subtag, so en-US
// and en share the key "en". Unparseable tags fall back to their
// lowercase form so the merge stays deterministic on malformed input.
func canonicalLocaleKey(locale string) string {
	if locale == "" {
		return ""
	}
	tag, err := language.Parse(locale)
	if err != nil {
		return strings.ToLower(locale)
	}
	base, _ := tag.Base()
	return base.String()
}

func canonicalLocaleKeyFromPtr(locale *string) string {
	if locale == nil {
		return ""
	}
	return canonicalLocaleKey(*locale)
}
