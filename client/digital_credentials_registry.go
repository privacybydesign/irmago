package client

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
)

// GetDigitalCredentialsRegistry returns the credentials a website can ask this
// wallet for through the W3C Digital Credentials API, for the app to register
// with the platform. Texts are resolved to the current locale.
//
// The entries come from two places:
//
//   - The credential types of the installed schemes, as dc+sd-jwt with the
//     credential type identifier as vct. They are listed whether or not the
//     wallet holds them: a user who is asked for one they do not have is taken
//     through obtaining it, as in any other disclosure. Demo schemes are only
//     listed in developer mode.
//   - The credentials the wallet obtained over OpenID4VCI (SD-JWT VC, mso_mdoc
//     and SD-JWT-secured VCDM), one entry per format and type. No scheme
//     describes these, so only what the wallet holds can be listed. The types
//     and claim names are registered, never a value.
//
// The order is stable, so an unchanged wallet gives an unchanged registry and
// whoever stores it can tell that nothing is to be done.
//
// When the stored credentials cannot be read, the scheme entries are returned
// together with the error.
func (client *Client) GetDigitalCredentialsRegistry() ([]*clientmodels.DigitalCredentialsRegistryEntry, error) {
	entries := schemeDigitalCredentialsRegistryEntries(
		client.irmaClient.Configuration,
		client.locale(),
		client.irmaClient.Preferences.DeveloperMode,
	)

	held, err := client.listEudiCredentials()
	if err != nil {
		sortDigitalCredentialsRegistryEntries(entries)
		return entries, fmt.Errorf("failed to get OID4VCI credentials from storage: %v", err)
	}
	entries = append(entries, heldDigitalCredentialsRegistryEntries(held)...)

	sortDigitalCredentialsRegistryEntries(entries)
	return entries, nil
}

func sortDigitalCredentialsRegistryEntries(entries []*clientmodels.DigitalCredentialsRegistryEntry) {
	slices.SortStableFunc(entries, func(a, b *clientmodels.DigitalCredentialsRegistryEntry) int {
		return cmp.Compare(a.Id, b.Id)
	})
}

// digitalCredentialsRegistryEntryId is unique per format and type. The format
// is part of it because a vct and a docType are free to be the same string.
func digitalCredentialsRegistryEntryId(format clientmodels.CredentialFormat, credentialType string) string {
	return string(format) + ":" + credentialType
}

// schemeDigitalCredentialsRegistryEntries lists every credential type of the
// configuration as a dc+sd-jwt, which is how irma_sdjwt_dcql answers a request
// for one.
func schemeDigitalCredentialsRegistryEntries(
	conf *irma.Configuration,
	locale string,
	includeDemoSchemes bool,
) []*clientmodels.DigitalCredentialsRegistryEntry {
	entries := []*clientmodels.DigitalCredentialsRegistryEntry{}

	for id, credType := range conf.CredentialTypes {
		if credType == nil {
			continue
		}
		scheme := conf.SchemeManagers[credType.SchemeManagerIdentifier()]
		if scheme == nil || (scheme.Demo && !includeDemoSchemes) {
			continue
		}

		claims := []clientmodels.DigitalCredentialsRegistryClaim{}
		for _, attr := range sortedAttributeTypes(credType.AttributeTypes) {
			// A revocation attribute is never disclosed.
			if attr.RevocationAttribute {
				continue
			}
			name := attr.ID
			if displayName, _ := attr.ResolveTexts(locale); displayName != nil && *displayName != "" {
				name = *displayName
			}
			claims = append(claims, clientmodels.DigitalCredentialsRegistryClaim{
				Path: []string{attr.ID},
				Name: name,
			})
		}
		// Without a claim there is nothing a request could match on.
		if len(claims) == 0 {
			continue
		}

		name, _, _ := credType.ResolveTexts(locale)
		issuerName := ""
		if issuer, ok := conf.Issuers[credType.IssuerIdentifier()]; ok && issuer != nil {
			issuerName = clientmodels.Resolve(clientmodels.TranslatedString(issuer.Name), locale)
		}

		entry := &clientmodels.DigitalCredentialsRegistryEntry{
			Id:         digitalCredentialsRegistryEntryId(clientmodels.Format_SdJwtVc, id.String()),
			Format:     clientmodels.Format_SdJwtVc,
			Type:       id.String(),
			Name:       name,
			IssuerName: issuerName,
			Claims:     claims,
		}
		// The scheme's logos are plain files, and there are many of them: the
		// app reads the ones it needs instead of receiving them all.
		if logo := credType.Logo(conf); logo != "" {
			entry.LogoPath = &logo
		}
		entries = append(entries, entry)
	}

	return entries
}

// heldDigitalCredentialsRegistryEntries lists the given stored credentials, one
// entry per format and type. Several credentials of one type become one entry
// that carries the claims of all of them, named and pictured as the first.
func heldDigitalCredentialsRegistryEntries(credentials []*clientmodels.Credential) []*clientmodels.DigitalCredentialsRegistryEntry {
	entries := []*clientmodels.DigitalCredentialsRegistryEntry{}
	byId := map[string]*clientmodels.DigitalCredentialsRegistryEntry{}
	seenClaims := map[string]map[string]struct{}{}

	for _, credential := range credentials {
		if credential == nil || credential.CredentialId == "" {
			continue
		}
		claims := digitalCredentialsRegistryClaims(credential.Attributes)

		// A credential rendered from a store has one format; one that was
		// merged over formats is listed under each.
		formats := make([]clientmodels.CredentialFormat, 0, len(credential.CredentialInstanceIds))
		for format := range credential.CredentialInstanceIds {
			formats = append(formats, format)
		}
		slices.Sort(formats)

		for _, format := range formats {
			formatClaims := claims
			if format == clientmodels.Format_MsoMdoc {
				formatClaims = mdocDigitalCredentialsRegistryClaims(claims)
			}
			if len(formatClaims) == 0 {
				continue
			}

			id := digitalCredentialsRegistryEntryId(format, credential.CredentialId)
			entry, ok := byId[id]
			if !ok {
				entry = &clientmodels.DigitalCredentialsRegistryEntry{
					Id:         id,
					Format:     format,
					Type:       credential.CredentialId,
					Name:       credential.Name,
					IssuerName: credential.Issuer.Name,
					Logo:       credential.Image,
					Claims:     []clientmodels.DigitalCredentialsRegistryClaim{},
				}
				byId[id] = entry
				seenClaims[id] = map[string]struct{}{}
				entries = append(entries, entry)
			}

			for _, claim := range formatClaims {
				key := strings.Join(claim.Path, "\x00")
				if _, dup := seenClaims[id][key]; dup {
					continue
				}
				seenClaims[id][key] = struct{}{}
				entry.Claims = append(entry.Claims, claim)
			}
		}
	}

	return entries
}

// digitalCredentialsRegistryClaims reduces the attribute rows of a credential
// to the claims a request can name. A row inside an array is registered as the
// array: its path is cut at the first index. Rows that then share a path
// collapse into the first, which is the row that names the array or object.
func digitalCredentialsRegistryClaims(attributes []clientmodels.Attribute) []clientmodels.DigitalCredentialsRegistryClaim {
	claims := []clientmodels.DigitalCredentialsRegistryClaim{}
	seen := map[string]struct{}{}

	for _, attribute := range attributes {
		path := make([]string, 0, len(attribute.ClaimPath))
		whole := true
		for _, element := range attribute.ClaimPath {
			key, ok := element.(string)
			if !ok {
				whole = false
				break
			}
			path = append(path, key)
		}
		if len(path) == 0 {
			continue
		}

		key := strings.Join(path, "\x00")
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		name := path[len(path)-1]
		// A display name of a cut path belongs to the element, not the array.
		if whole && attribute.DisplayName != nil && *attribute.DisplayName != "" {
			name = *attribute.DisplayName
		}
		claims = append(claims, clientmodels.DigitalCredentialsRegistryClaim{Path: path, Name: name})
	}

	return claims
}

// mdocDigitalCredentialsRegistryClaims keeps the elements of an mso_mdoc: a
// request names an element by its namespace and identifier, never by what is
// inside its value.
func mdocDigitalCredentialsRegistryClaims(claims []clientmodels.DigitalCredentialsRegistryClaim) []clientmodels.DigitalCredentialsRegistryClaim {
	elements := []clientmodels.DigitalCredentialsRegistryClaim{}
	seen := map[string]struct{}{}

	for _, claim := range claims {
		if len(claim.Path) < 2 {
			continue
		}
		path := claim.Path[:2]
		key := strings.Join(path, "\x00")
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		name := claim.Name
		if len(claim.Path) > 2 {
			name = path[1]
		}
		elements = append(elements, clientmodels.DigitalCredentialsRegistryClaim{Path: path, Name: name})
	}

	return elements
}
