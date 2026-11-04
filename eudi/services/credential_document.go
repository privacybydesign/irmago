package services

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// CredentialDocument is what a credential says about itself beyond its claim
// values: how it looks, and which claims are images. Each format builds its
// own, so callers need not know the format. The zero value says nothing, which
// is right for an mdoc: its images are bytes its attribute builders already
// show as pictures.
type CredentialDocument struct {
	payload    map[string]any
	openBadges bool
	display    DocumentDisplay
}

// DocumentDisplay is how a credential says it looks: its name and image, and
// its issuer's name and logo. Each field wins over the OpenID4VCI metadata's
// (OpenID4VCI 1.0 §12.2.4). Names are keyed by base language; an image is a
// URL or data URI, "" for none.
type DocumentDisplay struct {
	CredentialNames clientmodels.TranslatedString
	CredentialImage string
	IssuerNames     clientmodels.TranslatedString
	IssuerImage     string
}

// newSdJwtVcDocument is the document of an SD-JWT VC. Its images are its data
// URI claims; its type metadata is already merged into its metadata.
func newSdJwtVcDocument(payload map[string]any) CredentialDocument {
	return CredentialDocument{payload: payload}
}

// NewSdJwtVcDocumentFromJSON is newSdJwtVcDocument over a stored payload. An
// unreadable payload says nothing.
func NewSdJwtVcDocumentFromJSON(payload []byte) CredentialDocument {
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return CredentialDocument{}
	}
	return newSdJwtVcDocument(decoded)
}

// newVcdmDocument is the document of a VCDM credential with these expanded
// types. The types tell whether it is an Open Badge.
func newVcdmDocument(document vcdm.Document, expandedTypes []string) CredentialDocument {
	openBadges := vcdm.IsOpenBadgesCredential(expandedTypes)
	return CredentialDocument{
		payload:    document,
		openBadges: openBadges,
		display:    vcdmDocumentDisplay(document, openBadges),
	}
}

// NewVcdmDocumentFromJSON is newVcdmDocument over a stored document. An
// unreadable document says nothing.
func NewVcdmDocumentFromJSON(document []byte, expandedTypes []string) CredentialDocument {
	var decoded vcdm.Document
	if err := json.Unmarshal(document, &decoded); err != nil {
		return CredentialDocument{}
	}
	return newVcdmDocument(decoded, expandedTypes)
}

// Document is the document of a freshly issued credential.
func (p *ParsedCredential) Document() CredentialDocument {
	switch {
	case p.SdJwtVc != nil:
		return newSdJwtVcDocument(p.SdJwtVc.ProcessedSdJwtPayload)
	case p.SdJwtVcdm != nil:
		return newVcdmDocument(p.SdJwtVcdm.Document, p.ExpandedTypes)
	default:
		return CredentialDocument{}
	}
}

// Attributes are the attributes the permission screen shows for a freshly
// issued credential, named and ordered by the metadata's claims, with its
// claim images as pictures.
func (p *ParsedCredential) Attributes(claims []metadata.ClaimsDescription, locale string, credentialLogos filesystem.ImageManager) []clientmodels.Attribute {
	claimNames, claimOrder := claimDisplayLookups(claims, locale)
	var attrs []clientmodels.Attribute
	switch {
	case p.SdJwtVc != nil:
		attrs = BuildAttributesFromPayload(&p.SdJwtVc.ProcessedSdJwtPayload, claimNames, claimOrder)
	case p.SdJwtVcdm != nil:
		attrs = buildAttributesFromVcdmDocument(p.SdJwtVcdm.Document, claimNames, claimOrder)
	case p.Mdoc != nil:
		attrs = buildMdocAttributesFromResolvedClaims(claims, p.Mdoc.Namespaces, locale)
	default:
		return []clientmodels.Attribute{}
	}
	return p.Document().ShowImages(attrs, credentialLogos)
}

// Display is how the credential says it looks; empty where it says nothing.
func (d CredentialDocument) Display() DocumentDisplay {
	return d.display
}

// ShowImages turns the claim images among attrs into pictures, taking the
// images behind a URL from credentialLogos. attrs may be any subset of the
// credential's attributes.
func (d CredentialDocument) ShowImages(attrs []clientmodels.Attribute, credentialLogos filesystem.ImageManager) []clientmodels.Attribute {
	return showClaimImages(attrs, d.payload, d.openBadges, d.cachedClaimImages(credentialLogos))
}

// FetchImages downloads the credential's images that are not cached yet: its
// own and its claim images into credentialLogos, its issuer's into
// issuerLogos. Returns how many it cached.
func (d CredentialDocument) FetchImages(ctx context.Context, credentialLogos, issuerLogos filesystem.ImageManager, fetcher ImageFetcher) int {
	cached := fetcher.FetchIfMissing(ctx, credentialLogos, d.display.CredentialImage)
	cached += fetcher.FetchIfMissing(ctx, issuerLogos, d.display.IssuerImage)
	for _, url := range d.downloadableClaimImageURLs() {
		cached += fetcher.FetchIfMissing(ctx, credentialLogos, url)
	}
	return cached
}

// ImageFetcher downloads images into an image cache.
type ImageFetcher struct {
	HTTPClient *http.Client
	// AllowInsecureHTTP allows plain http, for developer mode.
	AllowInsecureHTTP bool
}
