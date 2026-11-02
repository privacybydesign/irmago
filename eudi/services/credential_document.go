package services

import (
	"context"
	"net/http"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// CredentialDocument is what a credential says about itself beyond its claim
// values: how it looks (DocumentDisplay), and which of its claims are images.
// Each format makes its own, from the credential as issued
// (ParsedCredential.Document) or as stored, so a caller shows and downloads a
// credential's images without knowing its format.
//
// The zero value says nothing, which is what an mdoc says: it names neither
// itself nor its issuer, and its images are bytes in its elements, which its
// attribute builders show as pictures (PromoteMdocDataURIs).
type CredentialDocument struct {
	// payload is the credential's full processed payload, in which its claim
	// images are found (findClaimImages).
	payload    map[string]any
	openBadges bool
	display    DocumentDisplay
}

// DocumentDisplay is how a credential says it looks: its name and image, and
// its issuer's name and logo. Each comes before what the OpenID4VCI metadata
// says, per field, as an SD-JWT VC's type metadata does: OpenID4VCI 1.0
// §12.2.4 says "Format-specific mechanisms ... are always preferred by the
// Wallet over the information in this object, which serves as the default
// fallback". The document is also the more specific of the two: the metadata
// describes a credential configuration, the document one credential.
//
// Names are keyed by base language; an image is a URI to download or a data
// URI, "" when there is none.
type DocumentDisplay struct {
	CredentialNames clientmodels.TranslatedString
	CredentialImage string
	IssuerNames     clientmodels.TranslatedString
	IssuerImage     string
}

// NewSdJwtVcDocument is the document of an SD-JWT VC with this processed
// payload. It says nothing of how it looks, since an SD-JWT VC's type metadata
// is merged into its metadata at issuance; its images are its data URI claims.
func NewSdJwtVcDocument(payload map[string]any) CredentialDocument {
	return CredentialDocument{payload: payload}
}

// NewVcdmDocument is the document of a VCDM credential with these expanded
// types (vcdm.ExpandTypes). Its display is read off it (vcdmDocumentDisplay);
// its images are its data URI claims and, in an Open Badges credential, the
// Image objects in its credentialSubject.
func NewVcdmDocument(document vcdm.Document, expandedTypes []string) CredentialDocument {
	openBadges := vcdm.IsOpenBadgesCredential(expandedTypes)
	return CredentialDocument{
		payload:    document,
		openBadges: openBadges,
		display:    vcdmDocumentDisplay(document, openBadges),
	}
}

// Document is the document of a freshly issued credential, by its format.
func (p *ParsedCredential) Document() CredentialDocument {
	switch {
	case p.SdJwtVc != nil:
		return NewSdJwtVcDocument(p.SdJwtVc.ProcessedSdJwtPayload)
	case p.SdJwtVcdm != nil:
		return NewVcdmDocument(p.SdJwtVcdm.Document, p.ExpandedTypes)
	default:
		return CredentialDocument{}
	}
}

// Display is how the credential says it looks; empty where it says nothing.
func (d CredentialDocument) Display() DocumentDisplay {
	return d.display
}

// ShowImages turns the attributes among attrs that are the credential's claim
// images into pictures (showClaimImages), with the images behind a URL from
// credentialLogos, the credential logo cache they share with the credential
// logos. attrs may be any of the credential's attributes, such as those a
// disclosure shows.
func (d CredentialDocument) ShowImages(attrs []clientmodels.Attribute, credentialLogos filesystem.LogoManager) []clientmodels.Attribute {
	return showClaimImages(attrs, d.payload, d.openBadges, cachedClaimImages(credentialLogos, d.payload, d.openBadges))
}

// FetchImages downloads the images the credential points to that are missing
// from the logo caches: its own image into credentialLogos and its issuer's
// into issuerLogos, and its claim images into credentialLogos, under the
// limits ShowImages shows them by. Returns how many it cached. ctx bounds the
// time the claim images may take together.
func (d CredentialDocument) FetchImages(ctx context.Context, credentialLogos, issuerLogos filesystem.LogoManager, fetcher LogoFetcher) int {
	cached := fetcher.FetchIfMissing(ctx, credentialLogos, d.display.CredentialImage)
	cached += fetcher.FetchIfMissing(ctx, issuerLogos, d.display.IssuerImage)
	claimImages, _ := d.fetchClaimImages(ctx, credentialLogos, fetcher)
	return cached + claimImages
}

// fetchClaimImages downloads the credential's claim images into
// credentialLogos (fetchClaimImages), also returning how many downloads it
// tried.
func (d CredentialDocument) fetchClaimImages(ctx context.Context, credentialLogos filesystem.LogoManager, fetcher LogoFetcher) (cached, tried int) {
	return fetchClaimImages(ctx, credentialLogos, fetcher, d.payload, d.openBadges)
}

// LogoFetcher downloads logos and images into a logo cache.
type LogoFetcher struct {
	HTTPClient *http.Client
	// AllowInsecureHTTP lets it download over plain http, as developer mode
	// lets issuance do.
	AllowInsecureHTTP bool
}
