package services

import (
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
)

// BuildMdocLogCredential records what left the wallet in one mdoc presentation,
// as the same rows the permission screen showed for it.
//
// It lives here rather than in a transport package because an mdoc disclosed
// over OpenID4VP and the same mdoc disclosed over org-iso-mdoc must be recorded
// identically. A log that described the same credential differently depending on
// how it was asked for would make the activity list the one place a user cannot
// compare two disclosures -- and the org-iso-mdoc case is where it matters most,
// since a zero-knowledge presentation reveals nothing to anyone watching and the
// wallet's own log is the only record the user will ever have that it happened.
//
// claimPaths say what left the wallet; claims say what the verifier said about
// it. Both are needed: the verifier's intent to retain is recorded per row, as
// the screen showed it, because a log that forgets it leaves the user unable to
// see later what they agreed to. The mdoc cannot enforce that promise, so
// remembering it is the only thing the wallet can do about it.
func BuildMdocLogCredential(
	store storage.Storage,
	batch *models.MdocBatch,
	claimPaths [][]any,
	claims []dcql.Claim,
	locale string,
) clientmodels.LogCredential {
	attributes := BuildMdocAttributesForElements(batch, UniqueMdocElementRefs(claimPaths), locale)
	attributes = StampMdocIntentToRetain(attributes, claims)

	signedAt := batch.SignedAt.Unix()
	expiry := batch.ValidUntil.Unix()

	return clientmodels.LogCredential{
		CredentialId: batch.DocType,
		Formats:      []clientmodels.CredentialFormat{clientmodels.Format_MsoMdoc},
		Name:         MdocDisplayName(batch, locale),
		Image:        MdocCredentialImage(store, batch, locale),
		Issuer:       MdocIssuerTrustedParty(store, batch, locale),
		Attributes:   attributes,
		ExpiryDate:   &expiry,
		IssuanceDate: &signedAt,
	}
}

// StampMdocIntentToRetain records, against each disclosed row, what the verifier
// said it would do with it.
//
// Only mso_mdoc can say this at all, so the distinction a reader of the log has
// to be able to draw is "the verifier said it will not retain this" from "this
// format cannot say" -- which is why the field is a pointer and is left nil
// where no claim matched.
func StampMdocIntentToRetain(
	attributes []clientmodels.Attribute,
	claims []dcql.Claim,
) []clientmodels.Attribute {
	claimByRef := make(map[MdocElementRef]dcql.Claim, len(claims))
	for _, claim := range claims {
		ref, ok := MdocElementRefFromPath(claim.Path)
		if !ok {
			continue
		}
		if _, duplicate := claimByRef[ref]; !duplicate {
			claimByRef[ref] = claim
		}
	}
	for i := range attributes {
		ref, ok := MdocElementRefFromPath(attributes[i].ClaimPath)
		if !ok {
			continue
		}
		claim, ok := claimByRef[ref]
		if !ok {
			continue
		}
		intentToRetain := claim.IntentToRetain
		attributes[i].IntentToRetain = &intentToRetain
	}
	return attributes
}

// MdocDisplayName resolves a credential's display name from its stored metadata,
// falling back to the docType when there is none.
func MdocDisplayName(batch *models.MdocBatch, locale string) string {
	if metadata := MdocCredentialMetadata(batch); metadata != nil {
		if names := MdocCredentialNamesByLanguage(metadata.Display); len(names) > 0 {
			return clientmodels.Resolve(names, locale)
		}
	}
	return batch.DocType
}

// MdocCredentialImage loads the credential logo that resolves for the locale.
func MdocCredentialImage(store storage.Storage, batch *models.MdocBatch, locale string) *clientmodels.Image {
	metadata := MdocCredentialMetadata(batch)
	if metadata == nil {
		return nil
	}
	return LoadResolvedLogo(
		store.FileSystem().Credentials().LogoManager(),
		MdocCredentialLogoURIsByLanguage(metadata.Display),
		locale,
	)
}

// MdocIssuerTrustedParty builds a TrustedParty from the stored issuer display
// metadata.
func MdocIssuerTrustedParty(store storage.Storage, batch *models.MdocBatch, locale string) clientmodels.TrustedParty {
	return clientmodels.TrustedParty{
		Id:   batch.CredentialIssuer,
		Name: clientmodels.Resolve(MdocIssuerNamesByLanguage(MdocIssuerDisplays(batch)), locale),
		Image: LoadResolvedLogo(
			store.FileSystem().Issuers().LogoManager(),
			MdocIssuerLogoURIsByLanguage(MdocIssuerDisplays(batch)),
			locale,
		),
		Verified: batch.IssuerVerified,
	}
}
