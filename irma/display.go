package irma

import "github.com/privacybydesign/irmago/common/clientmodels"

// This file holds the rules for turning IRMA scheme descriptions into
// app-facing text for one locale. They live in `irma`, below every consumer,
// because both the credential store (`client`) and OpenID4VP disclosure of
// IRMA SD-JWTs (`eudi/openid4vp/irma_sdjwt_dcql`) need them and `client`
// imports that handler, so neither can import the other. Which fields share a
// language is a product decision; keeping it in one place is what stops the
// two paths from drifting apart.

// Resolve returns the translation for the given locale following the fallback
// chain of clientmodels.BundleLanguage: exact locale → base language → English
// → raw ("") value → lowest remaining key. Use it instead of indexing the map
// with a literal language, which silently returns "" for every other language.
func (ts TranslatedString) Resolve(locale string) string {
	return clientmodels.Resolve(clientmodels.TranslatedString(ts), locale)
}

// ResolveTexts resolves a credential type's name and category as one text
// bundle: a single language for both fields, so a card never shows a Dutch
// name above an English category. The issue URL is resolved independently —
// it is a link, not displayed text, so it carries no mixed-language risk and
// must not disappear because the bundle settled on a language that lacks it.
func (ct *CredentialType) ResolveTexts(locale string) (name string, category *string, issueURL *string) {
	nameTS := clientmodels.TranslatedString(ct.Name)
	categoryTS := ct.Category.ToClientmodels()
	lang := clientmodels.BundleLanguage(locale, nameTS, categoryTS)
	return nameTS[lang],
		clientmodels.PtrIfNonEmpty(categoryTS[lang]),
		clientmodels.ResolvePtr(ct.IssueURL.ToClientmodels(), locale)
}

// ResolveTexts resolves an attribute type's display name and description as
// one text bundle: a single language for both fields.
func (at *AttributeType) ResolveTexts(locale string) (displayName *string, description *string) {
	nameTS := clientmodels.TranslatedString(at.Name)
	descTS := clientmodels.TranslatedString(at.Description)
	lang := clientmodels.BundleLanguage(locale, nameTS, descTS)
	return clientmodels.PtrIfNonEmpty(nameTS[lang]), clientmodels.PtrIfNonEmpty(descTS[lang])
}

// ToTrustedParty builds a TrustedParty for an issuer, including its logo and
// the scheme manager as parent. Each party resolves its own text bundle.
func (issuer *Issuer) ToTrustedParty(conf *Configuration, locale string) clientmodels.TrustedParty {
	scheme := conf.SchemeManagers[issuer.SchemeManagerIdentifier()]
	parent := clientmodels.TrustedParty{
		Id:       scheme.Identifier().String(),
		Name:     clientmodels.Resolve(clientmodels.TranslatedString(scheme.Name), locale),
		Verified: scheme.Status == SchemeManagerStatusValid,
	}
	return clientmodels.TrustedParty{
		Id:       issuer.Identifier().String(),
		Name:     clientmodels.Resolve(clientmodels.TranslatedString(issuer.Name), locale),
		Image:    clientmodels.ImageFromFile(issuer.Logo(conf)),
		Verified: scheme.Status == SchemeManagerStatusValid,
		Parent:   &parent,
	}
}
