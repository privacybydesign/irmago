package clientmodels

import "slices"

// DefaultFallbackLanguage is the language the fallback chain settles on when
// neither the requested locale nor its base language is available. It is the
// one language every user-facing text is expected to carry, so that a locale
// the data was never translated into still yields readable text instead of an
// empty string.
const DefaultFallbackLanguage = "en"

// SupportedLanguages lists the languages this project ships user-facing text
// in, in no particular order of preference. It is a statement of intent, not
// a filter: nothing here restricts which languages may appear in a scheme, in
// SD-JWT VC type metadata or in a keyshare email template. Any BCP 47 language
// tag resolves through the same fallback chain (see BundleLanguage), so a
// scheme translated into a language absent from this list works without a code
// change.
//
// What the list is for is the places that need to enumerate languages rather
// than resolve one: the scheme translation coverage report, deployment
// documentation, and anything that wants to state which languages a release is
// expected to be complete in.
//
// To add a language, add its base language tag here and translate the material
// listed in docs/translations.md.
var SupportedLanguages = []string{
	"en", // English
	"nl", // Dutch
	"fr", // French
	"de", // German
}

// IsSupportedLanguage reports whether lang, or the base language of a locale
// such as "fr-BE", is one of SupportedLanguages.
func IsSupportedLanguage(lang string) bool {
	if slices.Contains(SupportedLanguages, lang) {
		return true
	}
	base, ok := BaseLanguage(lang)
	return ok && slices.Contains(SupportedLanguages, base)
}

// PickLanguage returns the entry of m for the given locale: the exact locale,
// else its base language ("fr-BE" → "fr"). It reports false when neither is
// present and deliberately goes no further: the callers are server-side and
// configuration-driven — a keyshare server's email templates — where the
// operator configures the default and must keep the last word over any
// project-wide preference, and where silently reaching for whichever language
// happens to exist would hide a misconfiguration.
//
// Use it for maps keyed by language whose values are not strings — parsed
// templates, for instance — where TranslatedString and Resolve do not apply.
func PickLanguage[T any](m map[string]T, locale string) (T, bool) {
	if v, ok := m[locale]; ok {
		return v, true
	}
	if base, ok := BaseLanguage(locale); ok {
		if v, ok := m[base]; ok {
			return v, true
		}
	}
	var zero T
	return zero, false
}
