package clientmodels

import (
	"sync"

	"golang.org/x/text/language"
)

// CurrentLocale is a thread-safe holder of the wallet's current UI locale.
// The app is the source of truth: it supplies the initial value at client
// construction and updates it on language changes. Long-lived components
// (session clients, disclosure handlers) hold a reference and read the
// current value when building DTOs.
type CurrentLocale struct {
	mu sync.RWMutex
	v  string
}

func NewCurrentLocale(locale string) *CurrentLocale {
	if locale == "" {
		locale = DefaultFallbackLanguage
	}
	return &CurrentLocale{v: locale}
}

// Get is nil-safe: a component constructed without a locale holder resolves
// text with the default fallback language rather than panicking.
func (c *CurrentLocale) Get() string {
	if c == nil {
		return DefaultFallbackLanguage
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.v
}

// Set stores the locale and reports whether it differs from the previous one,
// so callers can skip work when the app re-asserts a locale it already set.
func (c *CurrentLocale) Set(locale string) (changed bool) {
	if locale == "" {
		locale = DefaultFallbackLanguage
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	changed = c.v != locale
	c.v = locale
	return changed
}

// BundleLanguage returns the language the fallback chain picks for the text
// fields of one object (its "text bundle"): exact locale → base language →
// English → raw ("" key) → lowest remaining key. A language is eligible when
// any of the fields carries a non-empty value for it, so all fields of the
// object resolve from the same language and text never mixes languages
// within one object. Fields missing the picked language resolve to "".
func BundleLanguage(locale string, fields ...TranslatedString) string {
	has := func(lang string) bool {
		for _, f := range fields {
			if f[lang] != "" {
				return true
			}
		}
		return false
	}

	if locale != "" && has(locale) {
		return locale
	}
	if base, ok := baseLanguage(locale); ok && has(base) {
		return base
	}
	if has(DefaultFallbackLanguage) {
		return DefaultFallbackLanguage
	}
	if has("") {
		return ""
	}

	// Deterministic last resort: the lowest key holding a non-empty value.
	lowest := ""
	for _, f := range fields {
		for k, v := range f {
			if v != "" && (lowest == "" || k < lowest) {
				lowest = k
			}
		}
	}
	return lowest
}

// Resolve returns the translation of a standalone TranslatedString for the
// given locale, following the fallback chain. Returns "" when no translation
// is available at all.
func Resolve(ts TranslatedString, locale string) string {
	return ts[BundleLanguage(locale, ts)]
}

// ResolvePtr resolves a standalone TranslatedString into an optional (*string)
// DTO field, yielding nil when no translation is available at all. Use this for
// fields that are not displayed text — a URL, for instance — so they resolve
// independently of the object's text bundle: a URL carries no mixed-language
// risk, and dropping it because the bundle settled on a language that lacks it
// would lose the field entirely rather than fall back.
func ResolvePtr(ts TranslatedString, locale string) *string {
	return PtrIfNonEmpty(Resolve(ts, locale))
}

// PtrIfNonEmpty returns a pointer to s, or nil when s is empty. Used to fill
// the optional (*string) DTO fields from a resolved translation.
func PtrIfNonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// baseLanguage reduces a locale to its base language ("nl-BE" → "nl").
// Duplicated from eudi/metadata to avoid an import cycle (that package
// imports clientmodels).
func baseLanguage(locale string) (string, bool) {
	if locale == "" {
		return "", false
	}
	tag, err := language.Parse(locale)
	if err != nil {
		return "", false
	}
	base, _ := tag.Base()
	return base.String(), true
}
