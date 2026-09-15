package clientmodels

import (
	"sync"
	"sync/atomic"

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
	if base, ok := BaseLanguage(locale); ok && has(base) {
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

// lastBaseLanguage memoises the most recent BaseLanguage result.
//
// One listing pull calls BundleLanguage several hundred times — once per field
// of every attribute of every credential — always with the same locale, and
// every call whose exact locale is absent from the map (which is all of them
// when the app passes a region tag like "en-US", since schemes key by base
// language) falls through to language.Parse at ~250ns and 3 allocations. A
// single-entry cache is enough: the locale changes when the user taps a
// setting, not within a call.
var lastBaseLanguage atomic.Pointer[baseLanguageResult]

type baseLanguageResult struct {
	locale, base string
	ok           bool
}

// BaseLanguage reduces a locale to its base language ("nl-BE" → "nl"),
// reporting false for an empty or unparseable locale. It lives here, the
// lowest package involved, so the maps keyed by base language and the chain
// that looks them up cannot disagree about what a base language is.
func BaseLanguage(locale string) (string, bool) {
	if locale == "" {
		return "", false
	}
	if cached := lastBaseLanguage.Load(); cached != nil && cached.locale == locale {
		return cached.base, cached.ok
	}

	result := baseLanguageResult{locale: locale}
	if tag, err := language.Parse(locale); err == nil {
		base, _ := tag.Base()
		result.base, result.ok = base.String(), true
	}
	lastBaseLanguage.Store(&result)
	return result.base, result.ok
}
