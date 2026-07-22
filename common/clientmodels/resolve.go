package clientmodels

import (
	"sort"
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

func (c *CurrentLocale) Get() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.v
}

func (c *CurrentLocale) Set(locale string) {
	if locale == "" {
		locale = DefaultFallbackLanguage
	}
	c.mu.Lock()
	c.v = locale
	c.mu.Unlock()
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
	keys := []string{}
	for _, f := range fields {
		for k, v := range f {
			if v != "" {
				keys = append(keys, k)
			}
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	return keys[0]
}

// Resolve returns the translation of a standalone TranslatedString for the
// given locale, following the fallback chain. Returns "" when no translation
// is available at all.
func Resolve(ts TranslatedString, locale string) string {
	return ts[BundleLanguage(locale, ts)]
}

// ResolveOptional resolves an optional TranslatedString to an optional
// string: nil stays nil, and a map without any usable translation also
// yields nil.
func ResolveOptional(ts *TranslatedString, locale string) *string {
	if ts == nil {
		return nil
	}
	s := Resolve(*ts, locale)
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
