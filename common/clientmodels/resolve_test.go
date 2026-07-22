package clientmodels

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolve_FallbackChain(t *testing.T) {
	ts := TranslatedString{"en": "English", "nl": "Nederlands", "de": "Deutsch"}

	t.Run("exact locale wins", func(t *testing.T) {
		assert.Equal(t, "Nederlands", Resolve(ts, "nl"))
	})

	t.Run("regional locale falls back to base language", func(t *testing.T) {
		assert.Equal(t, "Nederlands", Resolve(ts, "nl-BE"))
	})

	t.Run("unavailable locale falls back to English", func(t *testing.T) {
		assert.Equal(t, "English", Resolve(ts, "fr"))
	})

	t.Run("no English falls back to raw key", func(t *testing.T) {
		assert.Equal(t, "raw", Resolve(TranslatedString{"": "raw", "de": "Deutsch"}, "fr"))
	})

	t.Run("no English and no raw falls back to lowest key", func(t *testing.T) {
		assert.Equal(t, "Deutsch", Resolve(TranslatedString{"de": "Deutsch", "it": "Italiano"}, "fr"))
	})

	t.Run("empty locale resolves to English", func(t *testing.T) {
		assert.Equal(t, "English", Resolve(ts, ""))
	})

	t.Run("empty map resolves to empty string", func(t *testing.T) {
		assert.Equal(t, "", Resolve(TranslatedString{}, "nl"))
		assert.Equal(t, "", Resolve(nil, "nl"))
	})

	t.Run("empty value is treated as absent", func(t *testing.T) {
		assert.Equal(t, "English", Resolve(TranslatedString{"nl": "", "en": "English"}, "nl"))
	})
}

func TestBundleLanguage_TextBundle(t *testing.T) {
	t.Run("one language for all fields of an object", func(t *testing.T) {
		name := TranslatedString{"en": "Name EN", "nl": "Name NL"}
		description := TranslatedString{"en": "Desc EN", "nl": "Desc NL"}
		lang := BundleLanguage("nl", name, description)
		assert.Equal(t, "nl", lang)
		assert.Equal(t, "Name NL", name[lang])
		assert.Equal(t, "Desc NL", description[lang])
	})

	t.Run("field missing the bundle language resolves empty, never mixed", func(t *testing.T) {
		name := TranslatedString{"en": "Name EN", "nl": "Name NL"}
		description := TranslatedString{"en": "Desc EN"} // no nl translation
		lang := BundleLanguage("nl", name, description)
		assert.Equal(t, "nl", lang, "any field having the locale keeps the bundle in that locale")
		assert.Equal(t, "Name NL", name[lang])
		assert.Equal(t, "", description[lang], "missing field stays empty rather than borrowing English")
	})

	t.Run("whole bundle falls back when no field has the locale", func(t *testing.T) {
		name := TranslatedString{"en": "Name EN"}
		description := TranslatedString{"en": "Desc EN"}
		lang := BundleLanguage("nl", name, description)
		assert.Equal(t, "en", lang)
	})

	t.Run("nil fields are tolerated", func(t *testing.T) {
		name := TranslatedString{"en": "Name EN"}
		assert.Equal(t, "en", BundleLanguage("nl", name, nil))
	})

	t.Run("no translations anywhere yields empty language", func(t *testing.T) {
		assert.Equal(t, "", BundleLanguage("nl", nil, TranslatedString{}))
	})
}

func TestResolveOptional(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		assert.Nil(t, ResolveOptional(nil, "en"))
	})

	t.Run("unresolvable map yields nil", func(t *testing.T) {
		ts := TranslatedString{}
		assert.Nil(t, ResolveOptional(&ts, "en"))
	})

	t.Run("resolvable map yields pointer", func(t *testing.T) {
		ts := TranslatedString{"en": "value"}
		got := ResolveOptional(&ts, "nl")
		assert.NotNil(t, got)
		assert.Equal(t, "value", *got)
	})
}

func TestCurrentLocale(t *testing.T) {
	t.Run("empty initial locale defaults to English", func(t *testing.T) {
		assert.Equal(t, DefaultFallbackLanguage, NewCurrentLocale("").Get())
	})

	t.Run("set and get", func(t *testing.T) {
		l := NewCurrentLocale("en")
		l.Set("nl")
		assert.Equal(t, "nl", l.Get())
	})

	t.Run("set empty resets to default", func(t *testing.T) {
		l := NewCurrentLocale("nl")
		l.Set("")
		assert.Equal(t, DefaultFallbackLanguage, l.Get())
	})
}
