package clientmodels

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSupportedLanguages_ShipsFrenchAndGerman pins the languages a release is
// expected to be complete in. Removing one is a product decision, not a
// refactor; this test makes it a visible one.
func TestSupportedLanguages_ShipsFrenchAndGerman(t *testing.T) {
	for _, lang := range []string{"en", "nl", "fr", "de"} {
		assert.Contains(t, SupportedLanguages, lang)
	}
	assert.Contains(t, SupportedLanguages, DefaultFallbackLanguage,
		"the fallback language must itself be a supported language")
}

func TestIsSupportedLanguage(t *testing.T) {
	assert.True(t, IsSupportedLanguage("fr"))
	assert.True(t, IsSupportedLanguage("de"))
	assert.True(t, IsSupportedLanguage("fr-BE"), "a regional locale counts through its base language")
	assert.True(t, IsSupportedLanguage("de-AT"))
	assert.False(t, IsSupportedLanguage("xx"))
	assert.False(t, IsSupportedLanguage(""))
}

// TestPickLanguage_Chain covers the chain a language-keyed map of arbitrary
// values (templates, say) is resolved through: exact → base, and then the
// caller's own default rather than a project-wide one.
func TestPickLanguage_Chain(t *testing.T) {
	m := map[string]int{"en": 1, "fr": 2, "fr-CA": 3}

	v, ok := PickLanguage(m, "fr-CA")
	require.True(t, ok)
	assert.Equal(t, 3, v, "exact locale wins")

	v, ok = PickLanguage(m, "fr-BE")
	require.True(t, ok)
	assert.Equal(t, 2, v, "regional locale falls back to its base language")

	_, ok = PickLanguage(m, "de")
	assert.False(t, ok, "no project-wide fallback: the operator's configured default must keep the last word")

	_, ok = PickLanguage(map[string]int{}, "")
	assert.False(t, ok)
}

// TestNewTranslatedString_ResolvesForEveryLanguage pins why the raw-value
// wrapper does not enumerate SupportedLanguages: resolution already lands on the
// raw value for a language the wrapper never heard of.
func TestNewTranslatedString_ResolvesForEveryLanguage(t *testing.T) {
	v := "value"
	ts := NewTranslatedString(&v)
	for _, locale := range append([]string{"fr-BE", "de-CH", "pt", ""}, SupportedLanguages...) {
		assert.Equal(t, v, Resolve(ts, locale), "locale %q", locale)
	}
	assert.Nil(t, NewTranslatedString(nil))
	assert.Len(t, ts, 3, "raw value plus the two legacy wire-format aliases; growing this multiplies payload size")
}
