package typemetadata

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

func TestVctTypeMetadata_Names(t *testing.T) {
	var none *VctTypeMetadata
	require.Empty(t, none.Names())

	require.Equal(t, clientmodels.TranslatedString{"en": "Fallback"}, (&VctTypeMetadata{Name: "Fallback"}).Names(),
		"the document-level name stands in under the fallback language")

	m := &VctTypeMetadata{Name: "Ignored", Display: []DisplayEntry{{Locale: "nl", Name: "E-mail"}, {Name: "Email"}, {Locale: "de"}}}
	require.Equal(t, clientmodels.TranslatedString{"nl": "E-mail", "en": "Email"}, m.Names(), "an entry without a locale is the fallback language; one without a name is skipped")
}

func TestVctTypeMetadata_ClaimNames(t *testing.T) {
	m := &VctTypeMetadata{Claims: []ClaimMetadata{
		{Path: []any{"email"}, Display: []ClaimDisplayEntry{{Locale: "en", Name: "Email address"}}},
		{Path: []any{"addresses", float64(0), "street"}, Display: []ClaimDisplayEntry{{Name: "Street"}}},
		{Path: []any{"unnamed"}},
	}}
	require.Equal(t, clientmodels.TranslatedString{"en": "Email address"}, m.ClaimNames([]any{"email"}))
	require.Equal(t, clientmodels.TranslatedString{"en": "Street"}, m.ClaimNames([]any{"addresses", 0, "street"}), "an index compares across number types")
	require.Nil(t, m.ClaimNames([]any{"unnamed"}))
	require.Nil(t, m.ClaimNames([]any{"missing"}))

	var none *VctTypeMetadata
	require.Nil(t, none.ClaimNames([]any{"email"}))
}

func TestClaimPathsEqual(t *testing.T) {
	require.True(t, ClaimPathsEqual([]any{"a", 1}, []any{"a", float64(1)}))
	require.False(t, ClaimPathsEqual([]any{"a"}, []any{"a", "b"}))
	require.False(t, ClaimPathsEqual([]any{"a"}, []any{"b"}))
}
