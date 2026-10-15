package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildAttributeValue_Currency(t *testing.T) {
	val := buildAttributeValue("currency:EUR", &irma.TranslatedString{"": "12.50"})
	assert.Equal(t, clientmodels.AttributeType_String, val.Type)
	require.NotNil(t, val.String)
	assert.Equal(t, "12.50", *val.String)
	require.NotNil(t, val.Currency)
	assert.Equal(t, "EUR", *val.Currency)
}

// A value that isn't a plain decimal amount, or a malformed currency hint, falls
// back to a plain string without a currency code.
func TestBuildAttributeValue_CurrencyFallsBackToString(t *testing.T) {
	for _, tt := range []struct{ hint, value string }{
		{"currency:EUR", "€ 12,50"},
		{"currency:euro", "12.50"},
	} {
		val := buildAttributeValue(tt.hint, &irma.TranslatedString{"": tt.value})
		assert.Equal(t, clientmodels.AttributeType_String, val.Type)
		require.NotNil(t, val.String)
		assert.Equal(t, tt.value, *val.String)
		assert.Nil(t, val.Currency, tt.hint+" "+tt.value)
	}
}

func TestBuildAttributeValue_NoCurrencyWithoutHint(t *testing.T) {
	val := buildAttributeValue("", &irma.TranslatedString{"": "12.50"})
	assert.Nil(t, val.Currency)
}
