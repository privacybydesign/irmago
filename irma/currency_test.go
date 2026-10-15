package irma

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurrencyCode(t *testing.T) {
	tests := []struct {
		hint string
		code string
		ok   bool
	}{
		{"currency:EUR", "EUR", true},
		{"currency:USD", "USD", true},
		{"currency:eur", "", false},
		{"currency:EURO", "", false},
		{"currency:", "", false},
		{"currency", "", false},
		{"yesno", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		code, ok := CurrencyCode(tt.hint)
		assert.Equal(t, tt.ok, ok, tt.hint)
		assert.Equal(t, tt.code, code, tt.hint)
	}
}

func TestIsCurrencyAmount(t *testing.T) {
	for _, v := range []string{"0", "12", "12.50", "-3", "1000.00"} {
		assert.True(t, IsCurrencyAmount(v), v)
	}
	for _, v := range []string{"", "12,50", "€ 12.50", "12.", ".5", "1e3", "+1", "1 000"} {
		assert.False(t, IsCurrencyAmount(v), v)
	}
}
