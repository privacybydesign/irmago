package sdjwt

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// A claim only a Disclosure carries is taken from the processed payload; one
// the issuer-signed JWT carries is kept as read from the JWT.
func TestRegisteredClaims_AddDisclosedClaims(t *testing.T) {
	signedExp := int64(2000)
	claims := RegisteredClaims{Expiry: &signedExp}

	err := claims.AddDisclosedClaims(ProcessedPayload{
		"iss": "https://issuer.example",
		"nbf": float64(1500),
		"iat": json.Number("1000.5"),
		"exp": float64(9999),
	})
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example", *claims.Issuer)
	require.Equal(t, int64(1500), *claims.NotBefore)
	require.Equal(t, int64(1000), *claims.IssuedAt)
	require.Equal(t, int64(2000), *claims.Expiry)
}

func TestRegisteredClaims_AddDisclosedClaims_RejectsMalformedValues(t *testing.T) {
	for name, processed := range map[string]ProcessedPayload{
		"exp is a string": {"exp": "tomorrow"},
		"iss is a number": {"iss": float64(1)},
	} {
		t.Run(name, func(t *testing.T) {
			var claims RegisteredClaims
			require.Error(t, claims.AddDisclosedClaims(processed))
		})
	}
}
