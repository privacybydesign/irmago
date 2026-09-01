package sdjwt

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"
)

// TestBuilder_NoVct_Success verifies that the generic SD-JWT Builder (unlike
// SdJwtVcBuilder in the sdjwtvc package) has no opinion on `vct`: a plain
// SD-JWT with no vct claim at all is valid per the SD-JWT core spec.
func TestBuilder_NoVct_Success(t *testing.T) {
	sdJwt, err := NewBuilder().
		WithPayload(
			Claim(jwt.IssuerKey, "not-necessarily-a-url"),
			SdClaim("email", "test@gmail.com"),
		).
		Build(newTestJwtCreator(t))
	require.NoError(t, err)
	require.NotEmpty(t, sdJwt)

	payload, err := DecodeJwtPayload(sdJwt)
	require.NoError(t, err)
	require.NotContains(t, payload, "vct")
	require.Equal(t, "not-necessarily-a-url", payload[jwt.IssuerKey])
}
