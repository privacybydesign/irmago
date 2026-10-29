package sdjwt

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
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

// RFC 9901 §9.4: the truncated sha-256-* digests of the IANA registry are unfit
// for SD-JWT, and sha3-224 is less collision resistant than the ES256
// signature, so only full-length digests of at least 256 bits are accepted.
func TestExtractRegisteredClaims_SdAlg(t *testing.T) {
	for _, alg := range []iana.HashingAlgorithm{
		iana.SHA256, iana.SHA384, iana.SHA512, iana.SHA3_256, iana.SHA3_384, iana.SHA3_512,
	} {
		t.Run(string(alg)+" is accepted", func(t *testing.T) {
			token, err := jwt.NewBuilder().Claim(SdAlgKey, string(alg)).Build()
			require.NoError(t, err)
			claims, err := ExtractRegisteredClaims(token)
			require.NoError(t, err)
			require.Equal(t, alg, claims.SdAlg)
		})
	}
	for _, alg := range []iana.HashingAlgorithm{
		iana.SHA256_128, iana.SHA256_120, iana.SHA256_96, iana.SHA256_64, iana.SHA256_32, iana.SHA3_224, "md5",
	} {
		t.Run(string(alg)+" is refused", func(t *testing.T) {
			token, err := jwt.NewBuilder().Claim(SdAlgKey, string(alg)).Build()
			require.NoError(t, err)
			_, err = ExtractRegisteredClaims(token)
			require.ErrorContains(t, err, "unsupported _sd_alg")
		})
	}
}
