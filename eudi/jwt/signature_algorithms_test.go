package eudi_jwt

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/stretchr/testify/require"
)

func Test_IsSupportedSignatureAlgorithm_Accepted(t *testing.T) {
	for _, alg := range []jwa.SignatureAlgorithm{
		jwa.ES256(), jwa.ES384(), jwa.ES512(),
		jwa.EdDSA(), jwa.EdDSAEd25519(),
		jwa.PS256(), jwa.PS384(), jwa.PS512(),
		jwa.RS256(), jwa.RS384(), jwa.RS512(),
	} {
		t.Run(alg.String(), func(t *testing.T) {
			require.True(t, IsSupportedSignatureAlgorithm(alg))
		})
	}
}

func Test_IsSupportedSignatureAlgorithm_Rejected(t *testing.T) {
	tests := []struct {
		alg    jwa.SignatureAlgorithm
		reason string
	}{
		{jwa.HS256(), "symmetric"},
		{jwa.HS384(), "symmetric"},
		{jwa.HS512(), "symmetric"},
		{jwa.NoSignature(), "unsigned"},
		{jwa.EdDSAEd448(), "not registered by jwx and unimplemented in the standard library"},
	}

	for _, tt := range tests {
		t.Run(tt.alg.String(), func(t *testing.T) {
			require.False(t, IsSupportedSignatureAlgorithm(tt.alg), "expected %s to be rejected: %s", tt.alg, tt.reason)
		})
	}
}

// ES256K is accepted only in builds carrying the jwx_es256k build tag, which is what compiles
// jwx's secp256k1 support. Without it a signature using ES256K could not be verified, so the
// allow-list must follow the tag in both directions.
func Test_IsSupportedSignatureAlgorithm_ES256K_FollowsBuildTag(t *testing.T) {
	require.Equal(t, es256kEnabled, IsSupportedSignatureAlgorithm(jwa.ES256K()))

	_, found := LookupSupportedSignatureAlgorithm("ES256K")
	require.Equal(t, es256kEnabled, found)
}

// Every algorithm jwx knows must be a deliberate accept or a deliberate reject, so that an
// algorithm added by a future jwx release cannot slip into the accepted set unnoticed.
func Test_SupportedSignatureAlgorithms_CoversEveryKnownAlgorithm(t *testing.T) {
	expectedAccepted := map[string]bool{
		"ES256": true, "ES384": true, "ES512": true, "Ed25519": true,
		"PS256": true, "PS384": true, "PS512": true,
		"RS256": true, "RS384": true, "RS512": true,
		"ES256K": es256kEnabled,
		"EdDSA":  true,
		"none":   false,
		"HS256":  false, "HS384": false, "HS512": false,
	}

	known := jwa.SignatureAlgorithms()
	require.Len(t, known, len(expectedAccepted), "jwx's algorithm set changed; review supportedSignatureAlgorithms")

	for _, alg := range known {
		want, ok := expectedAccepted[alg.String()]
		require.True(t, ok, "jwx registered unreviewed algorithm %q; review supportedSignatureAlgorithms", alg)
		require.Equal(t, want, IsSupportedSignatureAlgorithm(alg), "unexpected verdict for %q", alg)
	}
}

func Test_LookupSupportedSignatureAlgorithm(t *testing.T) {
	alg, found := LookupSupportedSignatureAlgorithm("ES256")
	require.True(t, found)
	require.Equal(t, jwa.ES256(), alg)

	// RFC 9864 deprecates the EdDSA name, but issuers still sign with it and jwx can verify it,
	// so it must resolve.
	alg, found = LookupSupportedSignatureAlgorithm("EdDSA")
	require.True(t, found)
	require.Equal(t, jwa.EdDSA(), alg)

	// Known to jwx, but not accepted here.
	_, found = LookupSupportedSignatureAlgorithm("HS256")
	require.False(t, found)

	_, found = LookupSupportedSignatureAlgorithm("none")
	require.False(t, found)

	// Unknown to jwx entirely.
	_, found = LookupSupportedSignatureAlgorithm("NOT_AN_ALG")
	require.False(t, found)

	_, found = LookupSupportedSignatureAlgorithm("")
	require.False(t, found)
}

func Test_SupportedSignatureAlgorithms_ReturnsCopy(t *testing.T) {
	first := SupportedSignatureAlgorithms()
	require.NotEmpty(t, first)

	first[0] = jwa.HS256()

	require.NotEqual(t, jwa.HS256(), SupportedSignatureAlgorithms()[0])
	require.False(t, IsSupportedSignatureAlgorithm(jwa.HS256()))
}
