package eudi_jwt

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/stretchr/testify/require"
)

func Test_SupportedKeyEncryptionAlgorithm_Accepted(t *testing.T) {
	for _, alg := range []jwa.KeyEncryptionAlgorithm{
		jwa.ECDH_ES(), jwa.ECDH_ES_A128KW(), jwa.ECDH_ES_A192KW(), jwa.ECDH_ES_A256KW(),
		jwa.RSA_OAEP_256(), jwa.RSA_OAEP_384(), jwa.RSA_OAEP_512(),
	} {
		t.Run(alg.String(), func(t *testing.T) {
			got, ok := SupportedKeyEncryptionAlgorithm(alg)
			require.True(t, ok)
			require.Equal(t, alg, got)
		})
	}
}

func Test_SupportedKeyEncryptionAlgorithm_Rejected(t *testing.T) {
	tests := []struct {
		alg    jwa.KeyAlgorithm
		reason string
	}{
		{jwa.RSA1_5(), "RSAES-PKCS1-v1_5, padding-oracle attacks"},
		{jwa.RSA_OAEP(), "OAEP with SHA-1"},
		{jwa.DIRECT(), "symmetric"},
		{jwa.A128KW(), "symmetric"},
		{jwa.A256GCMKW(), "symmetric"},
		{jwa.PBES2_HS256_A128KW(), "password based"},
		{jwa.ES256(), "a signature algorithm, not a key encryption algorithm"},
	}

	for _, tt := range tests {
		t.Run(tt.alg.String(), func(t *testing.T) {
			_, ok := SupportedKeyEncryptionAlgorithm(tt.alg)
			require.False(t, ok, "expected %s to be rejected: %s", tt.alg, tt.reason)
		})
	}
}

func Test_LookupSupportedContentEncryptionAlgorithm(t *testing.T) {
	for _, name := range []string{"A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"} {
		t.Run(name, func(t *testing.T) {
			alg, ok := LookupSupportedContentEncryptionAlgorithm(name)
			require.True(t, ok)
			require.Equal(t, name, alg.String())
		})
	}

	for _, name := range []string{"", "A128CBC-HS256-legacy", "UNSUPPORTED_ALG_XYZ"} {
		t.Run("rejects "+name, func(t *testing.T) {
			_, ok := LookupSupportedContentEncryptionAlgorithm(name)
			require.False(t, ok)
		})
	}
}

// Every JWE algorithm jwx knows must be a deliberate accept or a deliberate reject, so that an
// algorithm added by a future jwx release cannot slip into the accepted set unnoticed.
func Test_SupportedKeyEncryptionAlgorithms_CoversEveryKnownAlgorithm(t *testing.T) {
	expectedAccepted := map[string]bool{
		"ECDH-ES": true, "ECDH-ES+A128KW": true, "ECDH-ES+A192KW": true, "ECDH-ES+A256KW": true,
		"RSA-OAEP-256": true, "RSA-OAEP-384": true, "RSA-OAEP-512": true,
		"RSA1_5": false, "RSA-OAEP": false,
		"dir":    false,
		"A128KW": false, "A192KW": false, "A256KW": false,
		"A128GCMKW": false, "A192GCMKW": false, "A256GCMKW": false,
		"PBES2-HS256+A128KW": false, "PBES2-HS384+A192KW": false, "PBES2-HS512+A256KW": false,
		// Registered by jwx from v4.4.0 on. JOSE HPKE is still a draft that no OpenID4VC or EUDI
		// profile specifies.
		"HPKE-0-KE": false, "HPKE-1-KE": false, "HPKE-2-KE": false,
		"HPKE-3-KE": false, "HPKE-4-KE": false, "HPKE-7-KE": false,
	}

	known := jwa.KeyEncryptionAlgorithms()
	require.Len(t, known, len(expectedAccepted), "jwx's key encryption algorithm set changed; review supportedKeyEncryptionAlgorithms")

	for _, alg := range known {
		accepted, listed := expectedAccepted[alg.String()]
		require.True(t, listed, "jwx knows %s, which this test does not classify; review supportedKeyEncryptionAlgorithms", alg)
		_, ok := SupportedKeyEncryptionAlgorithm(alg)
		require.Equal(t, accepted, ok, alg.String())
	}
}

func Test_SupportedContentEncryptionAlgorithms_CoversEveryKnownAlgorithm(t *testing.T) {
	known := jwa.ContentEncryptionAlgorithms()
	require.ElementsMatch(t, known, SupportedContentEncryptionAlgorithms(),
		"jwx's content encryption algorithm set changed; review supportedContentEncryptionAlgorithms")
}
