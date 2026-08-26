package openid4vp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A verifier is free to publish its signing and encryption keys in one
// client_metadata jwks, in any order. Selecting a signing key is fatal rather
// than merely suboptimal: encryptJwe deliberately has no fallback, since an
// mdoc's deviceAuth has already committed to the selected key's thumbprint, so
// the whole session dies on
//
//	jwe.Encrypt: WithKey() option must be specified using jwa.KeyEncryptionAlgorithm
func TestSelectResponseEncryptionKeySkipsSigningKeys(t *testing.T) {
	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(testPublicKey(t, jwa.ES256(), "sig", "sig-1")))
	require.NoError(t, jwks.AddKey(testPublicKey(t, jwa.ECDH_ES(), "enc", "enc-1")))

	key, thumbprint, err := selectResponseEncryptionKey(jwks)
	require.NoError(t, err)

	kid, ok := key.KeyID()
	require.True(t, ok)
	assert.Equal(t, "enc-1", kid, "the signing key listed first must be skipped")
	assert.NotEmpty(t, thumbprint)

	// The selected key must be one encryptJwe can actually use — the point of
	// matching the selection criterion to jwe.Encrypt's requirement.
	encrypted, err := encryptJwe(map[string]any{"vp_token": "presented"}, key, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
}

// A jwks holding nothing usable has to fail during selection, before any
// credential is disclosed, rather than after the device signature is committed.
func TestSelectResponseEncryptionKeyWithoutAnyEncryptionKey(t *testing.T) {
	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(testPublicKey(t, jwa.ES256(), "sig", "sig-1")))

	_, _, err := selectResponseEncryptionKey(jwks)
	require.ErrorContains(t, err, "no usable response encryption key")
}

// The thumbprint returned alongside the key is what the mdoc session transcript
// hashes, so it must belong to the very key the response is encrypted to.
func TestSelectResponseEncryptionKeyReturnsThumbprintOfSelectedKey(t *testing.T) {
	publicKey := testPublicKey(t, jwa.ECDH_ES(), "enc", "enc-1")
	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(publicKey))

	key, thumbprint, err := selectResponseEncryptionKey(jwks)
	require.NoError(t, err)

	expected, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, expected, thumbprint)
}

func testPublicKey(t *testing.T, alg jwa.KeyAlgorithm, use, kid string) jwk.Key {
	t.Helper()

	ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateKey, err := jwk.Import[jwk.Key](ecPrivateKey)
	require.NoError(t, err)
	require.NoError(t, privateKey.Set(jwk.AlgorithmKey, alg))
	require.NoError(t, privateKey.Set(jwk.KeyUsageKey, use))
	require.NoError(t, privateKey.Set(jwk.KeyIDKey, kid))

	publicKey, err := privateKey.PublicKey()
	require.NoError(t, err)
	return publicKey
}
