package sdjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/didkey"
	"github.com/stretchr/testify/require"
)

func mustThumbprint(t *testing.T, key jwk.Key) []byte {
	t.Helper()
	tp, err := key.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	return tp
}

// A credential's cnf.kid may be a did:key DID URL that carries the verification
// method fragment the did:key spec uses to reference the key, so the holder key has
// to resolve from either form.
func TestResolveKeyFromDid_DidKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didKey, err := didkey.Create(priv.PublicKey)
	require.NoError(t, err)

	expected, err := jwk.Import(priv.PublicKey)
	require.NoError(t, err)

	for _, kid := range []string{didKey, didKey + "#" + didKey[len(didkey.Prefix):]} {
		key, err := resolveKeyFromDid(kid)
		require.NoError(t, err, "kid %s should resolve", kid)
		require.Equal(t, mustThumbprint(t, expected), mustThumbprint(t, key))

		// The kid is kept on the key so the wallet can look up the private key by it.
		storedKid, ok := key.KeyID()
		require.True(t, ok)
		require.Equal(t, kid, storedKid)
	}
}

func TestResolveKeyFromDid_DidKeyWithMismatchedFragment(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didKey, err := didkey.Create(priv.PublicKey)
	require.NoError(t, err)
	otherDidKey, err := didkey.Create(other.PublicKey)
	require.NoError(t, err)

	_, err = resolveKeyFromDid(didKey + "#" + otherDidKey[len(didkey.Prefix):])
	require.ErrorContains(t, err, "fragment does not match")
}

func TestResolveKeyFromDid_UnsupportedMethod(t *testing.T) {
	_, err := resolveKeyFromDid("did:web:example.com")
	require.ErrorContains(t, err, "unsupported DID method in cnf.kid")
}
