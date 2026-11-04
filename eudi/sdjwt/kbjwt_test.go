package sdjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
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

	expected, err := jwk.Import[jwk.Key](priv.PublicKey)
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

func TestDuplicateConfirmation(t *testing.T) {
	kid1, kid2 := "did:jwk:one#0", "did:jwk:two#0"
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key, err := jwk.Import[jwk.Key](priv.PublicKey)
	require.NoError(t, err)

	require.Equal(t, -1, DuplicateConfirmation([]*CnfField{{Kid: &kid1}, {Kid: &kid2}}), "distinct kids")
	require.Equal(t, 0, DuplicateConfirmation([]*CnfField{{Kid: &kid1}, {Kid: &kid1}}), "duplicate kid")
	require.Equal(t, 0, DuplicateConfirmation([]*CnfField{{Jwk: &key}, {Jwk: &key}}), "duplicate jwk")
	require.Equal(t, -1, DuplicateConfirmation([]*CnfField{nil, nil}), "missing cnf")
}

type fixedClock time.Time

func (c fixedClock) Now() time.Time { return time.Time(c) }

// The binder stamps iat with its own clock, replacing one the caller sent, so a
// binder on a server records the server's time of signing.
func TestDefaultKeyBinder_SetsIssuedAt(t *testing.T) {
	signedAt := time.Unix(1_700_000_000, 0)
	binder := &DefaultKeyBinder{clock: fixedClock(signedAt), storage: NewInMemoryKeyBindingStorage()}
	keys, err := binder.CreateKeyPairs(1)
	require.NoError(t, err)

	claims := map[string]any{"nonce": "n", "iat": int64(1)}
	signed, err := binder.CreateHolderSignedJwt(keys[0], map[string]any{"typ": KbJwtTyp}, claims)
	require.NoError(t, err)

	_, payload, err := DecodeJwtWithoutCheckingSignature(signed)
	require.NoError(t, err)
	require.EqualValues(t, signedAt.Unix(), payload["iat"])
	require.Equal(t, int64(1), claims["iat"], "the caller's claims are not changed")
}
