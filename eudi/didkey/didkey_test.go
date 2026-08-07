package didkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateResolve_Ed25519_RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didKey, err := Create(pub)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(didKey, Prefix))

	resolved, err := Resolve(didKey)
	require.NoError(t, err)
	require.Equal(t, pub, resolved)
}

func TestCreateResolve_P256_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	didKey, err := Create(priv.PublicKey)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(didKey, Prefix))

	resolved, err := Resolve(didKey)
	require.NoError(t, err)
	resolvedKey, ok := resolved.(ecdsa.PublicKey)
	require.True(t, ok)
	require.True(t, priv.PublicKey.Equal(&resolvedKey))
}

// The did:key spec references a key through a DID URL whose fragment repeats the
// multibase value (e.g. "did:key:z6Mk...#z6Mk..."); Resolve must strip the fragment.
func TestResolve_WithVerificationMethodFragment_StripsFragment(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didKey, err := Create(pub)
	require.NoError(t, err)

	multibase := strings.TrimPrefix(didKey, Prefix)
	resolved, err := Resolve(didKey + "#" + multibase)
	require.NoError(t, err)
	require.Equal(t, pub, resolved)
}

func TestResolve_WithArbitraryFragment_StripsFragment(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didKey, err := Create(pub)
	require.NoError(t, err)

	resolved, err := Resolve(didKey + "#key-1")
	require.NoError(t, err)
	require.Equal(t, pub, resolved)
}

func TestResolve_MissingPrefix_ReturnsError(t *testing.T) {
	_, err := Resolve("did:jwk:eyJrdHkiOiJFQyJ9")
	require.EqualError(t, err, "invalid did:key: did:jwk:eyJrdHkiOiJFQyJ9")
}
