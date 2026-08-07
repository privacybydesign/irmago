package didkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func mustCreateEcdsaKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	return key
}

// fragmented turns a did:key DID into the verification method id the spec uses to
// reference the key inside the DID document: the DID plus a fragment repeating the
// multibase value.
func fragmented(didKey string) string {
	return didKey + "#" + didKey[len(Prefix):]
}

func TestCreateAndResolve_P256_RoundTrips(t *testing.T) {
	key := mustCreateEcdsaKey(t, elliptic.P256())

	didKey, err := Create(key.PublicKey)
	require.NoError(t, err)
	require.Contains(t, didKey, Prefix+"zDna", "P-256 did:key values carry the p256-pub multicodec prefix")

	resolved, err := Resolve(didKey)
	require.NoError(t, err)
	require.Equal(t, key.PublicKey, resolved)
}

func TestCreateAndResolve_P384_RoundTrips(t *testing.T) {
	key := mustCreateEcdsaKey(t, elliptic.P384())

	didKey, err := Create(key.PublicKey)
	require.NoError(t, err)

	resolved, err := Resolve(didKey)
	require.NoError(t, err)
	require.Equal(t, key.PublicKey, resolved)
}

func TestCreateAndResolve_Ed25519_RoundTrips(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	didKey, err := Create(pub)
	require.NoError(t, err)

	resolved, err := Resolve(didKey)
	require.NoError(t, err)
	require.Equal(t, pub, resolved)
}

// The spec references the key as `did:key:z…#z…`, so a DID URL in that form has to
// resolve to the same key as the fragmentless DID.
func TestResolve_WithVerificationMethodFragment(t *testing.T) {
	key := mustCreateEcdsaKey(t, elliptic.P256())

	didKey, err := Create(key.PublicKey)
	require.NoError(t, err)

	resolved, err := Resolve(fragmented(didKey))
	require.NoError(t, err)
	require.Equal(t, key.PublicKey, resolved)
}

func TestResolve_FragmentNamingAnotherKey_ReturnsError(t *testing.T) {
	first, err := Create(mustCreateEcdsaKey(t, elliptic.P256()).PublicKey)
	require.NoError(t, err)
	second, err := Create(mustCreateEcdsaKey(t, elliptic.P256()).PublicKey)
	require.NoError(t, err)

	_, err = Resolve(first + "#" + second[len(Prefix):])
	require.ErrorContains(t, err, "fragment does not match")
}

func TestResolve_EmptyFragment_ReturnsError(t *testing.T) {
	didKey, err := Create(mustCreateEcdsaKey(t, elliptic.P256()).PublicKey)
	require.NoError(t, err)

	_, err = Resolve(didKey + "#")
	require.ErrorContains(t, err, "fragment does not match")
}

func TestResolve_WithoutDidKeyPrefix_ReturnsError(t *testing.T) {
	didKey, err := Create(mustCreateEcdsaKey(t, elliptic.P256()).PublicKey)
	require.NoError(t, err)

	_, err = Resolve(didKey[len(Prefix):])
	require.ErrorContains(t, err, "not a did:key DID")
}

func TestResolve_OtherDidMethod_ReturnsError(t *testing.T) {
	_, err := Resolve("did:jwk:eyJrdHkiOiJFQyJ9")
	require.ErrorContains(t, err, "not a did:key DID")
}

// base58-btc is the only encoding the spec's creation algorithm defines for the
// method-specific identifier, so a base64url multibase value is not a did:key.
func TestResolve_NonBase58BtcMultibase_ReturnsError(t *testing.T) {
	_, err := Resolve(Prefix + "u7QEBAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA")
	require.ErrorContains(t, err, "must be base58-btc encoded")
}

func TestResolve_EmptyMultibase_ReturnsError(t *testing.T) {
	_, err := Resolve(Prefix)
	require.ErrorContains(t, err, "must be base58-btc encoded")
}

func TestResolve_EmptyString_ReturnsError(t *testing.T) {
	_, err := Resolve("")
	require.ErrorContains(t, err, "not a did:key DID")
}

func TestResolve_InvalidBase58_ReturnsError(t *testing.T) {
	_, err := Resolve(Prefix + "z0OIl")
	require.ErrorContains(t, err, "failed to decode multibase data")
}

func TestResolve_UnsupportedMulticodec_ReturnsError(t *testing.T) {
	// secp256k1-pub (0xe7 0x01) is in the spec's multicodec table but not implemented.
	_, err := Resolve(Prefix + "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")
	require.ErrorContains(t, err, "unsupported multicodec header")
}

func TestCreate_UnsupportedCurve_ReturnsError(t *testing.T) {
	key := mustCreateEcdsaKey(t, elliptic.P521())

	_, err := Create(key.PublicKey)
	require.ErrorContains(t, err, "unsupported elliptic curve")
}

func TestCreate_IncompleteEcdsaKey_ReturnsErrorWithoutPanicking(t *testing.T) {
	_, err := Create(ecdsa.PublicKey{})
	require.ErrorContains(t, err, "incomplete ECDSA public key")
}

func TestCreate_MalformedEd25519Key_ReturnsError(t *testing.T) {
	_, err := Create(ed25519.PublicKey{0x01, 0x02, 0x03})
	require.ErrorContains(t, err, "invalid Ed25519 public key size")
}
