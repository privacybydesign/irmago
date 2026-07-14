package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	testEd25519PubKey = ed25519.PublicKey{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	testP256PubKey = ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X: new(big.Int).SetBytes([]byte{
			0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
			0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
			0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
			0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
		}),
		Y: new(big.Int).SetBytes([]byte{
			0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
			0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
			0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
			0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
		}),
	}

	testP384PubKey = ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X: new(big.Int).SetBytes([]byte{
			0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37,
			0x8e, 0xb1, 0xc7, 0x1e, 0xf3, 0x20, 0xad, 0x74,
			0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98,
			0x59, 0xf7, 0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38,
			0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29, 0x6c,
			0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
		}),
		Y: new(big.Int).SetBytes([]byte{
			0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f,
			0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
			0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
			0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
			0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d,
			0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
		}),
	}

	testP521PubKey = ecdsa.PublicKey{
		Curve: elliptic.P521(),
		X:     big.NewInt(1),
		Y:     big.NewInt(1),
	}
)

// Tests for MultibaseFromPublicKey

func TestCreateMultibaseFromPublicKey_Ed25519_Base64UrlNoPad(t *testing.T) {
	result, err := CreateMultibaseFromPublicKey(testEd25519PubKey, Base64UrlNoPadEncoder{})
	require.NoError(t, err)
	require.Equal(t, "u7QEBAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA", result)
}

func TestCreateMultibaseFromPublicKey_P256_Base64UrlNoPad(t *testing.T) {
	result, err := CreateMultibaseFromPublicKey(testP256PubKey, Base64UrlNoPadEncoder{})
	require.NoError(t, err)
	require.Equal(t, "ugCQDaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY", result)
}

func TestCreateMultibaseFromPublicKey_P384_Base64UrlNoPad(t *testing.T) {
	result, err := CreateMultibaseFromPublicKey(testP384PubKey, Base64UrlNoPadEncoder{})
	require.NoError(t, err)
	require.Equal(t, "ugSQDqofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3", result)
}

func TestCreateMultibaseFromPublicKey_UnsupportedCurve_Base64UrlNoPad(t *testing.T) {
	_, err := CreateMultibaseFromPublicKey(testP521PubKey, Base64UrlNoPadEncoder{})
	require.EqualError(t, err, "unsupported elliptic curve: P-521")
}

func TestCreateMultibaseFromPublicKey_Ed25519_Base58BTC(t *testing.T) {
	result, err := CreateMultibaseFromPublicKey(testEd25519PubKey, Base58Encoder{})
	require.NoError(t, err)
	require.Equal(t, "z6MkeXCES4onVW4up9Qgz1KRnZsKmGufcaZxF6Zpv2w5QwUK", result)
}

func TestCreateMultibaseFromPublicKey_P256_Base58BTC(t *testing.T) {
	result, err := CreateMultibaseFromPublicKey(testP256PubKey, Base58Encoder{})
	require.NoError(t, err)
	require.Equal(t, "zDnaepsL7AXenJkVYdkh5KuKsSU7Ykh7kyXaLLU7auN9FWSiZ", result)
}

func TestCreateMultibaseFromPublicKey_P384_Base58BTC(t *testing.T) {
	result, err := CreateMultibaseFromPublicKey(testP384PubKey, Base58Encoder{})
	require.NoError(t, err)
	require.Equal(t, "z82Lm2Abz3bgMqXh7vPbTuaCgzL8Mxx3KcZ2ZyAEYtCMhYXCYE9yhBvpQ1F78faLDX6hpQN", result)
}

func TestCreateMultibaseFromPublicKey_UnsupportedCurve_Base58BTC(t *testing.T) {
	_, err := CreateMultibaseFromPublicKey(testP521PubKey, Base58Encoder{})
	require.EqualError(t, err, "unsupported elliptic curve: P-521")
}

// Tests for createMultibaseVerificationMethod

func TestCreateMultibaseVerificationMethod_SetsTypeAndPublicKeyMultibase(t *testing.T) {
	vm, err := createMultibaseVerificationMethod(testEd25519PubKey, Base58Encoder{})
	require.NoError(t, err)
	require.NotNil(t, vm)
	require.Equal(t, VerificationMethodType_Multikey, vm.Type)
	require.NotNil(t, vm.PublicKeyMultibase)
	require.Equal(t, "z6MkeXCES4onVW4up9Qgz1KRnZsKmGufcaZxF6Zpv2w5QwUK", *vm.PublicKeyMultibase)
}

func TestCreateMultibaseVerificationMethod_PropagatesError(t *testing.T) {
	vm, err := createMultibaseVerificationMethod(testP521PubKey, Base58Encoder{})
	require.EqualError(t, err, "unsupported elliptic curve: P-521")
	require.Nil(t, vm)
}

// Tests for ResolvePublicKeyFromMultibase

func TestResolvePublicKeyFromMultibase_Ed25519_Base58BTC(t *testing.T) {
	result, err := ResolvePublicKeyFromMultibase("z6MkeXCES4onVW4up9Qgz1KRnZsKmGufcaZxF6Zpv2w5QwUK")
	require.NoError(t, err)
	require.Equal(t, testEd25519PubKey, result)
}

func TestResolvePublicKeyFromMultibase_Ed25519_Base64UrlNoPad(t *testing.T) {
	result, err := ResolvePublicKeyFromMultibase("u7QEBAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fIA")
	require.NoError(t, err)
	require.Equal(t, testEd25519PubKey, result)
}

func TestResolvePublicKeyFromMultibase_P256_Base58BTC(t *testing.T) {
	result, err := ResolvePublicKeyFromMultibase("zDnaepsL7AXenJkVYdkh5KuKsSU7Ykh7kyXaLLU7auN9FWSiZ")
	require.NoError(t, err)
	require.Equal(t, testP256PubKey, result)
}

func TestResolvePublicKeyFromMultibase_P256_Base64UrlNoPad(t *testing.T) {
	result, err := ResolvePublicKeyFromMultibase("ugCQDaxfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY")
	require.NoError(t, err)
	require.Equal(t, testP256PubKey, result)
}

func TestResolvePublicKeyFromMultibase_P384_Base58BTC(t *testing.T) {
	result, err := ResolvePublicKeyFromMultibase("z82Lm2Abz3bgMqXh7vPbTuaCgzL8Mxx3KcZ2ZyAEYtCMhYXCYE9yhBvpQ1F78faLDX6hpQN")
	require.NoError(t, err)
	require.Equal(t, testP384PubKey, result)
}

func TestResolvePublicKeyFromMultibase_P384_Base64UrlNoPad(t *testing.T) {
	result, err := ResolvePublicKeyFromMultibase("ugSQDqofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3")
	require.NoError(t, err)
	require.Equal(t, testP384PubKey, result)
}

func TestResolvePublicKeyFromMultibase_EmptyString(t *testing.T) {
	_, err := ResolvePublicKeyFromMultibase("")
	require.EqualError(t, err, "multibase string is empty")
}

func TestResolvePublicKeyFromMultibase_UnsupportedMultibaseHeader(t *testing.T) {
	_, err := ResolvePublicKeyFromMultibase("mSomeBase64Data")
	require.EqualError(t, err, "unsupported multibase header: m")
}

func TestResolvePublicKeyFromMultibase_InvalidBase58Data(t *testing.T) {
	_, err := ResolvePublicKeyFromMultibase("z0OIl")
	require.ErrorContains(t, err, "failed to decode multibase data")
}

func TestResolvePublicKeyFromMultibase_InvalidBase64Data(t *testing.T) {
	_, err := ResolvePublicKeyFromMultibase("u!invalid")
	require.ErrorContains(t, err, "failed to decode multibase data")
}

func TestResolvePublicKeyFromMultibase_DataTooShort(t *testing.T) {
	multibase := Base64UrlNoPadEncoder{}.Encode([]byte{0x01})
	_, err := ResolvePublicKeyFromMultibase(multibase)
	require.EqualError(t, err, "multibase data is too short to contain a valid header")
}

func TestResolvePublicKeyFromMultibase_UnsupportedMulticodecHeader(t *testing.T) {
	multibase := Base64UrlNoPadEncoder{}.Encode([]byte{0x01, 0x02, 0x00})
	_, err := ResolvePublicKeyFromMultibase(multibase)
	require.EqualError(t, err, "unsupported multicodec header: 0102")
}

func TestResolvePublicKeyFromMultibase_InvalidEd25519KeySize(t *testing.T) {
	keyData := make([]byte, 31) // Ed25519 requires exactly 32 bytes
	multibase := Base64UrlNoPadEncoder{}.Encode(append([]byte(multicodecHeaderEd25519), keyData...))
	_, err := ResolvePublicKeyFromMultibase(multibase)
	require.EqualError(t, err, "invalid Ed25519 public key size: expected 32 bytes, got 31 bytes")
}

func TestResolvePublicKeyFromMultibase_InvalidP256KeyData(t *testing.T) {
	// 33 bytes with 0xFF x-coordinate exceeds the P-256 field prime
	invalidPoint := make([]byte, 33)
	invalidPoint[0] = 0x02
	for i := 1; i < 33; i++ {
		invalidPoint[i] = 0xFF
	}
	multibase := Base64UrlNoPadEncoder{}.Encode(append([]byte(multicodecHeaderP256), invalidPoint...))
	_, err := ResolvePublicKeyFromMultibase(multibase)
	require.EqualError(t, err, "invalid P-256 public key data")
}

func TestResolvePublicKeyFromMultibase_InvalidP384KeyData(t *testing.T) {
	// 49 bytes with 0xFF x-coordinate exceeds the P-384 field prime
	invalidPoint := make([]byte, 49)
	invalidPoint[0] = 0x02
	for i := 1; i < 49; i++ {
		invalidPoint[i] = 0xFF
	}
	multibase := Base64UrlNoPadEncoder{}.Encode(append([]byte(multicodecHeaderP384), invalidPoint...))
	_, err := ResolvePublicKeyFromMultibase(multibase)
	require.EqualError(t, err, "invalid P-384 public key data")
}
