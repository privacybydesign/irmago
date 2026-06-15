package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustHex decodes a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// p256PublicKeyFromHex builds a P-256 public key from hex x/y coordinates.
func p256PublicKeyFromHex(t *testing.T, xHex, yHex string) *ecdsa.PublicKey {
	t.Helper()
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(mustHex(t, xHex)),
		Y:     new(big.Int).SetBytes(mustHex(t, yHex)),
	}
}

func TestCOSEKeyMatchesAnnexDStaticDeviceKey(t *testing.T) {
	// The MSO deviceKey in the Annex D device response is the COSE_Key form of
	// the static device key. We must produce byte-identical output.
	pub := p256PublicKeyFromHex(t, iso180135AnnexDStaticDeviceKeyX, iso180135AnnexDStaticDeviceKeyY)

	encoded, err := ECDSAPublicKeyToCOSEKey(pub)
	require.NoError(t, err)

	expected := mustHex(t, "a401022001215820"+iso180135AnnexDStaticDeviceKeyX+"225820"+iso180135AnnexDStaticDeviceKeyY)
	assert.Equal(t, expected, encoded)
}

func TestCOSEKeyPublicRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encoded, err := ECDSAPublicKeyToCOSEKey(&priv.PublicKey)
	require.NoError(t, err)

	got, err := COSEKeyToECDSAPublicKey(encoded)
	require.NoError(t, err)

	assert.Equal(t, priv.PublicKey.X, got.X)
	assert.Equal(t, priv.PublicKey.Y, got.Y)
	assert.True(t, got.Curve == elliptic.P256())
}

func TestCOSEKeyPrivateRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	encoded, err := ECDSAPrivateKeyToCOSEKey(priv)
	require.NoError(t, err)

	got, err := COSEKeyToECDSAPrivateKey(encoded)
	require.NoError(t, err)

	assert.Equal(t, priv.D, got.D)
	assert.Equal(t, priv.PublicKey.X, got.X)
	assert.Equal(t, priv.PublicKey.Y, got.Y)

	// A COSE_Key without the private scalar must be rejected as a private key.
	pubOnly, err := ECDSAPublicKeyToCOSEKey(&priv.PublicKey)
	require.NoError(t, err)
	_, err = COSEKeyToECDSAPrivateKey(pubOnly)
	assert.Error(t, err)
}

// TestCOSEKeyJWKRoundTrip exercises the COSE_Key <-> JWK <-> ecdsa chain over
// many freshly generated keys.
func TestCOSEKeyJWKRoundTrip(t *testing.T) {
	for i := 0; i < 64; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		coseKey, err := ECDSAPublicKeyToCOSEKey(&priv.PublicKey)
		require.NoError(t, err)

		jwkKey, err := COSEKeyToJWK(coseKey)
		require.NoError(t, err)

		backToCose, err := JWKToCOSEKey(jwkKey)
		require.NoError(t, err)

		assert.Equal(t, coseKey, backToCose, "COSE_Key -> JWK -> COSE_Key must be stable")

		pub, err := COSEKeyToECDSAPublicKey(backToCose)
		require.NoError(t, err)
		assert.Equal(t, priv.PublicKey.X, pub.X)
		assert.Equal(t, priv.PublicKey.Y, pub.Y)
	}
}

func TestCOSEKeyRejectsShortCoordinates(t *testing.T) {
	// A leading-zero coordinate must be preserved as a full 32 bytes.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	encoded, err := ECDSAPublicKeyToCOSEKey(&priv.PublicKey)
	require.NoError(t, err)

	var k coseEC2Key
	require.NoError(t, UnmarshalCBOR(encoded, &k))
	assert.Len(t, k.X, p256CoordLen)
	assert.Len(t, k.Y, p256CoordLen)
}

func TestCOSEKeyRejectsNonP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, err = ECDSAPublicKeyToCOSEKey(&priv.PublicKey)
	assert.Error(t, err)
}

func TestSign1VerifyRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	payload := []byte("issuerAuth payload (MSO)")
	signed, err := Sign1(priv, AlgorithmES256, payload, nil)
	require.NoError(t, err)

	require.NoError(t, Verify1(signed, &priv.PublicKey, AlgorithmES256))

	// A different key must fail verification.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.Error(t, Verify1(signed, &other.PublicKey, AlgorithmES256))

	// A tampered payload must fail verification.
	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 0xff
	assert.Error(t, Verify1(tampered, &priv.PublicKey, AlgorithmES256))
}

func TestSign1WithX5Chain(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Two arbitrary DER certificates from the Annex D vectors, just to exercise
	// the chain encoding/extraction (their contents are not verified here).
	leaf := mustHex(t, iso180135AnnexDDSCert)
	root := mustHex(t, iso180135AnnexDReaderCert)

	signed, err := Sign1(priv, AlgorithmES256, []byte("payload"), [][]byte{leaf, root})
	require.NoError(t, err)
	require.NoError(t, Verify1(signed, &priv.PublicKey, AlgorithmES256))

	chain, err := X5Chain(signed)
	require.NoError(t, err)
	require.Len(t, chain, 2)

	leafCert, err := x509.ParseCertificate(leaf)
	require.NoError(t, err)
	assert.Equal(t, leafCert.SerialNumber, chain[0].SerialNumber)

	// Single-certificate chains encode as a bare bstr and extract identically.
	signedOne, err := Sign1(priv, AlgorithmES256, []byte("payload"), [][]byte{leaf})
	require.NoError(t, err)
	chainOne, err := X5Chain(signedOne)
	require.NoError(t, err)
	require.Len(t, chainOne, 1)
}

// TestVerifyAnnexDIssuerAuth cross-validates the COSE_Sign1 implementation
// against a real ISO/IEC 18013-5 Annex D test vector: it extracts the
// issuerAuth COSE_Sign1 from the worked-example device response and verifies
// its signature with the public key from the Annex D document signer (DS)
// certificate.
func TestVerifyAnnexDIssuerAuth(t *testing.T) {
	type tvIssuerSigned struct {
		NameSpaces cbor.RawMessage `cbor:"nameSpaces"`
		IssuerAuth cbor.RawMessage `cbor:"issuerAuth"`
	}
	type tvDocument struct {
		DocType      string          `cbor:"docType"`
		IssuerSigned tvIssuerSigned  `cbor:"issuerSigned"`
		DeviceSigned cbor.RawMessage `cbor:"deviceSigned"`
	}
	type tvDeviceResponse struct {
		Version   string       `cbor:"version"`
		Documents []tvDocument `cbor:"documents"`
		Status    int          `cbor:"status"`
	}

	var resp tvDeviceResponse
	require.NoError(t, UnmarshalCBOR(mustHex(t, iso180135AnnexDDeviceResponse), &resp))
	require.Len(t, resp.Documents, 1)
	issuerAuth := []byte(resp.Documents[0].IssuerSigned.IssuerAuth)
	require.NotEmpty(t, issuerAuth)

	// Parse the document signer certificate and verify the issuerAuth signature.
	dsCert, err := x509.ParseCertificate(mustHex(t, iso180135AnnexDDSCert))
	require.NoError(t, err)
	dsPub, ok := dsCert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	require.NoError(t, Verify1(issuerAuth, dsPub, AlgorithmES256),
		"Annex D issuerAuth must verify against the DS certificate public key")

	// The x5chain embedded in issuerAuth must contain that same DS certificate.
	chain, err := X5Chain(issuerAuth)
	require.NoError(t, err)
	require.Len(t, chain, 1)
	assert.Equal(t, dsCert.SerialNumber, chain[0].SerialNumber)

	// Tampering with the signed bytes must break verification.
	tampered := append([]byte(nil), issuerAuth...)
	tampered[len(tampered)-1] ^= 0xff
	assert.Error(t, Verify1(tampered, dsPub, AlgorithmES256))
}

// FuzzCOSEKeyToECDSAPublicKey ensures arbitrary input never panics the decoder.
func FuzzCOSEKeyToECDSAPublicKey(f *testing.F) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	seed, _ := ECDSAPublicKeyToCOSEKey(&priv.PublicKey)
	f.Add(seed)
	f.Add([]byte{0xa0})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic; an error return is fine.
		if pub, err := COSEKeyToECDSAPublicKey(data); err == nil {
			// If it decoded, re-encoding then decoding must round-trip.
			reenc, err := ECDSAPublicKeyToCOSEKey(pub)
			require.NoError(t, err)
			again, err := COSEKeyToECDSAPublicKey(reenc)
			require.NoError(t, err)
			assert.Equal(t, pub.X, again.X)
			assert.Equal(t, pub.Y, again.Y)
		}
	})
}
