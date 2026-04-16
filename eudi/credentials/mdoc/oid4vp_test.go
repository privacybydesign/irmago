package mdoc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/credentials/mdoc/testissuer"
)

// TestOID4VPSessionTranscript_Shape fixes the CBOR shape we emit so a
// spec-compliant verifier can rebuild and compare byte-for-byte.
func TestOID4VPSessionTranscript_Shape(t *testing.T) {
	st, err := mdoc.BuildOID4VPSessionTranscript(
		"x509_san_dns:verifier.example.com",
		"https://verifier.example.com/cb",
		"nonce-abc123",
	)
	require.NoError(t, err)

	var arr []cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(st, &arr))
	require.Len(t, arr, 3)

	// First two elements are null (no DeviceEngagement / EReaderKey in OID4VP).
	var first, second any
	require.NoError(t, cbor.Unmarshal(arr[0], &first))
	require.NoError(t, cbor.Unmarshal(arr[1], &second))
	assert.Nil(t, first)
	assert.Nil(t, second)

	// Third element is the OID4VPHandover = [clientIdHash, responseUriHash, nonce].
	var handover []cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(arr[2], &handover))
	require.Len(t, handover, 3)

	var clientIdHash, responseUriHash []byte
	var nonce string
	require.NoError(t, cbor.Unmarshal(handover[0], &clientIdHash))
	require.NoError(t, cbor.Unmarshal(handover[1], &responseUriHash))
	require.NoError(t, cbor.Unmarshal(handover[2], &nonce))
	assert.Len(t, clientIdHash, 32, "SHA-256 should be 32 bytes")
	assert.Len(t, responseUriHash, 32)
	assert.Equal(t, "nonce-abc123", nonce)
}

// TestSignDeviceAuth_VerifiesRoundTrip signs with the device key and then
// verifies with the matching public key via VerifyDeviceAuth — proving
// wallet and verifier agree on the Sig_structure bytes.
func TestSignDeviceAuth_VerifiesRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sessionTranscript, err := mdoc.BuildOID4VPSessionTranscript(
		"did:example:verifier", "https://verifier.example/cb", "nonce-xyz",
	)
	require.NoError(t, err)

	deviceSigned, err := mdoc.SignDeviceAuth(sessionTranscript, testissuer.AVDocType, key)
	require.NoError(t, err)
	require.NotEmpty(t, deviceSigned)

	assert.NoError(t, mdoc.VerifyDeviceAuth(deviceSigned, sessionTranscript, testissuer.AVDocType, &key.PublicKey))
}

// TestSignDeviceAuth_FailsOnWrongKey guards against the obvious regression:
// a verifier using the wrong public key must not accept.
func TestSignDeviceAuth_FailsOnWrongKey(t *testing.T) {
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	st, _ := mdoc.BuildOID4VPSessionTranscript("c", "r", "n")
	ds, err := mdoc.SignDeviceAuth(st, testissuer.AVDocType, signer)
	require.NoError(t, err)

	err = mdoc.VerifyDeviceAuth(ds, st, testissuer.AVDocType, &wrong.PublicKey)
	require.Error(t, err)
}

// TestSignDeviceAuth_FailsOnWrongTranscript proves the DeviceAuth binds to
// the exact SessionTranscript — a verifier with a mismatched transcript
// (wrong nonce, wrong client id, replayed session) must fail verification.
func TestSignDeviceAuth_FailsOnWrongTranscript(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	st1, _ := mdoc.BuildOID4VPSessionTranscript("c", "r", "nonce-1")
	st2, _ := mdoc.BuildOID4VPSessionTranscript("c", "r", "nonce-2")

	ds, err := mdoc.SignDeviceAuth(st1, testissuer.AVDocType, key)
	require.NoError(t, err)

	err = mdoc.VerifyDeviceAuth(ds, st2, testissuer.AVDocType, &key.PublicKey)
	require.Error(t, err)
}
