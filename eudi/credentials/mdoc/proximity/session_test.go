package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionEncryptionReaderAgainstAnnexDVector is transpiled from multipaz:
//
//	multipaz/src/commonTest/kotlin/org/multipaz/mdoc/sessionencryption/
//	  SessionEncryptionTest.kt -> testReaderAgainstVectors()
//
// Exercises the reader side of session encryption against the canonical
// ISO 18013-5 Annex D vectors: derive SK.Reader/SK.Device from ECDH-ES,
// produce a byte-for-byte match of SessionEstablishment, then decrypt the
// mdoc's SessionData response.
func TestSessionEncryptionReaderAgainstAnnexDVector(t *testing.T) {
	eReader := mustEcdsaPrivFromHex(t,
		ISO_18013_5_ANNEX_D_EPHEMERAL_READER_KEY_D,
		ISO_18013_5_ANNEX_D_EPHEMERAL_READER_KEY_X,
		ISO_18013_5_ANNEX_D_EPHEMERAL_READER_KEY_Y,
	)
	eDevice := mustEcdsaPubFromHex(t,
		ISO_18013_5_ANNEX_D_EPHEMERAL_DEVICE_KEY_X,
		ISO_18013_5_ANNEX_D_EPHEMERAL_DEVICE_KEY_Y,
	)

	sessionTranscript := stripTag24(t, ISO_18013_5_ANNEX_D_SESSION_TRANSCRIPT_BYTES)

	sess, err := NewSessionEncryption(RoleReader, eReader, eDevice, sessionTranscript)
	require.NoError(t, err)

	// Encrypt the reader's DeviceRequest. Must match the vector byte-for-byte,
	// proving both the session-key derivation and the GCM IV construction.
	req, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_REQUEST)
	out, err := sess.EncryptMessage(req, nil)
	require.NoError(t, err)
	expectedEstab, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_SESSION_ESTABLISHMENT)
	assert.Equal(t, expectedEstab, out, "SessionEstablishment differs from Annex D vector")

	// Decrypt the mdoc's SessionData reply (the full DeviceResponse in clear).
	sessionData, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_SESSION_DATA)
	plain, status, err := sess.DecryptMessage(sessionData)
	require.NoError(t, err)
	assert.Nil(t, status)
	expectedResp, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_RESPONSE_HEX)
	assert.Equal(t, expectedResp, plain)

	// Decrypt the termination message — data nil, status=20.
	term, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_SESSION_TERMINATION)
	plain, status, err = sess.DecryptMessage(term)
	require.NoError(t, err)
	assert.Nil(t, plain)
	require.NotNil(t, status)
	assert.Equal(t, StatusSessionTermination, *status)

	// The reader itself can also emit a termination.
	out, err = sess.EncryptMessage(nil, ptrU64(StatusSessionTermination))
	require.NoError(t, err)
	assert.Equal(t, term, out)
}

// TestSessionEncryptionDeviceAgainstAnnexDVector is the mdoc-side mirror of
// the reader test: decrypts the reader's SessionEstablishment, then encrypts
// the canonical DeviceResponse and checks it equals SESSION_DATA.
func TestSessionEncryptionDeviceAgainstAnnexDVector(t *testing.T) {
	eDevice := mustEcdsaPrivFromHex(t,
		ISO_18013_5_ANNEX_D_EPHEMERAL_DEVICE_KEY_D,
		ISO_18013_5_ANNEX_D_EPHEMERAL_DEVICE_KEY_X,
		ISO_18013_5_ANNEX_D_EPHEMERAL_DEVICE_KEY_Y,
	)

	sessionEstab, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_SESSION_ESTABLISHMENT)
	eReaderPub, _, err := GetEReaderKeyFromSessionEstablishment(sessionEstab)
	require.NoError(t, err)

	sessionTranscript := stripTag24(t, ISO_18013_5_ANNEX_D_SESSION_TRANSCRIPT_BYTES)
	sess, err := NewSessionEncryption(RoleMDOC, eDevice, eReaderPub, sessionTranscript)
	require.NoError(t, err)

	plain, status, err := sess.DecryptMessage(sessionEstab)
	require.NoError(t, err)
	assert.Nil(t, status)
	expectedReq, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_REQUEST)
	assert.Equal(t, expectedReq, plain)

	resp, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_DEVICE_RESPONSE_HEX)
	out, err := sess.EncryptMessage(resp, nil)
	require.NoError(t, err)
	expectedData, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_SESSION_DATA)
	assert.Equal(t, expectedData, out)
}

// TestSessionEncryptionRoundTripFreshKeys exercises a full reader↔holder
// round-trip using freshly generated P-256 keys; catches any subtle mistake
// in the per-direction counter or IV-identifier logic that the Annex D tests
// miss (they only cover one encrypt per side).
func TestSessionEncryptionRoundTripFreshKeys(t *testing.T) {
	eReader, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	eDevice, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	transcript := []byte{1, 2, 3}

	reader, err := NewSessionEncryption(RoleReader, eReader, &eDevice.PublicKey, transcript)
	require.NoError(t, err)
	device, err := NewSessionEncryption(RoleMDOC, eDevice, &eReader.PublicKey, transcript)
	require.NoError(t, err)

	for i := 1; i <= 3; i++ {
		req := []byte{byte(i), 0xaa, 0xbb}
		msg, err := reader.EncryptMessage(req, nil)
		require.NoError(t, err)
		plain, status, err := device.DecryptMessage(msg)
		require.NoError(t, err)
		assert.Nil(t, status)
		assert.Equal(t, req, plain)
		assert.Equal(t, i, reader.NumMessagesEncrypted())
		assert.Equal(t, i, device.NumMessagesDecrypted())

		resp := []byte{byte(i), 0xcc, 0xdd}
		msg, err = device.EncryptMessage(resp, nil)
		require.NoError(t, err)
		plain, status, err = reader.DecryptMessage(msg)
		require.NoError(t, err)
		assert.Nil(t, status)
		assert.Equal(t, resp, plain)
		assert.Equal(t, i, device.NumMessagesEncrypted())
		assert.Equal(t, i, reader.NumMessagesDecrypted())
	}
}

// TestEncodeStatusProducesTerminationVector is a narrow check that
// EncodeStatus(20) yields the exact three-byte Annex D session-termination
// payload; ensures the CBOR encoder used for bare-status messages matches
// other implementations bit-for-bit.
func TestEncodeStatusProducesTerminationVector(t *testing.T) {
	out, err := EncodeStatus(StatusSessionTermination)
	require.NoError(t, err)
	expected, _ := hex.DecodeString(ISO_18013_5_ANNEX_D_SESSION_TERMINATION)
	assert.Equal(t, expected, out)
}

// ---- helpers ---------------------------------------------------------------

func mustEcdsaPubFromHex(t *testing.T, xHex, yHex string) *ecdsa.PublicKey {
	t.Helper()
	x, err := hex.DecodeString(xHex)
	require.NoError(t, err)
	y, err := hex.DecodeString(yHex)
	require.NoError(t, err)
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}
}

func mustEcdsaPrivFromHex(t *testing.T, dHex, xHex, yHex string) *ecdsa.PrivateKey {
	t.Helper()
	d, err := hex.DecodeString(dHex)
	require.NoError(t, err)
	pub := mustEcdsaPubFromHex(t, xHex, yHex)
	return &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(d),
	}
}

// stripTag24 takes a hex-encoded CBOR value that begins with tag 24 wrapping a
// bstr (the shape ISO 18013-5 uses for "<something>Bytes") and returns the
// inner bstr contents. The SessionEncryption HKDF takes those inner bytes.
func stripTag24(t *testing.T, taggedHex string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(taggedHex)
	require.NoError(t, err)
	inner, err := innerOfTag24(raw)
	require.NoError(t, err)
	return inner
}

// innerOfTag24 unwraps a CBOR `#6.24(bstr .cbor ...)` value to its inner
// bstr contents. Used by the tests to strip the SessionTranscript's outer
// tag before feeding the bytes to SessionEncryption.
func innerOfTag24(b []byte) ([]byte, error) {
	var tagged cbor.Tag
	if err := cbor.Unmarshal(b, &tagged); err != nil {
		return nil, err
	}
	if tagged.Number != 24 {
		return nil, fmt.Errorf("expected tag 24, got %d", tagged.Number)
	}
	inner, ok := tagged.Content.([]byte)
	if !ok {
		return nil, fmt.Errorf("tag 24 content is %T, want bstr", tagged.Content)
	}
	return inner, nil
}

func ptrU64(v uint64) *uint64 { return &v }
