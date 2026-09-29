package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// HPKE for org-iso-mdoc: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM,
// with `info` the encoded SessionTranscript and empty `aad`.
//
// The suite is no longer guesswork. ISO/IEC TS 18013-7:2025 Table C.1 fixes all
// four parameters — Mode Base, KEM DHKEM_P256, KDF HKDF_SHA256, AEAD
// AES_128_GCM — and Tables C.2/C.3 fix `info` as the CBOR-encoded
// SessionTranscript and `aad` as empty. That is what dcapiSuite returns.
//
// What is still missing is test VECTORS. The captured exchange cannot be
// decrypted — the reader's private key was never on the wire — and none are
// published. So these tests pin the two things checkable without one: that our
// own two halves agree, and that the exchange is bound to everything it should
// be. A suite mismatch against another implementation would surface as "it does
// not open", and that is the one risk this file cannot retire; interop testing
// against a real reader is what retires it.

// dcapiSession is one request's worth of reader state: the ephemeral key pair,
// the EncryptionInfo built from it, and the transcript both sides derive.
type dcapiSession struct {
	readerKey      *ecdsa.PrivateKey
	encryptionInfo string
	transcript     SessionTranscript
}

func newDCAPISession(t *testing.T, origin string) dcapiSession {
	t.Helper()

	readerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	nonce := make([]byte, 16)
	_, err = rand.Read(nonce)
	require.NoError(t, err)

	info, err := NewDCAPIEncryptionInfo(nonce, &readerKey.PublicKey)
	require.NoError(t, err)
	encoded, err := cbor.Marshal(info)
	require.NoError(t, err)
	encryptionInfo := base64.RawURLEncoding.EncodeToString(encoded)

	transcript, err := NewDCAPISessionTranscript(encryptionInfo, origin)
	require.NoError(t, err)

	return dcapiSession{readerKey: readerKey, encryptionInfo: encryptionInfo, transcript: transcript}
}

// TestDCAPIResponseRoundTrip walks the whole wallet-to-reader path: a reader
// advertises a key in EncryptionInfo, a wallet seals a DeviceResponse to it, and
// the reader opens it with the private half.
func TestDCAPIResponseRoundTrip(t *testing.T) {
	session := newDCAPISession(t, testOrigin)
	plaintext := []byte("an encoded DeviceResponse")

	// The wallet only ever sees the public key, exactly as it arrives.
	var received DCAPIEncryptionInfo
	raw, err := base64.RawURLEncoding.DecodeString(session.encryptionInfo)
	require.NoError(t, err)
	require.NoError(t, cbor.Unmarshal(raw, &received))
	recipient, err := received.RecipientKey()
	require.NoError(t, err)

	sealed, err := SealDCAPIResponse(plaintext, recipient, session.transcript)
	require.NoError(t, err)
	require.Len(t, sealed.Enc, 65, "DHKEM(P-256) encapsulates as an uncompressed point")
	require.Equal(t, byte(0x04), sealed.Enc[0])
	require.NotEqual(t, plaintext, sealed.CipherText)

	opened, err := OpenDCAPIResponse(sealed, session.readerKey, session.transcript)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}

// TestDCAPIResponseSurvivesTheEnvelope checks the crypto and the CBOR agree —
// that what seal produces still opens after a trip through the wire format.
func TestDCAPIResponseSurvivesTheEnvelope(t *testing.T) {
	session := newDCAPISession(t, testOrigin)
	plaintext := []byte("an encoded DeviceResponse")

	sealed, err := SealDCAPIResponse(plaintext, &session.readerKey.PublicKey, session.transcript)
	require.NoError(t, err)

	encoded, err := cbor.Marshal(sealed)
	require.NoError(t, err)
	var decoded DCAPIEncryptedResponse
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))

	opened, err := OpenDCAPIResponse(decoded, session.readerKey, session.transcript)
	require.NoError(t, err)
	require.Equal(t, plaintext, opened)
}

// TestDCAPIResponseIsBoundToTheTranscript is the property the whole `info`
// construction exists for. The transcript carries the origin and the
// EncryptionInfo, so binding to it is what stops a response sealed for one
// verifier being opened by another.
func TestDCAPIResponseIsBoundToTheTranscript(t *testing.T) {
	session := newDCAPISession(t, testOrigin)

	sealed, err := SealDCAPIResponse([]byte("secret"), &session.readerKey.PublicKey, session.transcript)
	require.NoError(t, err)

	t.Run("a different origin cannot open it", func(t *testing.T) {
		other, err := NewDCAPISessionTranscript(session.encryptionInfo, "https://attacker.example.com")
		require.NoError(t, err)
		_, err = OpenDCAPIResponse(sealed, session.readerKey, other)
		require.ErrorContains(t, err, "decryption failed")
	})

	t.Run("a different EncryptionInfo cannot open it", func(t *testing.T) {
		elsewhere := newDCAPISession(t, testOrigin)
		other, err := NewDCAPISessionTranscript(elsewhere.encryptionInfo, testOrigin)
		require.NoError(t, err)
		_, err = OpenDCAPIResponse(sealed, session.readerKey, other)
		require.ErrorContains(t, err, "decryption failed")
	})

	t.Run("a QR transcript cannot open it", func(t *testing.T) {
		qr, err := NewQRSessionTranscript(testTag24("device-engagement"), testTag24("ereader-key"))
		require.NoError(t, err)
		_, err = OpenDCAPIResponse(sealed, session.readerKey, qr)
		require.ErrorContains(t, err, "decryption failed")
	})
}

// TestDCAPIResponseIsBoundToTheRecipientKey: only the advertised key opens it.
func TestDCAPIResponseIsBoundToTheRecipientKey(t *testing.T) {
	session := newDCAPISession(t, testOrigin)

	sealed, err := SealDCAPIResponse([]byte("secret"), &session.readerKey.PublicKey, session.transcript)
	require.NoError(t, err)

	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = OpenDCAPIResponse(sealed, stranger, session.transcript)
	require.Error(t, err, "a key the reader never advertised must not open the response")
}

// TestDCAPIResponseRejectsTampering covers both halves of the envelope: AEAD
// protects the ciphertext, and the encapsulated key is an input to the key
// schedule rather than a transmitted hint, so neither can be edited in flight.
func TestDCAPIResponseRejectsTampering(t *testing.T) {
	session := newDCAPISession(t, testOrigin)

	sealed, err := SealDCAPIResponse([]byte("an encoded DeviceResponse"), &session.readerKey.PublicKey, session.transcript)
	require.NoError(t, err)

	t.Run("flipped ciphertext byte", func(t *testing.T) {
		tampered := DCAPIEncryptedResponse{Enc: sealed.Enc, CipherText: append([]byte(nil), sealed.CipherText...)}
		tampered.CipherText[0] ^= 0xff
		_, err := OpenDCAPIResponse(tampered, session.readerKey, session.transcript)
		require.ErrorContains(t, err, "decryption failed")
	})

	t.Run("substituted encapsulated key", func(t *testing.T) {
		other := newDCAPISession(t, testOrigin)
		otherSealed, err := SealDCAPIResponse([]byte("x"), &other.readerKey.PublicKey, other.transcript)
		require.NoError(t, err)

		swapped := DCAPIEncryptedResponse{Enc: otherSealed.Enc, CipherText: sealed.CipherText}
		_, err = OpenDCAPIResponse(swapped, session.readerKey, session.transcript)
		require.Error(t, err)
	})
}

// TestDCAPIHPKEInfoIsTheBareTranscript pins the one detail most likely to be got
// wrong by analogy: `info` is the encoded SessionTranscript, not 9.1.5.1's
// tag-24 SessionTranscriptBytes. Both are plausible, only one interoperates, and
// choosing the other fails as an AEAD error that names nothing.
func TestDCAPIHPKEInfoIsTheBareTranscript(t *testing.T) {
	session := newDCAPISession(t, testOrigin)

	info, err := dcapiHPKEInfo(session.transcript)
	require.NoError(t, err)

	encoded, err := dcapiEncMode.Marshal(session.transcript)
	require.NoError(t, err)
	require.Equal(t, encoded, info)

	wrapped, err := session.transcript.SessionTranscriptBytes()
	require.NoError(t, err)
	require.NotEqual(t, wrapped, info, "info must not be the tag-24 wrapping")
	require.NotEqual(t, byte(0xd8), info[0], "a bare transcript does not start with a tag head")
}

func TestSealAndOpenRejectBadInput(t *testing.T) {
	session := newDCAPISession(t, testOrigin)

	_, err := SealDCAPIResponse(nil, &session.readerKey.PublicKey, session.transcript)
	require.ErrorContains(t, err, "nothing to seal")

	_, err = SealDCAPIResponse([]byte("x"), nil, session.transcript)
	require.ErrorContains(t, err, "recipient key is nil")

	_, err = OpenDCAPIResponse(DCAPIEncryptedResponse{}, session.readerKey, session.transcript)
	require.ErrorContains(t, err, "missing enc or cipherText")

	sealed, err := SealDCAPIResponse([]byte("x"), &session.readerKey.PublicKey, session.transcript)
	require.NoError(t, err)
	_, err = OpenDCAPIResponse(sealed, nil, session.transcript)
	require.ErrorContains(t, err, "recipient private key is nil")
}
