package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// These tests hold dcapi.go against a captured org-iso-mdoc exchange — the same
// Age Verification traffic zkp_av_sample_test.go replays, one layer further out.
// ISO/IEC 18013-7 is paywalled, so the capture is the reference: where a test
// asserts a byte, that byte is what a real reader and a real wallet put on the
// wire.
//
// The fixtures below are transcribed from that exchange.

// capturedEncryptionInfoHex is the whole `encryptionInfo` field of the request,
// base64url-decoded: ["dcapi", {"nonce": h'd7c4…', "recipientPublicKey": {1: 2,
// -1: 1, -2: h'594f…', -3: h'072c…'}}].
const capturedEncryptionInfoHex = "82656463617069a2656e6f6e636550d7c487892d843ac86d5c326fa8a7ddd3" +
	"72726563697069656e745075626c69634b6579a401022001215820594fdf1ad220b0d6714749a388bc41bd" +
	"7a80c3a3dedcc7447dc4abce5de40ba5225820072c8b2ac5bb4dcb40d8b15f5d99cc8b5395869b42d3687d" +
	"b513de6a69fde5a0"

const (
	capturedNonceHex = "d7c487892d843ac86d5c326fa8a7ddd3"
	capturedKeyXHex  = "594fdf1ad220b0d6714749a388bc41bd7a80c3a3dedcc7447dc4abce5de40ba5"
	capturedKeyYHex  = "072c8b2ac5bb4dcb40d8b15f5d99cc8b5395869b42d3687db513de6a69fde5a0"
)

// capturedResponseHeaderHex is the first 95 bytes of the DC API `response`
// field: the envelope, the 65-byte `enc`, and the length prefix of a
// cipherText the wallet sent as 325,345 bytes. The sealed body is omitted —
// these tests never decrypt, and could not: the reader's private key was not
// captured and the HPKE info is a session transcript that needs an origin.
const capturedResponseHeaderHex = "82656463617069a263656e63584104af4a0185b9033f5fcb9f01a687" +
	"2393a581ccd1d3403d5a13c17c46baf772657608be8d403cfab5835eae4fbefc2090cf4e1dc61fb4f8ead1" +
	"85b9d5b1f1f325756a636970686572546578745a0004f6e1"

const capturedResponseEncHex = "04af4a0185b9033f5fcb9f01a6872393a581ccd1d3403d5a13c17c46baf7" +
	"72657608be8d403cfab5835eae4fbefc2090cf4e1dc61fb4f8ead185b9d5b1f1f32575"

// capturedCipherTextLen is the length the captured `cipherText` declares. A
// sealed DeviceResponse carrying a zero-knowledge proof is this size; it is
// asserted because the CBOR length prefix for it is a four-byte 0x5a form, and
// an encoder that emitted a different width would still decode correctly while
// producing bytes no digest over the response would match.
const capturedCipherTextLen = 325345

func mustDCAPIHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// TestDCAPIEncryptionInfoDecodesCapture reads the reader's half of the captured
// exchange and recovers the two things a wallet needs from it.
func TestDCAPIEncryptionInfoDecodesCapture(t *testing.T) {
	var info DCAPIEncryptionInfo
	require.NoError(t, cbor.Unmarshal(mustDCAPIHex(t, capturedEncryptionInfoHex), &info))

	require.Equal(t, mustDCAPIHex(t, capturedNonceHex), info.Nonce)
	require.Len(t, info.Nonce, 16)

	key, err := info.RecipientKey()
	require.NoError(t, err)
	require.Equal(t, elliptic.P256(), key.Curve)

	// Compared as the uncompressed encoding rather than through key.X/key.Y,
	// which are deprecated: the coordinates are what the capture gives, so
	// 0x04 || X || Y is the form that holds both sides to the same bytes.
	ecdhKey, err := key.ECDH()
	require.NoError(t, err)
	wantPoint := append([]byte{0x04}, append(mustDCAPIHex(t, capturedKeyXHex), mustDCAPIHex(t, capturedKeyYHex)...)...)
	require.Equal(t, wantPoint, ecdhKey.Bytes())
}

// TestDCAPIEncryptionInfoRoundTripsToCapturedBytes is the check the re-encoding
// hazard in dcapi.go is about.
//
// It passing means canonical CBOR happens to reproduce this reader's bytes
// exactly — the map keys sort the way it emitted them, at both levels. That is
// worth knowing and worth a regression test. It is NOT permission to rebuild
// the structure on the wallet side: the session transcript hashes the base64url
// of the received bytes, and a reader that emitted a non-canonical map would
// round-trip to something different here while this test still passed.
func TestDCAPIEncryptionInfoRoundTripsToCapturedBytes(t *testing.T) {
	captured := mustDCAPIHex(t, capturedEncryptionInfoHex)

	var info DCAPIEncryptionInfo
	require.NoError(t, cbor.Unmarshal(captured, &info))

	reencoded, err := cbor.Marshal(info)
	require.NoError(t, err)
	require.Equal(t, captured, reencoded)
}

// TestNewDCAPIEncryptionInfoReproducesCapture builds the reader's half from
// scratch — a nonce and an *ecdsa.PublicKey — and lands on the captured bytes.
//
// This exercises coseKeyFromECDSA against a real reader's output rather than
// against our own decoder, which is the only way to catch a COSE_Key we encode
// self-consistently but differently from everyone else.
func TestNewDCAPIEncryptionInfoReproducesCapture(t *testing.T) {
	recipient := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(mustDCAPIHex(t, capturedKeyXHex)),
		Y:     new(big.Int).SetBytes(mustDCAPIHex(t, capturedKeyYHex)),
	}

	info, err := NewDCAPIEncryptionInfo(mustDCAPIHex(t, capturedNonceHex), recipient)
	require.NoError(t, err)

	encoded, err := cbor.Marshal(info)
	require.NoError(t, err)
	require.Equal(t, mustDCAPIHex(t, capturedEncryptionInfoHex), encoded)
}

func TestNewDCAPIEncryptionInfoRejectsEmptyInput(t *testing.T) {
	valid := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(mustDCAPIHex(t, capturedKeyXHex)),
		Y:     new(big.Int).SetBytes(mustDCAPIHex(t, capturedKeyYHex)),
	}

	_, err := NewDCAPIEncryptionInfo(nil, valid)
	require.ErrorContains(t, err, "nonce is empty")

	_, err = NewDCAPIEncryptionInfo(mustDCAPIHex(t, capturedNonceHex), nil)
	require.ErrorContains(t, err, "recipient key is nil")
}

// TestDCAPIEncryptedResponseMatchesCapturedHeader encodes the wallet's half
// with the captured encapsulated key and a cipherText of the captured length,
// then compares the leading bytes to what the wallet actually sent.
//
// The body is filler — only the framing is under test — but the length is not:
// it fixes the 0x5a four-byte length form, and it fixes `enc` sorting ahead of
// `cipherText`, which canonical CBOR decides by key length rather than by the
// order they are written in the struct.
func TestDCAPIEncryptedResponseMatchesCapturedHeader(t *testing.T) {
	response := DCAPIEncryptedResponse{
		Enc:        mustDCAPIHex(t, capturedResponseEncHex),
		CipherText: make([]byte, capturedCipherTextLen),
	}
	require.Len(t, response.Enc, 65, "enc is an uncompressed P-256 point")
	require.Equal(t, byte(0x04), response.Enc[0], "uncompressed point prefix")

	encoded, err := cbor.Marshal(response)
	require.NoError(t, err)

	header := mustDCAPIHex(t, capturedResponseHeaderHex)
	require.Equal(t, header, encoded[:len(header)])
	require.Len(t, encoded, len(header)+capturedCipherTextLen)
}

func TestDCAPIEncryptedResponseRoundTrips(t *testing.T) {
	original := DCAPIEncryptedResponse{
		Enc:        mustDCAPIHex(t, capturedResponseEncHex),
		CipherText: []byte("sealed DeviceResponse"),
	}

	encoded, err := cbor.Marshal(original)
	require.NoError(t, err)

	var decoded DCAPIEncryptedResponse
	require.NoError(t, cbor.Unmarshal(encoded, &decoded))
	require.Equal(t, original.Enc, decoded.Enc)
	require.Equal(t, original.CipherText, decoded.CipherText)
}

// TestDCAPIEnvelopeRejectsForeignMessages covers the reason the "dcapi" tag is
// checked at all: the DC API hands every protocol's response back in a field of
// the same name, so the first thing either decoder sees may belong to something
// else entirely.
func TestDCAPIEnvelopeRejectsForeignMessages(t *testing.T) {
	notAnArray, err := cbor.Marshal(map[string]string{"vp_token": "…"})
	require.NoError(t, err)

	wrongTag, err := cbor.Marshal([]any{"openid4vp", map[string]string{}})
	require.NoError(t, err)

	tooManyElements, err := cbor.Marshal([]any{"dcapi", map[string]string{}, "extra"})
	require.NoError(t, err)

	for _, tc := range []struct {
		name  string
		input []byte
		want  string
	}{
		{"not an array", notAnArray, "not a CBOR array"},
		{"foreign protocol tag", wrongTag, `is "openid4vp", want "dcapi"`},
		{"three elements", tooManyElements, "want a 2-element array, got 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var info DCAPIEncryptionInfo
			require.ErrorContains(t, cbor.Unmarshal(tc.input, &info), tc.want)

			var response DCAPIEncryptedResponse
			require.ErrorContains(t, cbor.Unmarshal(tc.input, &response), tc.want)
		})
	}
}

// TestDCAPIEnvelopeRejectsMissingFields keeps a half-populated envelope from
// reaching HPKE, where an absent nonce or enc would surface as a decryption
// failure rather than as the malformed request it is.
func TestDCAPIEnvelopeRejectsMissingFields(t *testing.T) {
	noNonce, err := cbor.Marshal([]any{"dcapi", map[string]any{
		"recipientPublicKey": cbor.RawMessage(mustDCAPIHex(t, "a0")),
	}})
	require.NoError(t, err)
	var info DCAPIEncryptionInfo
	require.ErrorContains(t, cbor.Unmarshal(noNonce, &info), "nonce is absent or empty")

	noKey, err := cbor.Marshal([]any{"dcapi", map[string]any{
		"nonce": mustDCAPIHex(t, capturedNonceHex),
	}})
	require.NoError(t, err)
	require.ErrorContains(t, cbor.Unmarshal(noKey, &info), "recipientPublicKey is absent")

	noCipherText, err := cbor.Marshal([]any{"dcapi", map[string]any{
		"enc": mustDCAPIHex(t, capturedResponseEncHex),
	}})
	require.NoError(t, err)
	var response DCAPIEncryptedResponse
	require.ErrorContains(t, cbor.Unmarshal(noCipherText, &response), "cipherText is absent or empty")
}

// TestDCAPIEncryptionInfoRejectsOffCurveKey confirms RecipientKey routes through
// the validating reconstruction rather than cose.Key.PublicKey, which would
// hand back a usable *ecdsa.PublicKey for a point that is not on P-256.
func TestDCAPIEncryptionInfoRejectsOffCurveKey(t *testing.T) {
	offCurve, err := cbor.Marshal(map[any]any{
		1:  2,
		-1: 1,
		-2: mustDCAPIHex(t, capturedKeyXHex),
		-3: mustDCAPIHex(t, capturedKeyXHex), // Y := X, which is not on the curve
	})
	require.NoError(t, err)

	info := DCAPIEncryptionInfo{
		Nonce:              mustDCAPIHex(t, capturedNonceHex),
		RecipientPublicKey: offCurve,
	}
	_, err = info.RecipientKey()
	require.Error(t, err)
}
