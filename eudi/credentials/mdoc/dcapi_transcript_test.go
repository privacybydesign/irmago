package mdoc

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// The org-iso-mdoc handover:
//
//	SessionTranscript = [null, null, ["dcapi", SHA-256(cbor([base64url(EncryptionInfo), origin]))]]
//
// ISO/IEC 18013-7 is paywalled, so the formula is taken from Multipaz's reader
// (VerificationUtil.kt, the "org-iso-mdoc" branch) — the same conformance target
// zkp.go uses. These tests recompute it independently rather than calling the
// production helper, so a change to either side shows up as a disagreement.

const testOrigin = "https://verifier.example.com"

func testEncryptionInfoBase64(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(mustDCAPIHex(t, capturedEncryptionInfoHex))
}

// TestDCAPISessionTranscriptShape pins all three slots, and recomputes the digest
// from the clause's own inputs rather than trusting the constructor.
func TestDCAPISessionTranscriptShape(t *testing.T) {
	encryptionInfo := testEncryptionInfoBase64(t)

	transcript, err := NewDCAPISessionTranscript(encryptionInfo, testOrigin)
	require.NoError(t, err)

	// Both leading slots are null: there is no engagement to bind.
	require.Empty(t, transcript.DeviceEngagementBytes)
	require.Empty(t, transcript.EReaderKeyBytes)

	handover, ok := transcript.Handover.([]any)
	require.True(t, ok, "handover is a two-element array")
	require.Len(t, handover, 2)
	require.Equal(t, "dcapi", handover[0])

	handoverInfo, err := cbor.Marshal([]any{encryptionInfo, testOrigin})
	require.NoError(t, err)
	want := sha256.Sum256(handoverInfo)
	require.Equal(t, want[:], handover[1])
}

// TestDCAPISessionTranscriptEncodesWithNullSlots checks what actually goes on the
// wire, since the two null slots are the part a struct assertion cannot see: a
// nil cbor.RawMessage has to encode as CBOR null and not vanish or become an
// empty byte string, either of which is a different transcript.
func TestDCAPISessionTranscriptEncodesWithNullSlots(t *testing.T) {
	transcript, err := NewDCAPISessionTranscript(testEncryptionInfoBase64(t), testOrigin)
	require.NoError(t, err)

	encoded, err := cbor.Marshal(transcript)
	require.NoError(t, err)

	var generic []any
	require.NoError(t, cbor.Unmarshal(encoded, &generic))
	require.Len(t, generic, 3, "SessionTranscript is a three-element array")
	require.Nil(t, generic[0], "DeviceEngagementBytes is null")
	require.Nil(t, generic[1], "EReaderKeyBytes is null")

	// 0x83 = array(3), 0xf6 = null, twice.
	require.Equal(t, []byte{0x83, 0xf6, 0xf6}, encoded[:3])
}

// TestDCAPISessionTranscriptBindsEveryInput is the property the handover exists
// for: change any input and the digest moves. An origin that did not reach the
// digest would leave a response built for one site replayable at another.
func TestDCAPISessionTranscriptBindsEveryInput(t *testing.T) {
	encryptionInfo := testEncryptionInfoBase64(t)

	digestOf := func(t *testing.T, info, origin string) []byte {
		t.Helper()
		transcript, err := NewDCAPISessionTranscript(info, origin)
		require.NoError(t, err)
		return transcript.Handover.([]any)[1].([]byte)
	}

	base := digestOf(t, encryptionInfo, testOrigin)

	otherOrigin := digestOf(t, encryptionInfo, "https://attacker.example.com")
	require.NotEqual(t, base, otherOrigin, "origin must be bound")

	// A different nonce is a different EncryptionInfo, which is the usual way two
	// sessions with the same verifier differ.
	otherInfo := base64.RawURLEncoding.EncodeToString(
		mustDCAPIHex(t, "82656463617069a2656e6f6e636550ffffffffffffffffffffffffffffffff"+
			"72726563697069656e745075626c69634b6579a401022001215820594fdf1ad220b0d6714749a388bc41bd"+
			"7a80c3a3dedcc7447dc4abce5de40ba5225820072c8b2ac5bb4dcb40d8b15f5d99cc8b5395869b42d3687d"+
			"b513de6a69fde5a0"))
	require.NotEqual(t, base, digestOf(t, otherInfo, testOrigin), "EncryptionInfo must be bound")
}

// TestDCAPISessionTranscriptHashesTheStringAsReceived is the re-encoding hazard
// from dcapi.go, stated as a test.
//
// Base64url admits padded and unpadded spellings of the same bytes. The digest is
// over the text, so the two are different transcripts — and a wallet that
// normalised, or that rebuilt the string from a decoded DCAPIEncryptionInfo,
// would compute a transcript the reader does not share. The failure would surface
// as an invalid deviceAuth signature, naming the wrong culprit.
func TestDCAPISessionTranscriptHashesTheStringAsReceived(t *testing.T) {
	raw := mustDCAPIHex(t, capturedEncryptionInfoHex)
	unpadded := base64.RawURLEncoding.EncodeToString(raw)
	padded := base64.URLEncoding.EncodeToString(raw)
	require.NotEqual(t, unpadded, padded, "the fixture must actually need padding for this to test anything")

	a, err := NewDCAPISessionTranscript(unpadded, testOrigin)
	require.NoError(t, err)
	b, err := NewDCAPISessionTranscript(padded, testOrigin)
	require.NoError(t, err)

	require.NotEqual(t, a.Handover.([]any)[1], b.Handover.([]any)[1],
		"the digest covers the text as received, so two spellings of the same bytes are two transcripts")
}

// TestDCAPISessionTranscriptNeverCollidesWithOtherHandovers keeps the four
// variants distinguishable. They share a SessionTranscript type and two of them
// share a transport, so a document signed under one must not verify under
// another.
func TestDCAPISessionTranscriptNeverCollidesWithOtherHandovers(t *testing.T) {
	dcapi, err := NewDCAPISessionTranscript(testEncryptionInfoBase64(t), testOrigin)
	require.NoError(t, err)

	qr, err := NewQRSessionTranscript(testTag24("device-engagement"), testTag24("ereader-key"))
	require.NoError(t, err)

	nfc, err := NewNFCSessionTranscript(
		testTag24("device-engagement"), testTag24("ereader-key"), []byte("handover-select"), nil)
	require.NoError(t, err)

	encode := func(t *testing.T, transcript SessionTranscript) string {
		t.Helper()
		b, err := cbor.Marshal(transcript)
		require.NoError(t, err)
		return string(b)
	}

	seen := map[string]string{}
	for name, transcript := range map[string]SessionTranscript{
		"dcapi": dcapi, "qr": qr, "nfc": nfc,
	} {
		encoded := encode(t, transcript)
		if other, dup := seen[encoded]; dup {
			t.Fatalf("%s and %s encode identically", name, other)
		}
		seen[encoded] = name
	}
}

func TestDCAPISessionTranscriptRejectsBadInput(t *testing.T) {
	encryptionInfo := testEncryptionInfoBase64(t)

	_, err := NewDCAPISessionTranscript("", testOrigin)
	require.ErrorContains(t, err, "requires the base64url EncryptionInfo")

	_, err = NewDCAPISessionTranscript(encryptionInfo, "")
	require.ErrorContains(t, err, "requires an origin")

	// The decoded CBOR where the encoded string belongs: well-formed input that
	// would otherwise yield a transcript disagreeing with the reader's.
	_, err = NewDCAPISessionTranscript(string(mustDCAPIHex(t, capturedEncryptionInfoHex)), testOrigin)
	require.ErrorContains(t, err, "not base64url text")
}
