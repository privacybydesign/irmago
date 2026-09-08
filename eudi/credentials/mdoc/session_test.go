package mdoc

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// isoTranscript returns the D.5.1 SessionTranscript, the one ISO's published ZAB
// and session keys belong to.
func isoTranscript(t *testing.T) SessionTranscript {
	t.Helper()
	transcript, err := tag24Unwrap[SessionTranscript](mustHex(t, isoAnnexDSessionTranscriptBytes))
	if err != nil {
		t.Fatalf("decode ISO SessionTranscriptBytes: %v", err)
	}
	return transcript
}

// TestSessionKeysFromZAB_MatchISOAnnexD runs the production derivation over ISO's
// published ZAB and requires both of ISO's published session keys.
//
// This is the 9.1.1.4 HKDF under test through the code the session actually uses,
// rather than through a test-local reimplementation of it. Annex D publishes no
// private keys, so the ECKA-DH step above it cannot be pinned to ISO's numbers —
// which is why deriveSessionKeys is split at exactly this point.
func TestSessionKeysFromZAB_MatchISOAnnexD(t *testing.T) {
	keys, err := sessionKeysFromZAB(mustHex(t, isoAnnexDZab), isoTranscript(t))
	if err != nil {
		t.Fatalf("sessionKeysFromZAB: %v", err)
	}
	if got := hex.EncodeToString(keys.SKReader); got != isoAnnexDSKReader {
		t.Errorf("SKReader\n got: %s\nwant: %s", got, isoAnnexDSKReader)
	}
	if got := hex.EncodeToString(keys.SKDevice); got != isoAnnexDSKDevice {
		t.Errorf("SKDevice\n got: %s\nwant: %s", got, isoAnnexDSKDevice)
	}
}

// TestSessionIV pins 9.1.1.5 byte for byte: a 12-byte IV of `identifier ||
// counter`, the reader's identifier all zeroes, the mdoc's ending 0x01, and the
// counter a 4-byte big-endian integer starting at 1.
func TestSessionIV(t *testing.T) {
	for name, tc := range map[string]struct {
		identifier [8]byte
		counter    uint32
		want       string
	}{
		"reader, first message": {readerIdentifier, 1, "000000000000000000000001"},
		"mdoc, first message":   {mdocIdentifier, 1, "000000000000000100000001"},
		"reader, counter 258":   {readerIdentifier, 258, "000000000000000000000102"},
		"mdoc, counter max":     {mdocIdentifier, 0xffffffff, "0000000000000001ffffffff"},
	} {
		t.Run(name, func(t *testing.T) {
			got := sessionIV(tc.identifier, tc.counter)
			if len(got) != 12 {
				t.Fatalf("IV is %d bytes, want the 12 of GCM", len(got))
			}
			if hex.EncodeToString(got) != tc.want {
				t.Fatalf("IV\n got: %x\nwant: %s", got, tc.want)
			}
		})
	}
}

// newSessionPair sets up both halves of a session over freshly generated ephemeral
// keys, the way engagement and session establishment would.
func newSessionPair(t *testing.T) (mdocSession, readerSession *Session) {
	t.Helper()

	eDeviceKey, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	eReaderKey, err := GenerateEDeviceKey() // same generator; the reader's half
	if err != nil {
		t.Fatalf("generate EReaderKey: %v", err)
	}

	eDeviceKeyBytes, err := EncodeEDeviceKeyBytes(&eDeviceKey.PublicKey)
	if err != nil {
		t.Fatalf("EncodeEDeviceKeyBytes: %v", err)
	}
	eReaderKeyBytes, err := EncodeEDeviceKeyBytes(&eReaderKey.PublicKey)
	if err != nil {
		t.Fatalf("encode EReaderKeyBytes: %v", err)
	}
	transcript, err := NewQRSessionTranscript(eDeviceKeyBytes, eReaderKeyBytes)
	if err != nil {
		t.Fatalf("NewQRSessionTranscript: %v", err)
	}

	mdocSession, err = NewMdocSession(eDeviceKey, &eReaderKey.PublicKey, transcript)
	if err != nil {
		t.Fatalf("NewMdocSession: %v", err)
	}
	readerSession, err = NewReaderSession(eReaderKey, &eDeviceKey.PublicKey, transcript)
	if err != nil {
		t.Fatalf("NewReaderSession: %v", err)
	}
	return mdocSession, readerSession
}

// TestEckaDhAgreesOnBothSides checks the mirrored inputs of 9.1.1.5 reach the same
// two keys: EDeviceKey.Priv with EReaderKey.Pub on one side, EReaderKey.Priv with
// EDeviceKey.Pub on the other.
func TestEckaDhAgreesOnBothSides(t *testing.T) {
	mdocSession, readerSession := newSessionPair(t)

	if !bytes.Equal(mdocSession.keys.SKReader, readerSession.keys.SKReader) {
		t.Error("SKReader differs between mdoc and reader")
	}
	if !bytes.Equal(mdocSession.keys.SKDevice, readerSession.keys.SKDevice) {
		t.Error("SKDevice differs between mdoc and reader")
	}
	if bytes.Equal(mdocSession.keys.SKReader, mdocSession.keys.SKDevice) {
		t.Error("SKReader and SKDevice are identical; the HKDF info strings are not being applied")
	}
	if len(mdocSession.keys.SKReader) != 32 {
		t.Errorf("session key is %d bytes, want 32", len(mdocSession.keys.SKReader))
	}
}

// TestSessionRoundTrip walks a short session in both directions, which is the
// thing that actually breaks if the roles, identifiers or counters are crossed:
// each side must decrypt under the key and identifier the *other* side encrypted
// with.
func TestSessionRoundTrip(t *testing.T) {
	mdocSession, readerSession := newSessionPair(t)

	request := []byte("mdoc request one")
	sealed, err := readerSession.Encrypt(request)
	if err != nil {
		t.Fatalf("reader Encrypt: %v", err)
	}
	got, err := mdocSession.Decrypt(sealed)
	if err != nil {
		t.Fatalf("mdoc Decrypt: %v", err)
	}
	if !bytes.Equal(got, request) {
		t.Fatalf("round trip: got %q, want %q", got, request)
	}

	response := []byte("mdoc response one")
	sealed, err = mdocSession.Encrypt(response)
	if err != nil {
		t.Fatalf("mdoc Encrypt: %v", err)
	}
	got, err = readerSession.Decrypt(sealed)
	if err != nil {
		t.Fatalf("reader Decrypt: %v", err)
	}
	if !bytes.Equal(got, response) {
		t.Fatalf("round trip: got %q, want %q", got, response)
	}

	// And again, to prove the counters advance in step on both sides rather than
	// only the first message working.
	for i := 0; i < 3; i++ {
		sealed, err = readerSession.Encrypt(request)
		if err != nil {
			t.Fatalf("reader Encrypt %d: %v", i, err)
		}
		if _, err := mdocSession.Decrypt(sealed); err != nil {
			t.Fatalf("mdoc Decrypt %d: %v", i, err)
		}
	}
}

// TestCiphertextIsCiphertextPlusTag pins the shape of the `data` element:
// "the concatenation of the ciphertext and all 16 bytes of the authentication tag".
func TestCiphertextIsCiphertextPlusTag(t *testing.T) {
	_, readerSession := newSessionPair(t)

	plaintext := []byte("0123456789")
	sealed, err := readerSession.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if want := len(plaintext) + 16; len(sealed) != want {
		t.Fatalf("sealed message is %d bytes, want %d (plaintext + 16-byte tag)", len(sealed), want)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Error("plaintext appears verbatim in the sealed message")
	}
}

// TestCounterNeverRepeats is the rule whose breach is catastrophic rather than
// merely non-conformant: an IV reused under GCM leaks the XOR of both plaintexts
// and the authentication subkey with it.
func TestCounterNeverRepeats(t *testing.T) {
	_, readerSession := newSessionPair(t)

	// The same plaintext under a fresh counter each time must give a different
	// ciphertext every time; equal output would mean an IV was reused.
	seen := map[string]bool{}
	plaintext := []byte("identical every time")
	for i := 0; i < 16; i++ {
		sealed, err := readerSession.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		if seen[string(sealed)] {
			t.Fatalf("message %d repeats an earlier ciphertext: the counter was reused", i)
		}
		seen[string(sealed)] = true
	}
	if readerSession.sendCounter != 16 {
		t.Errorf("send counter is %d after 16 messages, want 16", readerSession.sendCounter)
	}
}

// TestFirstMessageUsesCounterOne pins "For the first encryption with a session
// key, the message counter shall be set to 1."
func TestFirstMessageUsesCounterOne(t *testing.T) {
	mdocSession, readerSession := newSessionPair(t)

	sealed, err := readerSession.Encrypt([]byte("first"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if readerSession.sendCounter != 1 {
		t.Fatalf("send counter is %d after the first message, want 1", readerSession.sendCounter)
	}

	// Independently: opening it under an IV built with counter 1 must succeed,
	// and under counter 2 must not.
	if _, err := mdocSession.decrypt.Open(nil, sessionIV(readerIdentifier, 1), sealed, nil); err != nil {
		t.Fatalf("first message does not open under counter 1: %v", err)
	}
	if _, err := mdocSession.decrypt.Open(nil, sessionIV(readerIdentifier, 2), sealed, nil); err == nil {
		t.Fatal("first message opened under counter 2")
	}
}

// TestCounterExhaustionIsRefused: wrapping would reuse an IV, so the session has
// to fail instead.
func TestCounterExhaustionIsRefused(t *testing.T) {
	_, readerSession := newSessionPair(t)

	readerSession.sendCounter = 0xffffffff
	if _, err := readerSession.Encrypt([]byte("one too many")); err == nil {
		t.Fatal("expected an error when the message counter is exhausted")
	}
	if readerSession.sendCounter != 0xffffffff {
		t.Error("counter advanced past exhaustion")
	}
}

// TestDecryptFailureDoesNotAdvanceCounter: a caller that responds to a failure by
// retrying rather than terminating must still be on the right IV.
func TestDecryptFailureDoesNotAdvanceCounter(t *testing.T) {
	mdocSession, readerSession := newSessionPair(t)

	sealed, err := readerSession.Encrypt([]byte("intact"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	corrupted := bytes.Clone(sealed)
	corrupted[0] ^= 0xff

	if _, err := mdocSession.Decrypt(corrupted); err == nil {
		t.Fatal("corrupted message decrypted")
	}
	if mdocSession.recvCounter != 0 {
		t.Fatalf("receive counter advanced to %d on a failed decrypt", mdocSession.recvCounter)
	}
	if _, err := mdocSession.Decrypt(sealed); err != nil {
		t.Fatalf("intact message failed after a corrupted one: %v", err)
	}
}

// TestWrongDirectionDoesNotDecrypt: the identifiers differ precisely so the two
// directions cannot be confused, so a party must not be able to open its own
// message.
func TestWrongDirectionDoesNotDecrypt(t *testing.T) {
	_, readerSession := newSessionPair(t)

	sealed, err := readerSession.Encrypt([]byte("reader to mdoc"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := readerSession.Decrypt(sealed); err == nil {
		t.Fatal("the reader opened its own message; the two directions share an IV space")
	}
}

// TestSessionsFromDifferentTranscriptsCannotTalk is the point of binding the keys
// to the transcript: a session established against a different engagement, or a
// different reader key, derives different keys and cannot be replayed into.
func TestSessionsFromDifferentTranscriptsCannotTalk(t *testing.T) {
	_, readerSession := newSessionPair(t)
	otherMdoc, _ := newSessionPair(t)

	sealed, err := readerSession.Encrypt([]byte("for a different session"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := otherMdoc.Decrypt(sealed); err == nil {
		t.Fatal("a message decrypted under a session it was not established for")
	}
}

// TestCloseDestroysKeys covers 9.1.1.4's "destruction of session keys and related
// ephemeral key material" as far as this struct can.
func TestCloseDestroysKeys(t *testing.T) {
	mdocSession, readerSession := newSessionPair(t)

	sealed, err := readerSession.Encrypt([]byte("before close"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	mdocSession.Close()
	if _, err := mdocSession.Decrypt(sealed); err == nil {
		t.Error("a closed session still decrypts")
	}
	if _, err := mdocSession.Encrypt([]byte("after close")); err == nil {
		t.Error("a closed session still encrypts")
	}
	if mdocSession.keys.SKReader != nil || mdocSession.keys.SKDevice != nil {
		t.Error("session keys retained after Close")
	}
}

// TestSessionKeyDerivationRejects covers the inputs the ECKA-DH step has to refuse
// rather than proceed on.
func TestSessionKeyDerivationRejects(t *testing.T) {
	key, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	transcript, err := NewQRSessionTranscript(testTag24("de"), testTag24("erk"))
	if err != nil {
		t.Fatalf("NewQRSessionTranscript: %v", err)
	}

	if _, err := NewMdocSession(nil, &key.PublicKey, transcript); err == nil {
		t.Error("expected an error for a nil ephemeral private key")
	}
	if _, err := NewMdocSession(key, nil, transcript); err == nil {
		t.Error("expected an error for a nil peer public key")
	}
}

// TestSessionEstablishmentRoundTrip covers the message of 9.1.1.4 the reader opens
// with, including recovering EReaderKey for the mdoc's half of the agreement.
func TestSessionEstablishmentRoundTrip(t *testing.T) {
	eReaderKey, err := GenerateEDeviceKey()
	if err != nil {
		t.Fatalf("GenerateEDeviceKey: %v", err)
	}
	eReaderKeyBytes, err := EncodeEDeviceKeyBytes(&eReaderKey.PublicKey)
	if err != nil {
		t.Fatalf("EncodeEDeviceKeyBytes: %v", err)
	}

	establishment, err := NewSessionEstablishment(eReaderKeyBytes, []byte("sealed request"))
	if err != nil {
		t.Fatalf("NewSessionEstablishment: %v", err)
	}
	encoded, err := establishment.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	decoded, err := DecodeSessionEstablishment(encoded)
	if err != nil {
		t.Fatalf("DecodeSessionEstablishment: %v", err)
	}
	if !bytes.Equal(decoded.Data, []byte("sealed request")) {
		t.Errorf("data = %q, want %q", decoded.Data, "sealed request")
	}
	recovered, err := decoded.EReaderKey()
	if err != nil {
		t.Fatalf("EReaderKey: %v", err)
	}
	if !recovered.Equal(&eReaderKey.PublicKey) {
		t.Error("EReaderKey did not survive the round trip")
	}

	// The map keys are text strings, exactly as the CDDL spells them.
	var generic map[string]any
	if err := cbor.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("decode generically: %v", err)
	}
	if _, ok := generic["eReaderKey"]; !ok {
		t.Error(`SessionEstablishment has no "eReaderKey" key`)
	}
	if _, ok := generic["data"]; !ok {
		t.Error(`SessionEstablishment has no "data" key`)
	}
}

// TestSessionEstablishmentRejects covers what 9.1.1.4 makes mandatory in the
// opening message.
func TestSessionEstablishmentRejects(t *testing.T) {
	valid := testTag24("erk")

	if _, err := NewSessionEstablishment(valid, nil); err == nil {
		t.Error("expected an error for a SessionEstablishment with no data")
	}
	if _, err := NewSessionEstablishment(cbor.RawMessage(mustHex(t, "63646566")), []byte{1}); err == nil {
		t.Error("expected an error for an EReaderKeyBytes that is not a tag-24 item")
	}
	if _, err := DecodeSessionEstablishment(mustHex(t, "a0")); err == nil {
		t.Error("expected an error for an empty SessionEstablishment map")
	}
}

// TestSessionDataRoundTrip covers both shapes of the message: carrying data, and
// carrying a status.
func TestSessionDataRoundTrip(t *testing.T) {
	t.Run("data", func(t *testing.T) {
		message, err := NewSessionData([]byte("sealed response"))
		if err != nil {
			t.Fatalf("NewSessionData: %v", err)
		}
		encoded, err := message.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		decoded, err := DecodeSessionData(encoded)
		if err != nil {
			t.Fatalf("DecodeSessionData: %v", err)
		}
		if !bytes.Equal(decoded.Data, []byte("sealed response")) {
			t.Errorf("data = %q", decoded.Data)
		}
		if decoded.Status != nil {
			t.Errorf("status present (%d) on a data-only message", *decoded.Status)
		}
	})

	t.Run("termination", func(t *testing.T) {
		encoded, err := NewSessionStatus(StatusSessionTermination).Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		decoded, err := DecodeSessionData(encoded)
		if err != nil {
			t.Fatalf("DecodeSessionData: %v", err)
		}
		if decoded.Status == nil || *decoded.Status != StatusSessionTermination {
			t.Fatalf("status = %v, want %d", decoded.Status, StatusSessionTermination)
		}
		if len(decoded.Data) != 0 {
			t.Errorf("data present on a status-only message: %x", decoded.Data)
		}
	})
}

// TestSessionDataMatchesISOTerminationExample pins the encoding against the
// termination message D.5.1 prints: {"status": 20}.
func TestSessionDataMatchesISOTerminationExample(t *testing.T) {
	encoded, err := NewSessionStatus(StatusSessionTermination).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// a1 = map(1); 66 736 7461747573 = text(6) "status"; 14 = unsigned 20.
	want := mustHex(t, "a16673746174757314")
	if !bytes.Equal(encoded, want) {
		t.Fatalf("termination message\n got: %x\nwant: %x", encoded, want)
	}
}

// TestSessionDataForbidsDataWithErrorStatus pins "If status code 10 or 11 is
// returned, the data element shall not be present in that session data message."
func TestSessionDataForbidsDataWithErrorStatus(t *testing.T) {
	for _, status := range []uint{StatusErrorSessionEncryption, StatusErrorCBORDecoding} {
		message := SessionData{Data: []byte("should not be here"), Status: &status}
		if _, err := message.Encode(); err == nil {
			t.Errorf("status %d: expected an error when data accompanies it", status)
		}
		// And a peer that sends one is refused on the way in too.
		encoded, err := cbor.Marshal(struct {
			Data   []byte `cbor:"data"`
			Status uint   `cbor:"status"`
		}{Data: []byte("x"), Status: status})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := DecodeSessionData(encoded); err == nil {
			t.Errorf("status %d: expected a decode error when data accompanies it", status)
		}
	}
}
