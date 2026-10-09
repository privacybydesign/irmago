package mdoc

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The vectors below are published in ISO/IEC 18013-5:2021 Annex D.5.1 ("Session
// establishment") and the intermediate cryptographic data that follows it. They
// describe an NFC negotiated-handover session: both leading transcript slots are
// populated and the handover carries a Handover Select *and* a Handover Request
// message.
//
// Testing against ISO's own bytes rather than against a value this package
// produced is the only way to know the transcript is right. Every party in a
// proximity session derives its keys from this structure independently, so a
// construction that is merely self-consistent interoperates with nothing, and
// fails as a decryption error with nothing pointing back here.
const (
	// isoAnnexDSessionTranscriptBytes is #6.24(bstr .cbor SessionTranscript).
	isoAnnexDSessionTranscriptBytes = "" +
		"d81859024183d8185858a20063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a" +
		"968ff289d93e5fa444b624343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32" +
		"fc67d818584ba40102200121582060e3392385041f51403051f2415531cb56dd3f999c71687013aac6768bc8187e2258" +
		"20e58deb8fdbe907f7dd5368245551a34796f7d2215c440c339bb0f7b67beccdfa8258c391020f487315d10209616301" +
		"013001046d646f631a200c016170706c69636174696f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28" +
		"128b37282801021c015c1e580469736f2e6f72673a31383031333a646576696365656e676167656d656e746d646f63a2" +
		"0063312e30018201d818584ba4010220012158205a88d182bce5f42efa59943f33359d2e8a968ff289d93e5fa444b624" +
		"343167fe225820b16e8cf858ddc7690407ba61d4c338237a8cfcf3de6aa672fc60a557aa32fc6758cd91022548721591" +
		"020263720102110204616301013000110206616301036e6663005102046163010157001a201e016170706c6963617469" +
		"6f6e2f766e642e626c7565746f6f74682e6c652e6f6f6230081b28078080bf2801021c021107c832fff6d26fa0beb34d" +
		"fcd555d4823a1c11010369736f2e6f72673a31383031333a6e66636e6663015a172b016170706c69636174696f6e2f76" +
		"6e642e7766612e6e616e57030101032302001324fec9a70b97ac9684a4e326176ef5b981c5e8533e5f00298cfccbc35e" +
		"700a6b020414"

	// isoAnnexDZab is the ZAB (BSI TR-03111) shared secret. It is the same for
	// both session keys, which come from the same ECKA-DH agreement.
	isoAnnexDZab = "6423502f843d8cda01fbd9fa46cb397534a740ab1ec3d1076fbcb12e1dca2589"

	// isoAnnexDSKReader and isoAnnexDSKDevice are the derived session keys.
	isoAnnexDSKReader = "58d277d8719e62a1561d248f403f477e9e6c37bf5d5fc5126f8f4c727c22dfc9"
	isoAnnexDSKDevice = "81d170e07fbdac93c1a676242c2576124a380d87bb73ed9ce4834de2272cf409"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex vector: %v", err)
	}
	return b
}

// nfcHandoverElements pulls the two NFCHandover members out of a decoded
// Handover, failing the test if it is not the [bstr, bstr / null] of 9.1.5.1.
func nfcHandoverElements(t *testing.T, handover any) (handoverSelect, handoverRequest []byte) {
	t.Helper()
	elements, ok := handover.([]any)
	if !ok || len(elements) != 2 {
		t.Fatalf("handover is not a two-element NFCHandover array: %#v", handover)
	}
	handoverSelect, ok = elements[0].([]byte)
	if !ok {
		t.Fatalf("Handover Select Message is not a byte string: %#v", elements[0])
	}
	if elements[1] != nil {
		handoverRequest, ok = elements[1].([]byte)
		if !ok {
			t.Fatalf("Handover Request Message is neither a byte string nor null: %#v", elements[1])
		}
	}
	return handoverSelect, handoverRequest
}

// TestSessionTranscriptBytes_MatchesISOAnnexDVector decodes ISO's own
// SessionTranscriptBytes, rebuilds the transcript from its parts through the
// exported constructor, and requires the re-encoding to be byte-identical.
//
// This puts the whole of 9.1.5.1 under test at once: the tag-24 wrapping, the
// three-slot array, the two leading slots going on the wire inline as tag-24
// items, and the NFCHandover pair.
func TestSessionTranscriptBytes_MatchesISOAnnexDVector(t *testing.T) {
	golden := mustHex(t, isoAnnexDSessionTranscriptBytes)

	decoded, err := tag24Unwrap[SessionTranscript](golden)
	if err != nil {
		t.Fatalf("decode ISO SessionTranscriptBytes: %v", err)
	}
	handoverSelect, handoverRequest := nfcHandoverElements(t, decoded.Handover)
	if len(handoverRequest) == 0 {
		t.Fatal("ISO Annex D.5.1 is a negotiated handover: expected a Handover Request Message")
	}

	rebuilt, err := NewNFCSessionTranscript(
		decoded.DeviceEngagementBytes, decoded.EReaderKeyBytes, handoverSelect, handoverRequest)
	if err != nil {
		t.Fatalf("NewNFCSessionTranscript: %v", err)
	}

	got, err := rebuilt.SessionTranscriptBytes()
	if err != nil {
		t.Fatalf("SessionTranscriptBytes: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("SessionTranscriptBytes does not match ISO Annex D.5.1\n got: %x\nwant: %x", got, golden)
	}
}

// TestKeyDerivationSalt_DerivesISOSessionKeys runs the 9.1.1.4 HKDF over ISO's
// published ZAB using our salt, and requires both of ISO's published session keys
// to come out.
//
// It is a test of the transcript, not of a key schedule this package does not yet
// have: the salt is SHA-256(SessionTranscriptBytes), so one wrong byte anywhere in
// 9.1.5.1 changes both keys completely. Nothing else available verifies the
// transcript this strongly.
func TestKeyDerivationSalt_DerivesISOSessionKeys(t *testing.T) {
	transcript, err := tag24Unwrap[SessionTranscript](mustHex(t, isoAnnexDSessionTranscriptBytes))
	if err != nil {
		t.Fatalf("decode ISO SessionTranscriptBytes: %v", err)
	}
	salt, err := transcript.KeyDerivationSalt()
	if err != nil {
		t.Fatalf("KeyDerivationSalt: %v", err)
	}

	for _, tc := range []struct {
		info string
		want string
	}{
		{info: "SKReader", want: isoAnnexDSKReader},
		{info: "SKDevice", want: isoAnnexDSKDevice},
	} {
		t.Run(tc.info, func(t *testing.T) {
			key, err := hkdf.Key(sha256.New, mustHex(t, isoAnnexDZab), salt, tc.info, 32)
			if err != nil {
				t.Fatalf("hkdf: %v", err)
			}
			if !bytes.Equal(key, mustHex(t, tc.want)) {
				t.Fatalf("%s does not match ISO Annex D\n got: %x\nwant: %s", tc.info, key, tc.want)
			}
		})
	}
}

// transcriptSlots encodes a transcript and decodes it back as three raw CBOR
// items, so a test can inspect what each slot actually became on the wire rather
// than what the Go field says it holds.
func transcriptSlots(t *testing.T, transcript SessionTranscript) []cbor.RawMessage {
	t.Helper()
	encoded, err := transcript.SessionTranscriptBytes()
	if err != nil {
		t.Fatalf("SessionTranscriptBytes: %v", err)
	}
	slots, err := tag24Unwrap[[]cbor.RawMessage](encoded)
	if err != nil {
		t.Fatalf("decode transcript slots: %v", err)
	}
	if len(slots) != 3 {
		t.Fatalf("SessionTranscript has %d elements, want the 3 of 9.1.5.1", len(slots))
	}
	return slots
}

// TestLeadingSlotsEncodeInlineAsTag24 is the regression test for the field type of
// DeviceEngagementBytes and EReaderKeyBytes.
//
// As []byte they encoded the tag-24 item as the *contents of a further byte
// string*, which is a different transcript and so a different set of session keys,
// while still round-tripping perfectly within this package. cbor.RawMessage
// splices them in as the tag-24 items 9.1.5.1 asks for. The wire is the only place
// that difference is visible, so the test looks there.
func TestLeadingSlotsEncodeInlineAsTag24(t *testing.T) {
	engagement := testTag24("device-engagement")
	readerKey := testTag24("e-reader-key")

	transcript, err := NewQRSessionTranscript(engagement, readerKey)
	if err != nil {
		t.Fatalf("NewQRSessionTranscript: %v", err)
	}
	slots := transcriptSlots(t, transcript)

	for i, slot := range []struct {
		name string
		want cbor.RawMessage
	}{
		{"DeviceEngagementBytes", engagement},
		{"EReaderKeyBytes", readerKey},
	} {
		if !bytes.Equal(slots[i], slot.want) {
			t.Errorf("%s did not go on the wire inline\n got: %x\nwant: %x", slot.name, slots[i], slot.want)
		}
		if len(slots[i]) < 2 || slots[i][0] != 0xd8 || slots[i][1] != 0x18 {
			t.Errorf("%s is not a tag-24 item on the wire: %x", slot.name, slots[i])
		}
	}
}

// TestQRHandoverIsNull pins `QRHandover = null` from 9.1.5.1.
func TestQRHandoverIsNull(t *testing.T) {
	transcript, err := NewQRSessionTranscript(testTag24("de"), testTag24("erk"))
	if err != nil {
		t.Fatalf("NewQRSessionTranscript: %v", err)
	}
	if got := transcriptSlots(t, transcript)[2]; !bytes.Equal(got, []byte{0xf6}) {
		t.Fatalf("QRHandover encoded as %x, want CBOR null (f6)", got)
	}
}

// TestNFCHandoverStaticIsNull pins "shall be null if NFC Static Handover was used"
// from 9.1.5.1, for both spellings of absent.
func TestNFCHandoverStaticIsNull(t *testing.T) {
	for name, handoverRequest := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			transcript, err := NewNFCSessionTranscript(
				testTag24("de"), testTag24("erk"), []byte{0x91, 0x02}, handoverRequest)
			if err != nil {
				t.Fatalf("NewNFCSessionTranscript: %v", err)
			}
			// 82 = array(2), 42 9102 = bstr(2), f6 = null.
			want := []byte{0x82, 0x42, 0x91, 0x02, 0xf6}
			if got := transcriptSlots(t, transcript)[2]; !bytes.Equal(got, want) {
				t.Fatalf("static NFCHandover encoded as %x, want %x", got, want)
			}
		})
	}
}

// TestNFCHandoverRequiresHandoverSelect pins the CDDL giving the first NFCHandover
// element no null alternative.
func TestNFCHandoverRequiresHandoverSelect(t *testing.T) {
	if _, err := NewNFCSessionTranscript(
		testTag24("de"), testTag24("erk"), nil, []byte{0x01}); err == nil {
		t.Fatal("expected an error for an NFCHandover with no Handover Select Message")
	}
}

// TestLeadingSlotsRejectNonTag24 covers the mistake validateTag24Slot exists for:
// passing the contents of the tag-24 wrapper instead of the wrapper.
func TestLeadingSlotsRejectNonTag24(t *testing.T) {
	valid := testTag24("de")
	contentsOnly := cbor.RawMessage(mustHex(t, "63646566")) // 63="text(3)", "def" — bare CBOR, no tag-24 head

	for name, tc := range map[string]struct{ engagement, readerKey cbor.RawMessage }{
		"engagement empty":      {nil, valid},
		"reader key empty":      {valid, nil},
		"engagement not tag-24": {contentsOnly, valid},
		"reader key not tag-24": {valid, contentsOnly},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewQRSessionTranscript(tc.engagement, tc.readerKey); err == nil {
				t.Fatal("expected an error, got none")
			}
			if _, err := NewNFCSessionTranscript(tc.engagement, tc.readerKey, []byte{0x01}, nil); err == nil {
				t.Fatal("expected an error, got none")
			}
		})
	}
}

// TestUnsetLeadingSlotsEncodeAsNull guards the OpenID4VP and DC API handovers,
// which are `[null, null, Handover]`: both construct a SessionTranscript leaving
// the leading slots unset, so changing their type must not change what an unset
// slot encodes to.
func TestUnsetLeadingSlotsEncodeAsNull(t *testing.T) {
	slots := transcriptSlots(t, SessionTranscript{
		Handover: []any{"OpenID4VPHandover", make([]byte, 32)},
	})
	for i, name := range []string{"DeviceEngagementBytes", "EReaderKeyBytes"} {
		if !bytes.Equal(slots[i], []byte{0xf6}) {
			t.Errorf("unset %s encoded as %x, want CBOR null (f6)", name, slots[i])
		}
	}
}
