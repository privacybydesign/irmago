package mdoc

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// SESSION TRANSCRIPT — ISO/IEC 18013-5 9.1.5.1
// ============================================================
//
// The clause, verbatim:
//
//	SessionTranscriptBytes = #6.24(bstr .cbor SessionTranscript)
//
//	SessionTranscript = [
//	       DeviceEngagementBytes,
//	       EReaderKeyBytes,
//	       Handover
//	]
//
//	DeviceEngagementBytes = #6.24(bstr .cbor DeviceEngagement)
//
//	Handover = QRHandover / NFCHandover
//
//	QRHandover = null
//
//	NFCHandover = [
//	    bstr        ; Binary value of the Handover Select Message
//	    bstr / null ; Binary value of the Handover Request Message,
//	                ; shall be null if NFC Static Handover was used
//	]
//
// and: "If device engagement using QR code (see 8.2.2.3) was used, the contents
// shall be QRHandover. If device engagement using NFC (see 8.2.2.1) was used,
// the contents shall be NFCHandover."

// SessionTranscriptBytes returns the `#6.24(bstr .cbor SessionTranscript)` of
// 9.1.5.1 — the tag-24 wrapping of the encoded transcript.
//
// This is the form every cryptographic use of the transcript takes except its
// appearance inside DeviceAuthentication, which embeds the bare SessionTranscript
// (9.1.3.4). Note the wrapping is not itself the HKDF salt; see
// KeyDerivationSalt.
func (t SessionTranscript) SessionTranscriptBytes() ([]byte, error) {
	encoded, err := tag24Wrap(t)
	if err != nil {
		return nil, fmt.Errorf("encode SessionTranscriptBytes: %w", err)
	}
	return encoded, nil
}

// KeyDerivationSalt returns SHA-256(SessionTranscriptBytes), which is the HKDF
// salt 9.1.1.4 specifies for both session keys:
//
//	SKReader/SKDevice: Hash SHA-256, IKM ZAB, salt SHA-256(SessionTranscriptBytes),
//	info "SKReader"/"SKDevice" as UTF-8, L 32 octets.
//
// Exists as its own function because the salt is the *digest of* the transcript
// bytes rather than the bytes themselves, and passing SessionTranscriptBytes
// straight into HKDF is an easy mistake that fails only at the far end of a
// session, as an undiagnosable decryption error.
func (t SessionTranscript) KeyDerivationSalt() ([]byte, error) {
	encoded, err := t.SessionTranscriptBytes()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return digest[:], nil
}

// NewQRSessionTranscript builds the transcript for an engagement carried by QR
// code (8.2.2.3), where 9.1.5.1 fixes the handover to `QRHandover = null`.
//
// There is no data in a QR handover because there is nothing to bind: the QR
// carries the DeviceEngagement itself, which the first slot already covers. NFC
// needs a handover precisely because its engagement is negotiated over messages
// that would otherwise go unauthenticated.
//
// deviceEngagementBytes and eReaderKeyBytes are the complete tag-24 encodings of
// 9.1.5.1 and 9.1.1.4 respectively, not their contents — see validateTag24Slot.
func NewQRSessionTranscript(deviceEngagementBytes, eReaderKeyBytes cbor.RawMessage) (SessionTranscript, error) {
	if err := validateTag24Slot("DeviceEngagementBytes", deviceEngagementBytes); err != nil {
		return SessionTranscript{}, err
	}
	if err := validateTag24Slot("EReaderKeyBytes", eReaderKeyBytes); err != nil {
		return SessionTranscript{}, err
	}
	return SessionTranscript{
		DeviceEngagementBytes: deviceEngagementBytes,
		EReaderKeyBytes:       eReaderKeyBytes,
		Handover:              nil, // QRHandover = null
	}, nil
}

// NewNFCSessionTranscript builds the transcript for an engagement carried by NFC
// (8.2.2.1), whose handover is the two-element array of 9.1.5.1.
//
// handoverSelect is "the binary value of the Handover Select Message as retrieved
// by the mdoc reader from the mdoc" and is mandatory — the CDDL gives it no null
// alternative.
//
// handoverRequest is the binary value of the Handover Request Message and "shall
// be null if NFC Static Handover was used". Pass nil or an empty slice for static
// handover; the slot then encodes as CBOR null rather than as an empty byte
// string, which is a different transcript and so a different set of session keys.
//
// Both are raw NDEF message bytes, not CBOR: the CDDL says `bstr`, so unlike the
// two leading slots they are byte strings on the wire and take no tag-24 wrapping.
func NewNFCSessionTranscript(deviceEngagementBytes, eReaderKeyBytes cbor.RawMessage, handoverSelect, handoverRequest []byte) (SessionTranscript, error) {
	if err := validateTag24Slot("DeviceEngagementBytes", deviceEngagementBytes); err != nil {
		return SessionTranscript{}, err
	}
	if err := validateTag24Slot("EReaderKeyBytes", eReaderKeyBytes); err != nil {
		return SessionTranscript{}, err
	}
	if len(handoverSelect) == 0 {
		return SessionTranscript{}, fmt.Errorf(
			"NFCHandover requires a Handover Select Message: 9.1.5.1 defines the first element as bstr with no null alternative")
	}

	return SessionTranscript{
		DeviceEngagementBytes: deviceEngagementBytes,
		EReaderKeyBytes:       eReaderKeyBytes,
		Handover:              []any{handoverSelect, handoverRequestElement(handoverRequest)},
	}, nil
}

// handoverRequestElement renders the second NFCHandover element: the message
// bytes for negotiated handover, CBOR null for static handover. Spelled out
// rather than relying on a nil []byte encoding as null, so the encoded shape does
// not depend on the encoder's NilContainers setting — the same reasoning as
// encryptionKeyElement in eudi/openid4vp/mdoc_dcql.
func handoverRequestElement(handoverRequest []byte) any {
	if len(handoverRequest) == 0 {
		return nil
	}
	return handoverRequest
}

// validateTag24Slot refuses a leading transcript slot that is absent or is not a
// tag-24 item.
//
// 9.1.5.1 types both as `#6.24(bstr .cbor ...)`, so a well-formed value always
// begins with the two-byte tag-24 head 0xd8 0x18. Checking it here catches the
// one error this structure invites: handing over the *contents* of the tag-24
// wrapper — an encoded DeviceEngagement or EReaderKey — instead of the wrapping
// itself. That mistake encodes cleanly, transmits cleanly, and surfaces only as a
// signature or decryption failure at the other party, with nothing in the
// transcript to point at.
//
// Only the tag head is checked, not the inner CBOR: this package validates what
// the clause constrains at this level, and the payloads are the business of
// 8.2.1.1 and 9.1.1.4.
func validateTag24Slot(name string, raw cbor.RawMessage) error {
	if len(raw) == 0 {
		return fmt.Errorf("%s is empty: 9.1.5.1 requires #6.24(bstr .cbor ...) in this slot", name)
	}
	if len(raw) < 2 || raw[0] != 0xd8 || raw[1] != 0x18 {
		return fmt.Errorf(
			"%s is not a tag-24 item (starts %#x, want 0xd8 0x18): 9.1.5.1 requires #6.24(bstr .cbor ...), which is the tag-24 wrapping and not its contents",
			name, raw[:min(2, len(raw))])
	}
	return nil
}
