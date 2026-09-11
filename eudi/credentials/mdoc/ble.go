package mdoc

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

// ============================================================
// BLE DATA RETRIEVAL — ISO/IEC 18013-5 8.3.3.1.1
// ============================================================
//
// This file holds the parts of the BLE transport that are bytes rather than
// radio: the service definitions, the connection-state values, the message
// framing, and the Ident derivation. The GATT plumbing itself — scanning,
// connecting, subscribing, notifying — is necessarily native, and is the only
// part of proximity that cannot live here.
//
// The wallet is the **GATT client** (mdoc central client mode), per 8.3.3.1.1.1:
// "If the mdoc supports the Central role, it shall act as a GATT client." The
// reader advertises and hosts the service; the wallet scans for the UUID the
// engagement named and connects to it. See the CentralClient* characteristics
// below, and BleOptions for why this mode was chosen over peripheral server mode.

// Characteristic UUIDs from 8.3.3.1.1.4.
//
// Table 11 defines the service the mdoc hosts when it is the GATT server
// (peripheral server mode). Table 12 defines the service the *reader* hosts when
// it is the GATT server (central client mode), which is the one this wallet
// connects to — note it carries a fourth characteristic, Ident, that Table 11 has
// no counterpart for.
//
// Both sets are declared because a wallet only ever uses one of them and which one
// is a deployment decision, not a rebuild: the engagement layer already advertises
// either mode.
var (
	// Table 11 — mdoc service, used when the mdoc is the GATT server.
	PeripheralServerStateCharacteristic         = uuid.MustParse("00000001-A123-48CE-896B-4C76973373E6")
	PeripheralServerClient2ServerCharacteristic = uuid.MustParse("00000002-A123-48CE-896B-4C76973373E6")
	PeripheralServerServer2ClientCharacteristic = uuid.MustParse("00000003-A123-48CE-896B-4C76973373E6")

	// Table 12 — mdoc reader service, used when the reader is the GATT server.
	// This is the set mdoc central client mode uses.
	CentralClientStateCharacteristic         = uuid.MustParse("00000005-A123-48CE-896B-4C76973373E6")
	CentralClientClient2ServerCharacteristic = uuid.MustParse("00000006-A123-48CE-896B-4C76973373E6")
	CentralClientServer2ClientCharacteristic = uuid.MustParse("00000007-A123-48CE-896B-4C76973373E6")
	CentralClientIdentCharacteristic         = uuid.MustParse("00000008-A123-48CE-896B-4C76973373E6")
)

// Connection state values from Table 13, carried on the State characteristic as
// one byte, by Write Without Response and Notify.
const (
	// StateStart is written by the **GATT client** once it has subscribed to State
	// and Server2Client, and "tells the GATT server that the GATT client is ready
	// for the transmission to start" (8.3.3.1.1.5).
	StateStart byte = 0x01

	// StateEnd terminates the connection. Either party may send it at any time;
	// the reader "shall use this value to signal the end of data retrieval". It is
	// the BLE alternative to the SessionData termination status of 9.1.1.4 — see
	// StatusSessionTermination.
	StateEnd byte = 0x02
)

// Message framing flags from 8.3.3.1.1.6: "The first byte of each part is either
// 0x01, which indicates more messages are coming, or 0x00, to indicate it is the
// last part of the message."
const (
	chunkMore = 0x01
	chunkLast = 0x00
)

// attMaxAttributeValueLength is the 512-byte ceiling the Bluetooth Core
// Specification places on an attribute value, independent of the negotiated MTU.
// A large MTU does not license a larger characteristic write.
const attMaxAttributeValueLength = 512

// attMinimumMTU is the ATT_MTU every BLE stack supports without negotiation. An
// MTU below it is not a small MTU, it is a bug in the caller.
const attMinimumMTU = 23

// MaxCharacteristicSize is the largest value that fits in one characteristic
// write or notification at the given ATT MTU: MTU minus the 3 bytes of ATT
// overhead (one opcode, two handle), capped at the 512-byte attribute limit.
//
// This is the size of a "part" in 8.3.3.1.1.6's "divide the message in parts with
// a length of 3 bytes less than the MTU size". The leading flag byte is *inside*
// that part, so the message data each part carries is one byte less again — see
// MaxChunkPayload.
func MaxCharacteristicSize(mtu int) (int, error) {
	if mtu < attMinimumMTU {
		return 0, fmt.Errorf("ATT MTU is %d, below the BLE minimum of %d", mtu, attMinimumMTU)
	}
	return min(mtu-3, attMaxAttributeValueLength), nil
}

// MaxChunkPayload is how much of the message one part carries: the characteristic
// size less the leading flag byte.
func MaxChunkPayload(mtu int) (int, error) {
	size, err := MaxCharacteristicSize(mtu)
	if err != nil {
		return 0, err
	}
	return size - 1, nil
}

// ChunkMessage splits a SessionEstablishment or SessionData message into the parts
// of 8.3.3.1.1.6, each prefixed with its continuation flag.
//
// The caller writes each part to Client2Server (as GATT client) or notifies it on
// Server2Client (as GATT server); the framing is identical in both directions and
// in both modes, which is why this takes no role.
//
// An empty message still produces one part — a single last-chunk marker. That is
// not a case the session layer generates, but a framing function that silently
// produced nothing for it would turn a caller's bug into a peer that waits
// forever.
func ChunkMessage(message []byte, mtu int) ([][]byte, error) {
	payloadSize, err := MaxChunkPayload(mtu)
	if err != nil {
		return nil, err
	}

	var parts [][]byte
	for offset := 0; offset < len(message); offset += payloadSize {
		end := min(offset+payloadSize, len(message))
		part := make([]byte, 0, 1+end-offset)
		if end < len(message) {
			part = append(part, chunkMore)
		} else {
			part = append(part, chunkLast)
		}
		parts = append(parts, append(part, message[offset:end]...))
	}
	if len(parts) == 0 {
		parts = append(parts, []byte{chunkLast})
	}
	return parts, nil
}

// MessageAssembler reassembles the parts of 8.3.3.1.1.6 back into one message.
//
// It is not safe for concurrent use, and one instance handles one direction: a
// party that both sends and receives needs an assembler only for what it receives.
//
// Leniency on the way in is deliberate. The clause describes a sender dividing a
// message into full-MTU parts, and some implementations check that every
// non-final part is exactly that size. Requiring it here would reject a peer that
// is merely conservative — a smaller part is unambiguous, since the flag byte, not
// the length, says whether more is coming.
type MessageAssembler struct {
	// MaxMessageSize bounds what a peer can make this buffer. Zero means
	// DefaultMaxMessageSize. A peer that never sets the last-chunk flag would
	// otherwise grow this without limit, before any of Clause 9's protections have
	// had a chance to apply — the message is not decrypted until it is complete.
	MaxMessageSize int

	buffer []byte
}

// DefaultMaxMessageSize bounds an assembled message. A DeviceResponse carrying
// several documents with portraits is comfortably within it, and it is far below
// what an unbounded peer could ask for.
const DefaultMaxMessageSize = 4 << 20 // 4 MiB

// Add takes one received part. It returns the complete message and true once a
// part arrives with the last-chunk flag, and nil, false while more is expected.
//
// The assembler resets after returning a message, so the same instance handles
// every message of a session.
func (a *MessageAssembler) Add(part []byte) ([]byte, bool, error) {
	if len(part) == 0 {
		return nil, false, fmt.Errorf(
			"empty BLE part: 8.3.3.1.1.6 requires a leading 0x00 or 0x01 continuation flag")
	}

	flag, payload := part[0], part[1:]
	if flag != chunkMore && flag != chunkLast {
		return nil, false, fmt.Errorf(
			"BLE part has continuation flag %#x, want 0x00 (last) or 0x01 (more)", flag)
	}

	limit := a.MaxMessageSize
	if limit <= 0 {
		limit = DefaultMaxMessageSize
	}
	if len(a.buffer)+len(payload) > limit {
		a.Reset()
		return nil, false, fmt.Errorf(
			"BLE message exceeds %d bytes before its last part arrived", limit)
	}
	a.buffer = append(a.buffer, payload...)

	if flag == chunkMore {
		return nil, false, nil
	}
	message := a.buffer
	a.buffer = nil
	return message, true, nil
}

// Pending reports whether a message is partly assembled. A connection dropped
// while this is true lost data: 8.3.3.1.1.8 forbids re-establishing a connection
// once transmission has started, so the transaction has to begin again.
func (a *MessageAssembler) Pending() bool {
	return len(a.buffer) > 0
}

// Reset discards a partly assembled message.
func (a *MessageAssembler) Reset() {
	a.buffer = nil
}

// BLEIdentLength is the 16 octets 8.3.3.1.1.3 derives.
const BLEIdentLength = 16

// BLEIdent computes the value of the Ident characteristic (Table 12), which the
// mdoc reads from the reader "to ensure that the mdoc is connected to the correct
// mdoc reader" (8.3.3.1.1.3):
//
//	HKDF, Hash SHA-256, IKM EDeviceKeyBytes, no salt, info "BLEIdent", L 16 octets.
//
// Two details that are easy to get wrong. The IKM is EDeviceKeyBytes — the
// complete tag-24 wrapping of 9.1.1.4, which is exactly what
// DeviceEngagement.Security.EDeviceKeyBytes holds — not the COSE_Key inside it.
// And there is genuinely *no salt*, unlike the session key derivation of 9.1.1.4,
// which salts with SHA-256(SessionTranscriptBytes).
//
// Ident exists only in central client mode: in peripheral server mode the mdoc is
// the GATT server and Table 11 gives it no such characteristic.
//
// Checking it is a "may", and NOTE 3 explains why it is worth little on its own:
// "If the mdoc is connected to the wrong mdoc reader, session establishment will
// fail" regardless, because Clause 9 binds the session to the engagement. Treat a
// mismatch as a reason to disconnect early rather than as the security boundary.
func BLEIdent(eDeviceKeyBytes cbor.RawMessage) ([]byte, error) {
	if err := validateTag24Slot("EDeviceKeyBytes", eDeviceKeyBytes); err != nil {
		return nil, err
	}
	ident, err := hkdf.Key(sha256.New, eDeviceKeyBytes, nil, "BLEIdent", BLEIdentLength)
	if err != nil {
		return nil, fmt.Errorf("derive BLEIdent: %w", err)
	}
	return ident, nil
}

// VerifyBLEIdent checks the Ident value read from the reader against the one the
// engagement's EDeviceKey implies.
//
// 8.3.3.1.1.3: "If the Ident characteristic received from the mdoc reader does not
// match the expected value, the mdoc shall terminate the connection." The
// comparison is of public, engagement-derived values on both sides, so it is not
// a secret comparison and needs no constant-time treatment.
func VerifyBLEIdent(eDeviceKeyBytes cbor.RawMessage, received []byte) error {
	expected, err := BLEIdent(eDeviceKeyBytes)
	if err != nil {
		return err
	}
	if len(received) != len(expected) {
		return fmt.Errorf("received Ident is %d bytes, want %d", len(received), len(expected))
	}
	for i := range expected {
		if expected[i] != received[i] {
			return fmt.Errorf(
				"received Ident does not match this engagement's EDeviceKey: connected to the wrong mdoc reader")
		}
	}
	return nil
}
