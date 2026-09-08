package mdoc

import (
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// MDOC MAC AUTHENTICATION — ISO/IEC 18013-5 9.1.3.5
// ============================================================
//
// 9.1.3 gives the mdoc two ways to authenticate a DeviceResponse and says an
// "mdoc reader shall support both approaches", so a proximity wallet that only
// signs will meet readers that ask for the other one. This is that other one.
//
// The clause: "the mdoc computes the MAC of the device authentication data with
// an ephemeral MAC key (EMacKey) derived from the mdoc authentication private key
// and the mdoc reader ephemeral public key."
//
//	ECKA-DH inputs: SDeviceKey.Priv + EReaderKey.Pub for the mdoc,
//	                EReaderKey.Priv + SDeviceKey.Pub for the reader.
//	EMacKey = HKDF(SHA-256, IKM = ZAB, salt = SHA-256(SessionTranscriptBytes),
//	               info = "EMacKey", L = 32)
//
// # Why this reaches back into issuance
//
// The agreement uses **SDeviceKey**, the *static* mdoc authentication key held in
// the MSO — not the session's ephemeral EDeviceKey. A device key created for
// signing only cannot perform ECDH, so a hardware-backed key must be generated
// with a key-agreement purpose *at issuance*. That is a change to the key creation
// path, not something the presentation code can arrange. See KeyAgreer, whose
// absence is reported with that explanation rather than as a generic failure.
//
// 9.1.3.4 adds a rule this package cannot enforce from here: "A single mdoc
// authentication key shall not be used to produce both MACs and signatures during
// its lifetime." Whichever branch a credential's key is first used for is the one
// it is committed to.

// coseAlgorithmHMAC256 is "HMAC 256/256" from RFC 8152, which 9.1.3.5 requires:
// HMAC with SHA-256 and a full 256-bit tag, no truncation.
const coseAlgorithmHMAC256 = 5

// EMacKeyLength is the 32 octets 9.1.3.5 derives.
const EMacKeyLength = 32

// KeyAgreer is the capability deviceMac needs from a device key beyond signing:
// ECKA-DH against the reader's ephemeral public key.
//
// It is deliberately separate from Holder rather than a method on it. Every
// existing Holder — including hardware-backed ones built through
// NewHolderFromSigner — keeps working untouched, and a holder that cannot agree
// keys simply does not satisfy this interface, which is exactly the situation a
// signing-only keystore key is in.
type KeyAgreer interface {
	// AgreeSharedSecret returns the ZAB of BSI TR-03111 ECKA-DH between this
	// device's static private key and peer: the x-coordinate of the shared point.
	AgreeSharedSecret(peer *ecdsa.PublicKey) ([]byte, error)
}

// AgreeSharedSecret implements KeyAgreer for the software holder.
//
// It works only when the underlying signer is an in-process *ecdsa.PrivateKey.
// A crypto.Signer is, by definition, a signing capability: a platform key handle
// satisfies it without being able to agree keys at all, and there is no way to ask
// it. Such a holder gets a named error here rather than a wrong answer.
func (h *DefaultHolder) AgreeSharedSecret(peer *ecdsa.PublicKey) ([]byte, error) {
	private, ok := h.signer.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf(
			"this device key signs but cannot perform key agreement, so deviceMac (9.1.3.5) is unavailable: "+
				"the key must be created with a key-agreement purpose at issuance, which is a change to the key creation path (signer is %T)",
			h.signer)
	}
	return ecdhSharedSecret(private, peer)
}

// ecdhSharedSecret performs the ECKA-DH of 9.1.3.5 and returns ZAB.
//
// As in 9.1.1.5, ZAB is the x-coordinate of the shared point, which is what
// crypto/ecdh returns for the NIST curves.
func ecdhSharedSecret(private *ecdsa.PrivateKey, peer *ecdsa.PublicKey) ([]byte, error) {
	if private == nil || private.Curve == nil {
		return nil, fmt.Errorf("no private key for ECKA-DH")
	}
	if peer == nil || peer.Curve == nil {
		return nil, fmt.Errorf("no peer public key for ECKA-DH")
	}
	ecdhPrivate, err := private.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert private key for ECKA-DH: %w", err)
	}
	ecdhPeer, err := peer.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert peer public key for ECKA-DH: %w", err)
	}
	zab, err := ecdhPrivate.ECDH(ecdhPeer)
	if err != nil {
		return nil, fmt.Errorf("ECKA-DH: %w", err)
	}
	return zab, nil
}

// emacKeyFromZAB runs the HKDF of 9.1.3.5.
//
// The salt is the same SHA-256(SessionTranscriptBytes) the session keys use
// (9.1.1.4); only the info string differs. Split out so it can be exercised
// against a known ZAB, as sessionKeysFromZAB is.
func emacKeyFromZAB(zab []byte, transcript SessionTranscript) ([]byte, error) {
	salt, err := transcript.KeyDerivationSalt()
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, zab, salt, "EMacKey", EMacKeyLength)
	if err != nil {
		return nil, fmt.Errorf("derive EMacKey: %w", err)
	}
	return key, nil
}

// DeriveEMacKeyAsMdoc derives EMacKey from the mdoc's side: SDeviceKey.Priv,
// reached through the holder's key agreement, and EReaderKey.Pub.
func DeriveEMacKeyAsMdoc(agreer KeyAgreer, eReaderKeyPub *ecdsa.PublicKey, transcript SessionTranscript) ([]byte, error) {
	if agreer == nil {
		return nil, fmt.Errorf("no key agreement available for deviceMac (9.1.3.5)")
	}
	zab, err := agreer.AgreeSharedSecret(eReaderKeyPub)
	if err != nil {
		return nil, err
	}
	return emacKeyFromZAB(zab, transcript)
}

// DeriveEMacKeyAsReader derives the same EMacKey from the reader's side:
// EReaderKey.Priv and SDeviceKey.Pub, the latter being the deviceKey the MSO
// carries.
func DeriveEMacKeyAsReader(eReaderKey *ecdsa.PrivateKey, sDeviceKeyPub *ecdsa.PublicKey, transcript SessionTranscript) ([]byte, error) {
	zab, err := ecdhSharedSecret(eReaderKey, sDeviceKeyPub)
	if err != nil {
		return nil, err
	}
	return emacKeyFromZAB(zab, transcript)
}

// coseMac0 is the untagged COSE_Mac0 of RFC 8152 that 9.1.3.5 names DeviceMac.
//
// Built here rather than with go-cose, which implements COSE_Sign1 and COSE_Sign
// but no MAC structures at all (v1.2.0).
//
// Payload is nil, and therefore CBOR null: "Within the COSE_Mac0 structure, the
// payload shall have a null value. The detached content is
// DeviceAuthenticationBytes."
type coseMac0 struct {
	_           struct{} `cbor:",toarray"`
	Protected   []byte
	Unprotected map[int]any
	Payload     []byte
	Tag         []byte
}

// macStructure is RFC 8152's MAC_structure, the bytes the HMAC is actually taken
// over:
//
//	MAC_structure = ["MAC0", protected, external_aad, payload]
//
// ExternalAAD is a zero-length byte string, not null — 9.1.3.5: "The
// `external_aad' field shall be a bytestring of size zero." Payload here is the
// detached content, i.e. DeviceAuthenticationBytes.
type macStructure struct {
	_           struct{} `cbor:",toarray"`
	Context     string
	Protected   []byte
	ExternalAAD []byte
	Payload     []byte
}

// macProtectedHeader is the protected header of 9.1.3.5, CBOR-encoded ready to be
// embedded as a byte string: "The alg element shall be included as an element in
// the protected header. Other elements should not be present."
func macProtectedHeader() ([]byte, error) {
	encoded, err := cbor.Marshal(map[int]any{1: coseAlgorithmHMAC256})
	if err != nil {
		return nil, fmt.Errorf("encode MAC protected header: %w", err)
	}
	return encoded, nil
}

// macTag computes the HMAC over the MAC_structure.
func macTag(emacKey, protected, detachedPayload []byte) ([]byte, error) {
	if len(emacKey) != EMacKeyLength {
		return nil, fmt.Errorf("EMacKey is %d bytes, want %d", len(emacKey), EMacKeyLength)
	}
	structure, err := cbor.Marshal(macStructure{
		Context:     "MAC0",
		Protected:   protected,
		ExternalAAD: []byte{}, // zero-length, not null
		Payload:     detachedPayload,
	})
	if err != nil {
		return nil, fmt.Errorf("encode MAC_structure: %w", err)
	}
	mac := hmac.New(sha256.New, emacKey)
	mac.Write(structure)
	return mac.Sum(nil), nil
}

// MacDeviceAuth produces the deviceMac of 9.1.3.5 for this session: the
// DeviceAuthentication of 9.1.3.4, tag-24 wrapped as the detached content of an
// untagged COSE_Mac0.
//
// It is the MAC counterpart of Holder.SignDeviceAuth and builds the same
// DeviceAuthentication, so a reader gets the same bytes authenticated either way —
// only the mechanism differs.
func MacDeviceAuth(agreer KeyAgreer, docType string, transcript SessionTranscript, eReaderKeyPub *ecdsa.PublicKey) ([]byte, error) {
	emacKey, err := DeriveEMacKeyAsMdoc(agreer, eReaderKeyPub, transcript)
	if err != nil {
		return nil, err
	}
	return macDeviceAuthWithKey(emacKey, docType, transcript)
}

// macDeviceAuthWithKey is MacDeviceAuth once the key exists, so a caller holding
// an EMacKey derived elsewhere — a test, or a reader checking its own work — does
// not have to re-agree it.
func macDeviceAuthWithKey(emacKey []byte, docType string, transcript SessionTranscript) ([]byte, error) {
	payload, err := deviceAuthenticationBytes(docType, transcript)
	if err != nil {
		return nil, err
	}
	protected, err := macProtectedHeader()
	if err != nil {
		return nil, err
	}
	tag, err := macTag(emacKey, protected, payload)
	if err != nil {
		return nil, err
	}
	encoded, err := cbor.Marshal(coseMac0{
		Protected:   protected,
		Unprotected: map[int]any{},
		Payload:     nil, // detached
		Tag:         tag,
	})
	if err != nil {
		return nil, fmt.Errorf("encode deviceMac: %w", err)
	}
	return encoded, nil
}

// deviceAuthenticationBytes builds the DeviceAuthenticationBytes of 9.1.3.4 —
// `#6.24(bstr .cbor DeviceAuthentication)` — which is the detached content both
// deviceAuth branches authenticate.
//
// The empty deviceNameSpaces mirrors SignDeviceAuth: this profile has no
// holder-asserted claims, and both branches must cover identical bytes or a
// verifier checking one against the other's structure would fail.
func deviceAuthenticationBytes(docType string, transcript SessionTranscript) ([]byte, error) {
	emptyNS, err := tag24Wrap(map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("encode empty nameSpaces: %w", err)
	}
	payload, err := tag24Wrap(DeviceAuthentication{
		Context:           "DeviceAuthentication",
		SessionTranscript: transcript,
		DocType:           docType,
		DeviceNameSpaces:  emptyNS,
	})
	if err != nil {
		return nil, fmt.Errorf("wrap deviceAuthentication: %w", err)
	}
	return payload, nil
}

// VerifyDeviceMac checks a deviceMac against an EMacKey the verifier derived
// itself, per 9.1.3.5.
//
// The comparison is constant-time. Unlike the Ident check of 8.3.3.1.1.3, this one
// is over a secret-keyed tag, and a verifier that leaked timing here would leak
// information about a value an attacker is trying to forge.
func VerifyDeviceMac(deviceMac, emacKey []byte, docType string, transcript SessionTranscript) error {
	var message coseMac0
	if err := mdocDecMode.Unmarshal(deviceMac, &message); err != nil {
		return fmt.Errorf("decode deviceMac as COSE_Mac0: %w", err)
	}
	if len(message.Payload) != 0 {
		return fmt.Errorf(
			"deviceMac carries a payload: 9.1.3.5 requires a null payload with DeviceAuthenticationBytes as detached content")
	}
	if err := checkMacProtectedHeader(message.Protected); err != nil {
		return err
	}

	payload, err := deviceAuthenticationBytes(docType, transcript)
	if err != nil {
		return err
	}
	expected, err := macTag(emacKey, message.Protected, payload)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, message.Tag) {
		return fmt.Errorf("deviceMac does not authenticate this session's DeviceAuthentication")
	}
	return nil
}

// checkMacProtectedHeader enforces the algorithm 9.1.3.5 fixes.
//
// The header is read from the message rather than assumed, because it is covered
// by the MAC: accepting whatever algorithm it names and then verifying with
// HMAC-SHA-256 anyway would make the field meaningless, while ignoring it
// entirely would let a peer claim one algorithm and be checked with another.
func checkMacProtectedHeader(protected []byte) error {
	var header map[int]any
	if err := mdocDecMode.Unmarshal(protected, &header); err != nil {
		return fmt.Errorf("decode deviceMac protected header: %w", err)
	}
	algorithm, present := header[1]
	if !present {
		return fmt.Errorf("deviceMac protected header has no alg: 9.1.3.5 requires one")
	}
	value, ok := algorithm.(uint64)
	if !ok || value != coseAlgorithmHMAC256 {
		return fmt.Errorf(
			"deviceMac names algorithm %v, want %d (HMAC 256/256): 9.1.3.5 permits no other",
			algorithm, coseAlgorithmHMAC256)
	}
	return nil
}

// AttachDeviceMac returns a copy of mdoc with DeviceSigned populated from a
// deviceMac, the MAC counterpart of AttachDeviceSigned.
func AttachDeviceMac(mdoc *MDoc, deviceMacBytes []byte) (*MDoc, error) {
	emptyNS, err := tag24Wrap(map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("wrap empty deviceNameSpaces: %w", err)
	}
	attached := *mdoc
	attached.DeviceSigned = &DeviceSigned{
		NameSpaces: emptyNS,
		DeviceAuth: DeviceAuth{DeviceMac: cbor.RawMessage(deviceMacBytes)},
	}
	return &attached, nil
}
