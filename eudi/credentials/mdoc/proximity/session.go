package proximity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Role identifies which side of the mdoc session this object speaks for.
// It controls the HKDF info label and the AES-GCM IV identifier byte.
type Role int

const (
	RoleReader Role = iota
	RoleMDOC
)

// StatusSessionTermination — ISO 18013-5 Table 20.
const StatusSessionTermination uint64 = 20

// SessionEncryption implements ISO/IEC 18013-5 §9.1.1 session encryption.
type SessionEncryption struct {
	role                     Role
	ePriv                    *ecdsa.PrivateKey
	remotePub                *ecdsa.PublicKey
	skSelf                   []byte
	skRemote                 []byte
	encryptedCounter         uint32
	decryptedCounter         uint32
	sessionEstablishmentSent bool
}

// NewSessionEncryption constructs a SessionEncryption ready for use.
func NewSessionEncryption(
	role Role,
	ephemeralPrivate *ecdsa.PrivateKey,
	remotePublic *ecdsa.PublicKey,
	sessionTranscript []byte,
) (*SessionEncryption, error) {
	if ephemeralPrivate == nil || remotePublic == nil {
		return nil, errors.New("proximity: both keys required")
	}

	sharedSecret, err := ecdhP256(ephemeralPrivate, remotePublic)
	if err != nil {
		return nil, fmt.Errorf("proximity: ECDH: %w", err)
	}

	// salt = SHA-256( CBOR( #6.24(bstr(sessionTranscript)) ) ) — ISO 18013-5 §9.1.1.
	taggedTranscript, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: sessionTranscript})
	if err != nil {
		return nil, fmt.Errorf("proximity: wrap transcript: %w", err)
	}
	saltArr := sha256.Sum256(taggedTranscript)
	salt := saltArr[:]

	skDevice, err := hkdf.Key(sha256.New, sharedSecret, salt, "SKDevice", 32)
	if err != nil {
		return nil, fmt.Errorf("proximity: HKDF SKDevice: %w", err)
	}
	skReader, err := hkdf.Key(sha256.New, sharedSecret, salt, "SKReader", 32)
	if err != nil {
		return nil, fmt.Errorf("proximity: HKDF SKReader: %w", err)
	}

	s := &SessionEncryption{
		role:             role,
		ePriv:            ephemeralPrivate,
		remotePub:        remotePublic,
		encryptedCounter: 1,
		decryptedCounter: 1,
	}
	if role == RoleMDOC {
		s.skSelf, s.skRemote = skDevice, skReader
	} else {
		s.skSelf, s.skRemote = skReader, skDevice
	}
	return s, nil
}

// EncryptMessage builds either a SessionEstablishment (reader's first
// message) or a SessionData (subsequent messages) message.
func (s *SessionEncryption) EncryptMessage(plaintext []byte, status *uint64) ([]byte, error) {
	var ciphertext []byte
	if plaintext != nil {
		gcm, err := newGCM(s.skSelf)
		if err != nil {
			return nil, err
		}
		iv := buildIV(s.role, s.encryptedCounter, true)
		ciphertext = gcm.Seal(nil, iv, plaintext, nil)
		s.encryptedCounter++
	}

	if !s.sessionEstablishmentSent && s.role == RoleReader {
		if ciphertext == nil {
			return nil, errors.New("proximity: first reader message must include data")
		}
		if status != nil {
			return nil, errors.New("proximity: first reader message cannot carry status")
		}
		s.sessionEstablishmentSent = true
		return encodeSessionEstablishment(&s.ePriv.PublicKey, ciphertext)
	}

	s.sessionEstablishmentSent = true
	return encodeSessionData(ciphertext, status)
}

// DecryptMessage parses a SessionEstablishment or SessionData message and
// decrypts any embedded payload.
func (s *SessionEncryption) DecryptMessage(data []byte) ([]byte, *uint64, error) {
	ct, status, err := parseSessionMessage(data)
	if err != nil {
		return nil, nil, err
	}
	var plaintext []byte
	if ct != nil {
		gcm, err := newGCM(s.skRemote)
		if err != nil {
			return nil, nil, err
		}
		iv := buildIV(s.role, s.decryptedCounter, false)
		plaintext, err = gcm.Open(nil, iv, ct, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("proximity: AES-GCM open: %w", err)
		}
		s.decryptedCounter++
	}
	return plaintext, status, nil
}

// NumMessagesEncrypted returns the number of messages this side has sent.
// Counter starts at 1 internally so we subtract 1 for the public value.
func (s *SessionEncryption) NumMessagesEncrypted() int {
	return int(s.encryptedCounter) - 1
}

// NumMessagesDecrypted returns the number of messages this side has received.
func (s *SessionEncryption) NumMessagesDecrypted() int {
	return int(s.decryptedCounter) - 1
}

// EncodeStatus builds a bare SessionData message carrying only a status code.
func EncodeStatus(status uint64) ([]byte, error) {
	return cbor.Marshal(sessionDataEncode{Status: &status})
}

// GetEReaderKeyFromSessionEstablishment extracts the reader's ephemeral
// public key plus the inner COSE_Key bytes from a SessionEstablishment message.
func GetEReaderKeyFromSessionEstablishment(data []byte) (*ecdsa.PublicKey, []byte, error) {
	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, nil, fmt.Errorf("proximity: decode SessionEstablishment: %w", err)
	}
	raw, ok := m["eReaderKey"]
	if !ok {
		return nil, nil, errors.New("proximity: SessionEstablishment has no eReaderKey")
	}
	var tagged cbor.Tag
	if err := cbor.Unmarshal(raw, &tagged); err != nil {
		return nil, nil, err
	}
	if tagged.Number != tagEncodedCBOR {
		return nil, nil, fmt.Errorf("eReaderKey wrapper tag = %d, want 24", tagged.Number)
	}
	inner, ok := tagged.Content.([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("eReaderKey content is %T, want bstr", tagged.Content)
	}
	pub, err := decodeTag24CoseKey(raw)
	if err != nil {
		return nil, nil, err
	}
	return pub, inner, nil
}

// ---- internal: crypto, IV construction, CBOR message shapes ----------------

func ecdhP256(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	curve := ecdh.P256()
	// crypto/ecdh wants a big-endian fixed-width scalar.
	dBytes := padLeft(priv.D.Bytes(), 32)
	ecdhPriv, err := curve.NewPrivateKey(dBytes)
	if err != nil {
		return nil, err
	}
	uncompressed := make([]byte, 1+2*32)
	uncompressed[0] = 0x04
	copy(uncompressed[1:33], padLeft(pub.X.Bytes(), 32))
	copy(uncompressed[33:], padLeft(pub.Y.Bytes(), 32))
	ecdhPub, err := curve.NewPublicKey(uncompressed)
	if err != nil {
		return nil, err
	}
	return ecdhPriv.ECDH(ecdhPub)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// buildIV constructs the 12-byte AES-GCM nonce defined in ISO 18013-5
// §9.1.1.5: bytes 0..3 are zero, 4..7 are the "iv identifier" (distinguishes
// which side encrypted), 8..11 are a big-endian per-direction counter.
func buildIV(role Role, counter uint32, encrypting bool) []byte {
	iv := make([]byte, 12)
	var ivID uint32
	// Encrypting: MDOC uses 0x00000001, Reader uses 0x00000000.
	// Decrypting: swap — you expect the peer's identifier.
	switch {
	case role == RoleMDOC && encrypting:
		ivID = 1
	case role == RoleMDOC && !encrypting:
		ivID = 0
	case role == RoleReader && encrypting:
		ivID = 0
	case role == RoleReader && !encrypting:
		ivID = 1
	}
	binary.BigEndian.PutUint32(iv[4:8], ivID)
	binary.BigEndian.PutUint32(iv[8:12], counter)
	return iv
}

type sessionEstablishmentEncode struct {
	EReaderKey cbor.RawMessage `cbor:"eReaderKey"`
	Data       []byte          `cbor:"data"`
}

type sessionDataEncode struct {
	Data   []byte  `cbor:"data,omitempty"`
	Status *uint64 `cbor:"status,omitempty"`
}

func encodeSessionEstablishment(eReaderPub *ecdsa.PublicKey, ciphertext []byte) ([]byte, error) {
	coseKey := ecPubToCoseKey(eReaderPub)
	coseKeyBytes, err := cbor.Marshal(coseKey)
	if err != nil {
		return nil, err
	}
	tagged, err := cbor.Marshal(cbor.Tag{Number: tagEncodedCBOR, Content: coseKeyBytes})
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(sessionEstablishmentEncode{
		EReaderKey: tagged,
		Data:       ciphertext,
	})
}

func encodeSessionData(ciphertext []byte, status *uint64) ([]byte, error) {
	if ciphertext == nil && status == nil {
		return nil, errors.New("proximity: SessionData needs at least data or status")
	}
	return cbor.Marshal(sessionDataEncode{Data: ciphertext, Status: status})
}

// parseSessionMessage handles both SessionEstablishment and SessionData —
// they differ only in the presence of `eReaderKey`, which is not needed for
// decryption (the mdoc is expected to have called
// GetEReaderKeyFromSessionEstablishment before constructing its
// SessionEncryption).
func parseSessionMessage(data []byte) ([]byte, *uint64, error) {
	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(data, &m); err != nil {
		return nil, nil, fmt.Errorf("proximity: decode session message: %w", err)
	}
	var ciphertext []byte
	if raw, ok := m["data"]; ok {
		if err := cbor.Unmarshal(raw, &ciphertext); err != nil {
			return nil, nil, fmt.Errorf("proximity: decode data bstr: %w", err)
		}
	}
	var statusOut *uint64
	if raw, ok := m["status"]; ok {
		var s uint64
		if err := cbor.Unmarshal(raw, &s); err != nil {
			return nil, nil, fmt.Errorf("proximity: decode status: %w", err)
		}
		statusOut = &s
	}
	return ciphertext, statusOut, nil
}
