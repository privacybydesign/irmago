package mdoc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/fxamacker/cbor/v2"
)

// ============================================================
// SESSION ENCRYPTION — ISO/IEC 18013-5 9.1.1.4, 9.1.1.5
// ============================================================
//
// 9.1.1.4 defines the two messages:
//
//	SessionEstablishment = {
//	    "eReaderKey" : EReaderKeyBytes,
//	    "data" : bstr                    ; Encrypted mdoc request
//	}
//
//	SessionData = {
//	    ? "data" : bstr       ; Encrypted mdoc response or mdoc request
//	    ? "status" : uint     ; Status code
//	}
//
// and 9.1.1.5 the cryptography under them: ECKA-DH to ZAB, HKDF to SKReader and
// SKDevice, AES-256-GCM with a 12-byte IV of `identifier || message counter`.
//
// The IV is never transmitted. Both parties reconstruct it from counters they
// keep themselves, which is why Session tracks a receive counter as well as a
// send counter: a message dropped or replayed does not merely fail to decrypt, it
// desynchronises everything after it.

// Session status codes from Table 20.
//
// The published table renders with its Description column shifted one row up
// relative to the codes — the same layout defect that affects Table 7 and the
// BleOptions CDDL. The mapping below is the corrected one, confirmed by D.5.1,
// which ends its example session with `{"status": 20}` under the heading "Session
// termination".
const (
	// StatusErrorSessionEncryption reports that a message could not be decrypted.
	// The session shall be terminated.
	StatusErrorSessionEncryption uint = 10

	// StatusErrorCBORDecoding reports that a message was not valid CBOR. The
	// session shall be terminated.
	StatusErrorCBORDecoding uint = 11

	// StatusSessionTermination ends the session. 9.1.1.4 requires both parties to
	// then destroy the session keys and ephemeral key material and close the
	// channel — see Session.Close.
	StatusSessionTermination uint = 20
)

// Session identifiers from 9.1.1.5: "The mdoc reader shall use the following
// identifier: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00. The mdoc shall use the
// following identifier: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x01."
//
// They differ so that the two directions cannot collide on an IV while sharing a
// counter space. Which one a party encrypts under follows from its role, never
// from which key it happens to hold.
var (
	readerIdentifier = [8]byte{0, 0, 0, 0, 0, 0, 0, 0}
	mdocIdentifier   = [8]byte{0, 0, 0, 0, 0, 0, 0, 1}
)

// SessionKeys are the two keys of 9.1.1.4. Both parties derive both: each
// encrypts with one and decrypts with the other.
type SessionKeys struct {
	// SKReader encrypts mdoc requests, i.e. everything the reader sends.
	SKReader []byte
	// SKDevice encrypts mdoc responses, i.e. everything the mdoc sends.
	SKDevice []byte
}

// deriveSessionKeys performs the ECKA-DH of 9.1.1.5 and derives both session keys
// from the result.
//
// "The inputs shall be the EDeviceKey.Priv and EReaderKey.Pub for the mdoc and
// EReaderKey.Priv and EDeviceKey.Pub for the mdoc reader" — the two parties feed
// the mirrored pair and reach the same ZAB, so this function is role-agnostic and
// the callers below carry the role.
//
// ZAB in BSI TR-03111's ECKA-DH is the x-coordinate of the shared point, which is
// exactly what crypto/ecdh returns for the NIST curves.
func deriveSessionKeys(ourPrivate *ecdsa.PrivateKey, peerPublic *ecdsa.PublicKey, transcript SessionTranscript) (SessionKeys, error) {
	if ourPrivate == nil || ourPrivate.Curve == nil {
		return SessionKeys{}, fmt.Errorf("no ephemeral private key for the session")
	}
	if peerPublic == nil || peerPublic.Curve == nil {
		return SessionKeys{}, fmt.Errorf("no peer ephemeral public key for the session")
	}
	// 9.1.5.2 restricts both ephemeral keys to Table 22, and this package's subset
	// of it is what coseCurveIDFor knows. Checking here names the curve; letting
	// ECDH fail would report only a mismatch.
	if _, ok := coseCurveIDFor(ourPrivate.Curve); !ok {
		return SessionKeys{}, fmt.Errorf(
			"ephemeral key is on %s, which is not one of the Table 22 curves this package supports",
			ourPrivate.Curve.Params().Name)
	}

	ecdhPrivate, err := ourPrivate.ECDH()
	if err != nil {
		return SessionKeys{}, fmt.Errorf("convert ephemeral private key for ECKA-DH: %w", err)
	}
	ecdhPeer, err := peerPublic.ECDH()
	if err != nil {
		return SessionKeys{}, fmt.Errorf("convert peer ephemeral public key for ECKA-DH: %w", err)
	}
	zab, err := ecdhPrivate.ECDH(ecdhPeer)
	if err != nil {
		// Curve mismatch between the two ephemeral keys lands here, as does a
		// peer point that is not on the curve.
		return SessionKeys{}, fmt.Errorf("ECKA-DH: %w", err)
	}
	return sessionKeysFromZAB(zab, transcript)
}

// sessionKeysFromZAB runs the two HKDF derivations of 9.1.1.4:
//
//	Hash SHA-256, IKM ZAB, salt SHA-256(SessionTranscriptBytes),
//	info "SKReader" / "SKDevice" as UTF-8, L 32 octets.
//
// Split from the agreement so it can be exercised against ISO's published ZAB and
// session keys without needing the private keys, which Annex D does not publish.
func sessionKeysFromZAB(zab []byte, transcript SessionTranscript) (SessionKeys, error) {
	salt, err := transcript.KeyDerivationSalt()
	if err != nil {
		return SessionKeys{}, err
	}
	skReader, err := hkdf.Key(sha256.New, zab, salt, "SKReader", 32)
	if err != nil {
		return SessionKeys{}, fmt.Errorf("derive SKReader: %w", err)
	}
	skDevice, err := hkdf.Key(sha256.New, zab, salt, "SKDevice", 32)
	if err != nil {
		return SessionKeys{}, fmt.Errorf("derive SKDevice: %w", err)
	}
	return SessionKeys{SKReader: skReader, SKDevice: skDevice}, nil
}

// Session holds one party's half of an encrypted session: which key it encrypts
// under, which it decrypts with, and the two message counters that make up the
// IVs.
//
// It is not safe for concurrent use. The counters are the reason: two goroutines
// encrypting at once could hand the same counter to two messages, and 9.1.1.5's
// "a message counter value shall never be reused in any future encryption using
// the same key" is the one rule in the clause whose breach is catastrophic rather
// than merely non-conformant — repeating an IV under GCM leaks the XOR of the two
// plaintexts and the authentication subkey with it.
type Session struct {
	encrypt cipher.AEAD
	decrypt cipher.AEAD

	encryptIdentifier [8]byte
	decryptIdentifier [8]byte

	sendCounter uint32
	recvCounter uint32

	// keys is retained only so Close can zero it; see the caveat there.
	keys SessionKeys
}

// NewMdocSession derives the session keys as the mdoc: ECKA-DH over
// EDeviceKey.Priv and EReaderKey.Pub, per 9.1.1.5.
//
// The mdoc encrypts with SKDevice under identifier 0x00…01 and decrypts the
// reader's messages with SKReader.
func NewMdocSession(eDeviceKey *ecdsa.PrivateKey, eReaderKeyPub *ecdsa.PublicKey, transcript SessionTranscript) (*Session, error) {
	keys, err := deriveSessionKeys(eDeviceKey, eReaderKeyPub, transcript)
	if err != nil {
		return nil, err
	}
	return newSession(keys, keys.SKDevice, mdocIdentifier, keys.SKReader, readerIdentifier)
}

// NewReaderSession derives the session keys as the mdoc reader: ECKA-DH over
// EReaderKey.Priv and EDeviceKey.Pub, per 9.1.1.5.
//
// The reader encrypts with SKReader under identifier 0x00…00 and decrypts the
// mdoc's messages with SKDevice.
func NewReaderSession(eReaderKey *ecdsa.PrivateKey, eDeviceKeyPub *ecdsa.PublicKey, transcript SessionTranscript) (*Session, error) {
	keys, err := deriveSessionKeys(eReaderKey, eDeviceKeyPub, transcript)
	if err != nil {
		return nil, err
	}
	return newSession(keys, keys.SKReader, readerIdentifier, keys.SKDevice, mdocIdentifier)
}

func newSession(keys SessionKeys, encryptKey []byte, encryptID [8]byte, decryptKey []byte, decryptID [8]byte) (*Session, error) {
	encrypt, err := newGCM(encryptKey)
	if err != nil {
		return nil, err
	}
	decrypt, err := newGCM(decryptKey)
	if err != nil {
		return nil, err
	}
	return &Session{
		encrypt:           encrypt,
		decrypt:           decrypt,
		encryptIdentifier: encryptID,
		decryptIdentifier: decryptID,
		keys:              keys,
	}, nil
}

// newGCM builds the AES-256-GCM instance 9.1.1.5 requires. The key length is
// checked rather than assumed: HKDF was asked for 32 octets, and AES-128 silently
// standing in for AES-256 is not a failure any test of the ciphertext would catch.
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("session key is %d bytes, want the 32 of AES-256-GCM", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES-256: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM: %w", err)
	}
	return aead, nil
}

// sessionIV builds the 12-byte IV of 9.1.1.5: "The IV shall be the concatenation
// of the identifier and the message counter (identifier || message counter). The
// identifier shall be an 8-byte value. […] The message counter value shall be a
// 4-byte big-endian unsigned integer."
func sessionIV(identifier [8]byte, counter uint32) []byte {
	iv := make([]byte, 12)
	copy(iv, identifier[:])
	binary.BigEndian.PutUint32(iv[8:], counter)
	return iv
}

// Encrypt seals one message for the peer and returns the value of the `data`
// element: 9.1.1.5's "concatenation of the ciphertext and all 16 bytes of the
// authentication tag (ciphertext || authentication tag)", which is what GCM's
// Seal already produces.
//
// The counter advances first, so the first message of a session is encrypted
// under counter 1 as the clause requires, and no counter is ever used twice.
// Exhaustion is an error rather than a wrap: wrapping would reuse an IV.
//
// AAD is empty, per "The AAD […] shall be an empty string."
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	if s.encrypt == nil {
		return nil, fmt.Errorf("session is closed")
	}
	if s.sendCounter == math.MaxUint32 {
		return nil, fmt.Errorf(
			"session message counter is exhausted: 9.1.1.5 forbids reusing a counter value with the same key, so the session must be terminated")
	}
	s.sendCounter++
	return s.encrypt.Seal(nil, sessionIV(s.encryptIdentifier, s.sendCounter), plaintext, nil), nil
}

// Decrypt opens one message from the peer.
//
// The IV is not transmitted, so it is reconstructed from this side's count of how
// many messages the peer has sent. A failure therefore means either a corrupted
// message or a lost one — after a gap, every subsequent message fails too, and
// 9.1.1.4 gives StatusErrorSessionEncryption for exactly this, with termination as
// the required action. The counter is not advanced on failure, so a caller that
// chooses to retry the same message rather than terminate still uses the right IV.
func (s *Session) Decrypt(data []byte) ([]byte, error) {
	if s.decrypt == nil {
		return nil, fmt.Errorf("session is closed")
	}
	if s.recvCounter == math.MaxUint32 {
		return nil, fmt.Errorf("session message counter is exhausted")
	}
	next := s.recvCounter + 1
	plaintext, err := s.decrypt.Open(nil, sessionIV(s.decryptIdentifier, next), data, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"decrypt session message %d: %w (a lost or reordered message desynchronises the counter and every later message fails too)",
			next, err)
	}
	s.recvCounter = next
	return plaintext, nil
}

// Close discards the session state, covering 9.1.1.4's "destruction of session
// keys and related ephemeral key material" on termination. Closing the channel is
// the caller's half.
//
// Caveat, stated rather than papered over: this zeroes the key material this
// struct holds and drops the AEADs, so the session cannot be used again. It cannot
// scrub the copies crypto/aes made of the key inside the cipher, which Go gives no
// way to reach. Treat it as bounding the lifetime of the keys, not as guaranteeing
// their erasure from memory.
func (s *Session) Close() {
	for _, key := range [][]byte{s.keys.SKReader, s.keys.SKDevice} {
		for i := range key {
			key[i] = 0
		}
	}
	s.keys = SessionKeys{}
	s.encrypt = nil
	s.decrypt = nil
}

// SessionEstablishment is the first message of a session, sent by the reader
// (9.1.1.4). It carries the reader's ephemeral public key and the first encrypted
// request in one go.
//
// EReaderKeyBytes must be the same bytes that occupy the second slot of the
// SessionTranscript, since both parties derive the session keys over a transcript
// they each build independently.
type SessionEstablishment struct {
	EReaderKeyBytes cbor.RawMessage `cbor:"eReaderKey"`
	Data            []byte          `cbor:"data"`
}

// SessionData carries every message after the first, in either direction
// (9.1.1.4). Both members are optional in the CDDL, but a message with neither
// says nothing; the constructors below cannot build one.
type SessionData struct {
	Data   []byte `cbor:"data,omitempty"`
	Status *uint  `cbor:"status,omitempty"`
}

// NewSessionEstablishment builds the reader's opening message.
func NewSessionEstablishment(eReaderKeyBytes cbor.RawMessage, encryptedRequest []byte) (SessionEstablishment, error) {
	if err := validateTag24Slot("EReaderKeyBytes", eReaderKeyBytes); err != nil {
		return SessionEstablishment{}, err
	}
	if len(encryptedRequest) == 0 {
		return SessionEstablishment{}, fmt.Errorf(
			"SessionEstablishment has no data: 9.1.1.4 makes the encrypted mdoc request mandatory")
	}
	return SessionEstablishment{EReaderKeyBytes: eReaderKeyBytes, Data: encryptedRequest}, nil
}

// NewSessionData wraps an encrypted message for transmission.
func NewSessionData(encrypted []byte) (SessionData, error) {
	if len(encrypted) == 0 {
		return SessionData{}, fmt.Errorf("SessionData has neither data nor status")
	}
	return SessionData{Data: encrypted}, nil
}

// NewSessionStatus builds a status-only message.
//
// 9.1.1.4: "If status code 10 or 11 is returned, the data element shall not be
// present in that session data message." Status 20 carries no data here either —
// nothing in this package has anything to say alongside a termination.
func NewSessionStatus(status uint) SessionData {
	return SessionData{Status: &status}
}

// validate applies the one constraint 9.1.1.4 places on the combination of the
// two optional members.
func (d SessionData) validate() error {
	if d.Status != nil && len(d.Data) > 0 {
		switch *d.Status {
		case StatusErrorSessionEncryption, StatusErrorCBORDecoding:
			return fmt.Errorf(
				"SessionData carries data alongside status %d: 9.1.1.4 requires the data element to be absent for status 10 and 11",
				*d.Status)
		}
	}
	return nil
}

// Encode CBOR-encodes the message.
func (d SessionData) Encode() ([]byte, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	encoded, err := cbor.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("encode SessionData: %w", err)
	}
	return encoded, nil
}

// Encode CBOR-encodes the message.
func (e SessionEstablishment) Encode() ([]byte, error) {
	if err := validateTag24Slot("EReaderKeyBytes", e.EReaderKeyBytes); err != nil {
		return nil, err
	}
	encoded, err := cbor.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("encode SessionEstablishment: %w", err)
	}
	return encoded, nil
}

// DecodeSessionEstablishment reads the reader's opening message.
func DecodeSessionEstablishment(data []byte) (SessionEstablishment, error) {
	var establishment SessionEstablishment
	if err := mdocDecMode.Unmarshal(data, &establishment); err != nil {
		return SessionEstablishment{}, fmt.Errorf("decode SessionEstablishment: %w", err)
	}
	if err := validateTag24Slot("EReaderKeyBytes", establishment.EReaderKeyBytes); err != nil {
		return SessionEstablishment{}, err
	}
	if len(establishment.Data) == 0 {
		return SessionEstablishment{}, fmt.Errorf(
			"SessionEstablishment has no data: 9.1.1.4 makes the encrypted mdoc request mandatory")
	}
	return establishment, nil
}

// DecodeSessionData reads a session message.
func DecodeSessionData(data []byte) (SessionData, error) {
	var message SessionData
	if err := mdocDecMode.Unmarshal(data, &message); err != nil {
		return SessionData{}, fmt.Errorf("decode SessionData: %w", err)
	}
	if err := message.validate(); err != nil {
		return SessionData{}, err
	}
	return message, nil
}

// EReaderKey decodes the reader's ephemeral public key out of the session
// establishment message, for the mdoc's half of the ECKA-DH.
func (e SessionEstablishment) EReaderKey() (*ecdsa.PublicKey, error) {
	if err := validateTag24Slot("EReaderKeyBytes", e.EReaderKeyBytes); err != nil {
		return nil, err
	}
	coseKey, err := tag24Unwrap[COSEKey](e.EReaderKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("decode EReaderKey: %w", err)
	}
	return ecdsaPublicKeyFromCOSE(coseKey)
}
