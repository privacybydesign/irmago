package keysharecore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"

	"github.com/privacybydesign/gabi/big"

	"github.com/go-errors/errors"
)

type (
	// Contains pin (bytes 0-63), secret (bytes 64-127), and identifier (bytes 128-159)
	//  The binary structure of this packet can have security implications through its interaction with the
	//  encryption layer applied before storing it. As such, we keep it here more explicit than
	//  is standard in go. When modifying this structure, analyse whether such changes can have a
	//  security impact through error side channels.
	unencryptedKeysharePacket [64 + 64 + 32]byte

	// Size is that of unencrypted packet + 12 bytes for nonce + 16 bytes for tag + 4 bytes for key ID
	EncryptedKeysharePacket [64 + 64 + 32 + 12 + 16 + 4]byte
)

var (
	ErrKeyshareSecretTooBig   = errors.New("Keyshare secret too big to store")
	ErrKeyshareSecretNegative = errors.New("Keyshare secret negative")
	ErrNoSuchKey              = errors.New("Key identifier unknown")
)

func (p *unencryptedKeysharePacket) pin() [64]byte {
	var result [64]byte
	copy(result[:], p[0:64])
	return result
}

func (p *unencryptedKeysharePacket) setPin(pw [64]byte) {
	copy(p[0:64], pw[:])
}

func (p *unencryptedKeysharePacket) keyshareSecret() *big.Int {
	result := new(big.Int)
	return result.SetBytes(p[64:128])
}

func (p *unencryptedKeysharePacket) setKeyshareSecret(val *big.Int) error {
	if val.Sign() == -1 {
		return ErrKeyshareSecretNegative
	}

	data := val.Bytes()
	if len(data) > 64 {
		return ErrKeyshareSecretTooBig
	}
	zerolen := 64 - len(data)
	for i := 0; i < zerolen; i++ {
		p[64+i] = 0
	}
	copy(p[64+zerolen:], data)

	return nil
}

func (p *unencryptedKeysharePacket) id() [32]byte {
	var result [32]byte
	copy(result[:], p[128:160])
	return result
}

func (p *unencryptedKeysharePacket) setID(id [32]byte) {
	copy(p[128:160], id[:])
}

func (c *Core) encryptPacket(p unencryptedKeysharePacket) (EncryptedKeysharePacket, error) {
	var result EncryptedKeysharePacket

	// Store key id
	binary.LittleEndian.PutUint32(result[0:], c.encryptionKeyID)

	// Generate and store nonce
	_, err := rand.Read(result[4:16])
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}

	// Encrypt packet
	gcm, err := newGCM(c.encryptionKey)
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}
	gcm.Seal(result[:16], result[4:16], p[:], nil)

	return result, nil
}

func (c *Core) decryptPacket(p EncryptedKeysharePacket) (unencryptedKeysharePacket, error) {
	// determine key id
	id := binary.LittleEndian.Uint32(p[0:])

	// Fetch key
	key, ok := c.decryptionKeys[id]
	if !ok {
		return unencryptedKeysharePacket{}, ErrNoSuchKey
	}

	// try and decrypt packet
	gcm, err := newGCM(key)
	if err != nil {
		return unencryptedKeysharePacket{}, err
	}
	var result unencryptedKeysharePacket
	_, err = gcm.Open(result[:0], p[4:16], p[16:], nil)
	if err != nil {
		return unencryptedKeysharePacket{}, err
	}
	return result, nil
}

func (c *Core) decryptPacketIfPinOK(ep EncryptedKeysharePacket, pin string) (unencryptedKeysharePacket, error) {
	paddedPin, err := padPin(pin)
	if err != nil {
		return unencryptedKeysharePacket{}, err
	}

	p, err := c.decryptPacket(ep)
	if err != nil {
		return unencryptedKeysharePacket{}, err
	}

	// Check pins in constant time
	refPin := p.pin()
	if !hmac.Equal(refPin[:], paddedPin[:]) {
		return unencryptedKeysharePacket{}, ErrInvalidPin
	}
	return p, nil
}

func newGCM(key AesKey) (cipher.AEAD, error) {
	keyedAes, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(keyedAes)
	if err != nil {
		return nil, err
	}
	return gcm, nil
}
