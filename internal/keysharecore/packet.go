package keysharecore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/privacybydesign/gabi/big"
)

type (
	// Contains pin (bytes 0-63) and secret (bytes 64-127)
	unencryptedKeysharePacket [64 + 64]byte

	// Size is that of unencrypted packet + 12 bytes for nonce + 16 bytes for tag + 4 bytes for key ID
	EncryptedKeysharePacket [64 + 64 + 12 + 16 + 4]byte
)

var (
	ErrKeyshareSecretTooBig   = errors.New("Keyshare secret too big to store")
	ErrKeyshareSecretNegative = errors.New("Keyshare secret negative")
	NoSuchKey                 = errors.New("Key identifier unknown")
)

func (p *unencryptedKeysharePacket) getPin() [64]byte {
	var result [64]byte
	copy(result[:], p[0:64])
	return result
}

func (p *unencryptedKeysharePacket) setPin(pw [64]byte) {
	copy(p[0:64], pw[:])
}

func (p *unencryptedKeysharePacket) getKeyshareSecret() *big.Int {
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

func (c *KeyshareCore) encryptPacket(p unencryptedKeysharePacket) (EncryptedKeysharePacket, error) {
	var result EncryptedKeysharePacket

	// Store key id
	binary.LittleEndian.PutUint32(result[0:], c.encryptionKeyID)

	// Generate and store nonce
	_, err := rand.Read(result[4:16])
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}

	// Encrypt packet
	keyedAes, err := aes.NewCipher(c.encryptionKey[:])
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}
	gcm, err := cipher.NewGCM(keyedAes)
	if err != nil {
		return EncryptedKeysharePacket{}, err
	}
	gcm.Seal(result[:16], result[4:16], p[:], nil)

	return result, nil
}

func (c *KeyshareCore) decryptPacket(p EncryptedKeysharePacket) (unencryptedKeysharePacket, error) {
	// determine key id
	id := binary.LittleEndian.Uint32(p[0:])

	// Fetch key
	key, ok := c.decryptionKeys[id]
	if !ok {
		return unencryptedKeysharePacket{}, NoSuchKey
	}

	// try and decrypt packet
	keyedAes, err := aes.NewCipher(key[:])
	if err != nil {
		return unencryptedKeysharePacket{}, err
	}
	gcm, err := cipher.NewGCM(keyedAes)
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
