package keysharecore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
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
	unencryptedUserSecrets [64 + 64 + 32]byte

	// UserSecrets contains the encrypted data of a keyshare user.
	// The size is that of unencryptedUserSecrets + 12 bytes for nonce + 16 bytes for tag + 4 bytes for key ID.
	UserSecrets [64 + 64 + 32 + 12 + 16 + 4]byte
)

var (
	ErrKeyshareSecretTooBig   = errors.New("Keyshare secret too big to store")
	ErrKeyshareSecretNegative = errors.New("Keyshare secret negative")
	ErrNoSuchKey              = errors.New("Key identifier unknown")
)

func (p *unencryptedUserSecrets) pin() [64]byte {
	var result [64]byte
	copy(result[:], p[0:64])
	return result
}

func (p *unencryptedUserSecrets) setPin(pw [64]byte) {
	copy(p[0:64], pw[:])
}

func (p *unencryptedUserSecrets) keyshareSecret() *big.Int {
	result := new(big.Int)
	return result.SetBytes(p[64:128])
}

func (p *unencryptedUserSecrets) setKeyshareSecret(val *big.Int) error {
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

func (p *unencryptedUserSecrets) id() [32]byte {
	var result [32]byte
	copy(result[:], p[128:160])
	return result
}

func (p *unencryptedUserSecrets) setID(id [32]byte) {
	copy(p[128:160], id[:])
}

func (c *Core) encryptUserSecrets(p unencryptedUserSecrets) (UserSecrets, error) {
	var result UserSecrets

	// Store key id
	binary.LittleEndian.PutUint32(result[0:], c.decryptionKeyID)

	// Generate and store nonce
	_, err := rand.Read(result[4:16])
	if err != nil {
		return UserSecrets{}, err
	}

	// Encrypt packet
	gcm, err := newGCM(c.decryptionKey)
	if err != nil {
		return UserSecrets{}, err
	}
	gcm.Seal(result[:16], result[4:16], p[:], nil)

	return result, nil
}

func (c *Core) decryptUserSecrets(p UserSecrets) (unencryptedUserSecrets, error) {
	// determine key id
	id := binary.LittleEndian.Uint32(p[0:])

	// Fetch key
	key, ok := c.decryptionKeys[id]
	if !ok {
		return unencryptedUserSecrets{}, ErrNoSuchKey
	}

	// try and decrypt packet
	gcm, err := newGCM(key)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}
	var result unencryptedUserSecrets
	_, err = gcm.Open(result[:0], p[4:16], p[16:], nil)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}
	return result, nil
}

func (c *Core) decryptUserSecretsIfPinOK(ep UserSecrets, pin string) (unencryptedUserSecrets, error) {
	paddedPin, err := padPin(pin)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}

	p, err := c.decryptUserSecrets(ep)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}

	refPin := p.pin()
	if subtle.ConstantTimeCompare(refPin[:], paddedPin[:]) != 1 {
		return unencryptedUserSecrets{}, ErrInvalidPin
	}
	return p, nil
}

func newGCM(key AESKey) (cipher.AEAD, error) {
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
