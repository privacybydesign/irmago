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
	//  The binary structure of this data structure can have security implications through its interaction
	//  with the encryption layer applied before storing it. As such, we keep it here more explicit than
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

func (s *unencryptedUserSecrets) pin() [64]byte {
	var result [64]byte
	copy(result[:], s[0:64])
	return result
}

func (s *unencryptedUserSecrets) setPin(pw [64]byte) {
	copy(s[0:64], pw[:])
}

func (s *unencryptedUserSecrets) keyshareSecret() *big.Int {
	result := new(big.Int)
	return result.SetBytes(s[64:128])
}

func (s *unencryptedUserSecrets) setKeyshareSecret(val *big.Int) error {
	if val.Sign() == -1 {
		return ErrKeyshareSecretNegative
	}

	data := val.Bytes()
	if len(data) > 64 {
		return ErrKeyshareSecretTooBig
	}
	zerolen := 64 - len(data)
	for i := 0; i < zerolen; i++ {
		s[64+i] = 0
	}
	copy(s[64+zerolen:], data)

	return nil
}

func (s *unencryptedUserSecrets) id() [32]byte {
	var result [32]byte
	copy(result[:], s[128:160])
	return result
}

func (s *unencryptedUserSecrets) setID(id [32]byte) {
	copy(s[128:160], id[:])
}

func (c *Core) encryptUserSecrets(secrets unencryptedUserSecrets) (UserSecrets, error) {
	var encSecret UserSecrets

	// Store key id
	binary.LittleEndian.PutUint32(encSecret[0:], c.decryptionKeyID)

	// Generate and store nonce
	_, err := rand.Read(encSecret[4:16])
	if err != nil {
		return UserSecrets{}, err
	}

	// Encrypt secrets
	gcm, err := newGCM(c.decryptionKey)
	if err != nil {
		return UserSecrets{}, err
	}
	gcm.Seal(encSecret[:16], encSecret[4:16], secrets[:], nil)

	return encSecret, nil
}

func (c *Core) decryptUserSecrets(secrets UserSecrets) (unencryptedUserSecrets, error) {
	// determine key id
	id := binary.LittleEndian.Uint32(secrets[0:])

	// Fetch key
	key, ok := c.decryptionKeys[id]
	if !ok {
		return unencryptedUserSecrets{}, ErrNoSuchKey
	}

	// try and decrypt secrets
	gcm, err := newGCM(key)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}
	var unencSecret unencryptedUserSecrets
	_, err = gcm.Open(unencSecret[:0], secrets[4:16], secrets[16:], nil)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}
	return unencSecret, nil
}

func (c *Core) decryptUserSecretsIfPinOK(secrets UserSecrets, pin string) (unencryptedUserSecrets, error) {
	paddedPin, err := padPin(pin)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}

	s, err := c.decryptUserSecrets(secrets)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}

	refPin := s.pin()
	if subtle.ConstantTimeCompare(refPin[:], paddedPin[:]) != 1 {
		return unencryptedUserSecrets{}, ErrInvalidPin
	}
	return s, nil
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
