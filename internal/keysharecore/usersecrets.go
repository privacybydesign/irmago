package keysharecore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"

	"github.com/fxamacker/cbor"
	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/signed"
)

type (
	unencryptedUserSecrets struct {
		Pin            []byte
		KeyshareSecret *big.Int
		ID             []byte
		PublicKey      *ecdsa.PublicKey
	}

	// UserSecrets contains the encrypted data of a keyshare user.
	UserSecrets []byte
)

var (
	ErrKeyshareSecretTooBig   = errors.New("Keyshare secret too big to store")
	ErrKeyshareSecretNegative = errors.New("Keyshare secret negative")
	ErrNoSuchKey              = errors.New("Key identifier unknown")
)

func (s *unencryptedUserSecrets) setPin(pin string) error {
	if len(pin) > 64 {
		// padBytes also checks the length, but we want to return a specific error in this case
		return ErrPinTooLong
	}
	paddedPin, err := padBytes([]byte(pin), 64)
	if err != nil {
		return err
	}
	s.Pin = paddedPin
	return nil
}

func (s *unencryptedUserSecrets) setKeyshareSecret(val *big.Int) error {
	if val.Sign() == -1 {
		return ErrKeyshareSecretNegative
	}

	// We want the result to fit into 64 bytes
	if val.BitLen() > 64*8 {
		return ErrKeyshareSecretTooBig
	}

	s.KeyshareSecret = new(big.Int).Set(val)

	return nil
}

func (s *unencryptedUserSecrets) setID(id []byte) error {
	paddedID, err := padBytes(id, 32)
	if err != nil {
		return err
	}
	s.ID = paddedID
	return nil
}

func (user *unencryptedUserSecrets) verifyPin(pin string) error {
	paddedPin, err := padBytes([]byte(pin), 64)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(user.Pin, paddedPin) != 1 {
		return ErrInvalidPin
	}
	return nil
}

type marshaledUserSecrets struct {
	Pin            []byte
	KeyshareSecret []byte
	ID             []byte
	PublicKey      []byte
}

// MarshalCBOR implements cbor.Marshaler to ensure that all fields have a constant size, to minimize
// differences in the size of the encrypted blobs.
func (s *unencryptedUserSecrets) MarshalCBOR() ([]byte, error) {
	secretBts, err := padBytes(s.KeyshareSecret.Bytes(), 64)
	if err != nil {
		return nil, err
	}
	var pkBts []byte
	if s.PublicKey != nil {
		pkBts, err = signed.MarshalPublicKey(s.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	return cbor.Marshal(marshaledUserSecrets{
		s.Pin, secretBts, s.ID, pkBts,
	}, cbor.EncOptions{})
}

func (s *unencryptedUserSecrets) UnmarshalCBOR(bytes []byte) error {
	raw := marshaledUserSecrets{}
	err := cbor.Unmarshal(bytes, &raw)
	if err != nil {
		return err
	}
	*s = unencryptedUserSecrets{
		Pin:            raw.Pin,
		KeyshareSecret: new(big.Int).SetBytes(raw.KeyshareSecret),
		ID:             raw.ID,
	}
	if len(raw.PublicKey) > 0 {
		s.PublicKey, err = signed.UnmarshalPublicKey(raw.PublicKey)
		if err != nil {
			return err
		}
	}
	return nil
}

// publicKey returns the user's public key. For use in jwt.ParseWithClaims().
func (s *unencryptedUserSecrets) publicKey(_ *jwt.Token) (interface{}, error) {
	if s.PublicKey == nil {
		return nil, ErrKeyNotFound
	}
	return s.PublicKey, nil
}

func (c *Core) encryptUserSecrets(secrets unencryptedUserSecrets) (UserSecrets, error) {
	encSecrets := make(UserSecrets, 16, 256)

	bts, err := cbor.Marshal(secrets, cbor.EncOptions{})
	if err != nil {
		return nil, err
	}

	// Store key id
	binary.LittleEndian.PutUint32(encSecrets[0:], c.decryptionKeyID)

	// Generate and store nonce
	_, err = rand.Read(encSecrets[4:16])
	if err != nil {
		return nil, err
	}

	// Encrypt secrets
	gcm, err := newGCM(c.decryptionKey)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(encSecrets[:16], encSecrets[4:16], bts, nil), nil
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

	bts, err := gcm.Open(nil, secrets[4:16], secrets[16:], nil)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}

	var unencSecrets unencryptedUserSecrets
	err = cbor.Unmarshal(bts, &unencSecrets)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}

	return unencSecrets, nil
}

func (c *Core) decryptUserSecretsIfPinOK(secrets UserSecrets, pin string) (unencryptedUserSecrets, error) {
	s, err := c.decryptUserSecrets(secrets)
	if err != nil {
		return unencryptedUserSecrets{}, err
	}

	if err = s.verifyPin(pin); err != nil {
		return unencryptedUserSecrets{}, err
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

// padBytes pads the given byte slice with zeros on the left such that the resulting byte slice
// has the specified length.
func padBytes(src []byte, length int) ([]byte, error) {
	if len(src) > length {
		return nil, errors.New("padBytes: source slice too long")
	}
	if len(src) == length {
		return src, nil
	}
	result := make([]byte, length)
	copy(result[length-len(src):], src)
	return result, nil
}
