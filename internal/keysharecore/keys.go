package keysharecore

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
)

type (
	AesKey [32]byte

	KeyshareCore struct {
		decryptionKeys  map[uint32]AesKey
		encryptionKey   AesKey
		encryptionKeyID uint32

		signKey   *rsa.PrivateKey
		signKeyId int

		commitmentData  map[uint64]*big.Int
		commitmentMutex sync.Mutex

		trustedKeys map[irma.PublicKeyIdentifier]*gabi.PublicKey
	}
)

func NewKeyshareCore() *KeyshareCore {
	return &KeyshareCore{
		decryptionKeys: map[uint32]AesKey{},
		commitmentData: map[uint64]*big.Int{},
		trustedKeys:    map[irma.PublicKeyIdentifier]*gabi.PublicKey{},
	}
}

func GenerateAESKey() (AesKey, error) {
	var res AesKey
	_, err := rand.Read(res[:])
	return res, err
}

func (c *KeyshareCore) DangerousAddAESKey(keyid uint32, key AesKey) {
	c.decryptionKeys[keyid] = key
}

func (c *KeyshareCore) DangerousSetAESEncryptionKey(keyid uint32, key AesKey) {
	c.decryptionKeys[keyid] = key
	c.encryptionKey = key
	c.encryptionKeyID = keyid
}

func (c *KeyshareCore) DangerousSetSignKey(key *rsa.PrivateKey, id int) {
	c.signKey = key
	c.signKeyId = id
}

// Add public key as trusted by keyshareCore. Calling this on incorrectly generated key material WILL compromise keyshare secrets!
func (c *KeyshareCore) DangerousAddTrustedPublicKey(keyid irma.PublicKeyIdentifier, key *gabi.PublicKey) {
	c.trustedKeys[keyid] = key
}
