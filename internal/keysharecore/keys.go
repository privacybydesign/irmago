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

	commitData struct {
		commit    *big.Int
		challenge *big.Int
	}

	Core struct {
		// Keys used for storage encryption/decryption
		decryptionKeys  map[uint32]AesKey
		encryptionKey   AesKey
		encryptionKeyID uint32

		// Key used to sign keyshare protocol messages
		signKey   *rsa.PrivateKey
		signKeyID int

		// Commit values generated in first step of keyshare protocol
		commitmentData  map[uint64]commitData
		commitmentMutex sync.Mutex

		// IRMA issuer keys that are allowed to be used in keyshare
		//  sessions
		trustedKeys map[irma.PublicKeyIdentifier]*gabi.PublicKey
	}
)

func NewKeyshareCore() *Core {
	return &Core{
		decryptionKeys: map[uint32]AesKey{},
		commitmentData: map[uint64]commitData{},
		trustedKeys:    map[irma.PublicKeyIdentifier]*gabi.PublicKey{},
	}
}

func GenerateAESKey() (AesKey, error) {
	var res AesKey
	_, err := rand.Read(res[:])
	return res, err
}

// Add an aes key for decryption, with identifier keyid
// Calling this will cause all keyshare packets generated with the key to be trusted
func (c *Core) DangerousAddAESKey(keyID uint32, key AesKey) {
	c.decryptionKeys[keyID] = key
}

// Set the aes key for encrypting new/changed keyshare data
// with identifier keyid
// Calling this wil also cause all keyshare packets generated with the key to be trusted
func (c *Core) DangerousSetAESEncryptionKey(keyID uint32, key AesKey) {
	c.decryptionKeys[keyID] = key
	c.encryptionKey = key
	c.encryptionKeyID = keyID
}

// Set key used to sign keyshare protocol messages
func (c *Core) SetSignKey(key *rsa.PrivateKey, id int) {
	c.signKey = key
	c.signKeyID = id
}

// Add public key as trusted by keyshareCore. Calling this on incorrectly generated key material WILL compromise keyshare secrets!
func (c *Core) DangerousAddTrustedPublicKey(keyID irma.PublicKeyIdentifier, key *gabi.PublicKey) {
	c.trustedKeys[keyID] = key
}
