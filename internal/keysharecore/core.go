package keysharecore

import (
	"crypto/rand"
	"crypto/rsa"
	"sync"

	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/gabikeys"
	irma "github.com/privacybydesign/irmago"
)

const (
	JWTIssuerDefault    = "keyshare_server"
	JWTPinExpiryDefault = 5 * 60 // seconds
)

type (
	AESKey [32]byte

	Core struct {
		// Keys used for storage encryption/decryption
		decryptionKeys  map[uint32]AESKey
		decryptionKey   AESKey
		decryptionKeyID uint32

		// Key used to sign keyshare protocol messages
		jwtPrivateKey   *rsa.PrivateKey
		jwtPrivateKeyID uint32

		jwtIssuer    string
		jwtPinExpiry int

		// Commit values generated in first step of keyshare protocol
		commitmentData  map[uint64]*big.Int
		commitmentMutex sync.Mutex

		// IRMA issuer keys that are allowed to be used in keyshare
		//  sessions
		trustedKeys map[irma.PublicKeyIdentifier]*gabikeys.PublicKey
	}

	Configuration struct {
		// Keys used for storage encryption/decryption
		DecryptionKey   AESKey
		DecryptionKeyID uint32

		// Key used to sign keyshare protocol messages
		JWTPrivateKey   *rsa.PrivateKey
		JWTPrivateKeyID uint32

		JWTIssuer    string
		JWTPinExpiry int // in seconds
	}
)

func NewKeyshareCore(conf *Configuration) *Core {
	c := &Core{
		decryptionKeys: map[uint32]AESKey{},
		commitmentData: map[uint64]*big.Int{},
		trustedKeys:    map[irma.PublicKeyIdentifier]*gabikeys.PublicKey{},
	}

	c.setDecryptionKey(conf.DecryptionKeyID, conf.DecryptionKey)
	c.setJWTPrivateKey(conf.JWTPrivateKeyID, conf.JWTPrivateKey)

	c.jwtIssuer = conf.JWTIssuer
	if c.jwtIssuer == "" {
		c.jwtIssuer = JWTIssuerDefault
	}
	c.jwtPinExpiry = conf.JWTPinExpiry
	if c.jwtPinExpiry == 0 {
		c.jwtPinExpiry = JWTPinExpiryDefault
	}

	return c
}

func GenerateDecryptionKey() (AESKey, error) {
	var res AESKey
	_, err := rand.Read(res[:])
	return res, err
}

// Add an aes key for decryption, with identifier keyid
// Calling this will cause all keyshare packets generated with the key to be trusted
func (c *Core) DangerousAddDecryptionKey(keyID uint32, key AESKey) {
	c.decryptionKeys[keyID] = key
}

// Set the aes key for encrypting new/changed keyshare data
// with identifier keyid
// Calling this will also cause all keyshare packets generated with the key to be trusted
func (c *Core) setDecryptionKey(keyID uint32, key AESKey) {
	c.decryptionKeys[keyID] = key
	c.decryptionKey = key
	c.decryptionKeyID = keyID
}

// Set key used to sign keyshare protocol messages
func (c *Core) setJWTPrivateKey(id uint32, key *rsa.PrivateKey) {
	c.jwtPrivateKey = key
	c.jwtPrivateKeyID = id
}

// Add public key as trusted by keyshareCore. Calling this on incorrectly generated key material WILL compromise keyshare secrets!
func (c *Core) DangerousAddTrustedPublicKey(keyID irma.PublicKeyIdentifier, key *gabikeys.PublicKey) {
	c.trustedKeys[keyID] = key
}
