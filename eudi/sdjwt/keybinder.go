package sdjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

type KeyBindingStorage interface {
	StorePrivateKeys(keys []*ecdsa.PrivateKey) error
	GetAndRemovePrivateKey(pubKey jwk.Key) (*ecdsa.PrivateKey, error)
	// Takes in a list of pub keys for which it should delete the corresponding private keys
	RemovePrivateKeys(pubKeys []jwk.Key) error
	// Removes all holder binding private keys
	RemoveAllPrivateKeys() error
}

func NewInMemoryKeyBindingStorage() KeyBindingStorage {
	return &InMemoryKeyBindingStorage{
		keys: map[string]*ecdsa.PrivateKey{},
	}
}

type InMemoryKeyBindingStorage struct {
	keys map[string]*ecdsa.PrivateKey
}

func (s *InMemoryKeyBindingStorage) StorePrivateKeys(keys []*ecdsa.PrivateKey) error {
	for _, privKey := range keys {
		privJwk, err := jwk.Import[jwk.Key](privKey)
		if err != nil {
			return fmt.Errorf("failed to convert ecdsa priv key to jwk: %v", err)
		}

		pubJwk, err := privJwk.PublicKey()
		if err != nil {
			return fmt.Errorf("failed to obtain pub key from jwk: %v", err)
		}

		thumbprint, err := pubJwk.Thumbprint(crypto.SHA256)
		if err != nil {
			return fmt.Errorf("failed to create thumbprint of jwk pub key: %v", err)
		}

		s.keys[string(thumbprint)] = privKey
	}
	return nil
}

func (s *InMemoryKeyBindingStorage) GetAndRemovePrivateKey(pubKey jwk.Key) (*ecdsa.PrivateKey, error) {
	thumbprint, err := pubKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to create thumbprint for holder pub key: %v", err)
	}

	privKey, ok := s.keys[string(thumbprint)]
	if !ok {
		return nil, fmt.Errorf("failed to find private key for holder pub key")
	}

	delete(s.keys, string(thumbprint))
	return privKey, nil
}

func (s *InMemoryKeyBindingStorage) RemovePrivateKeys(pubKeys []jwk.Key) error {
	for _, pk := range pubKeys {
		_, err := s.GetAndRemovePrivateKey(pk)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *InMemoryKeyBindingStorage) RemoveAllPrivateKeys() error {
	s.keys = map[string]*ecdsa.PrivateKey{}
	return nil
}

// KeyBinder holds the holder's private keys and signs with them. Can be used to
// move the signing to a server.
type KeyBinder interface {
	// Creates a batch of key pairs and returns the pub keys.
	// These pub keys should be passed in when calling `CreateHolderSignedJwt()`.
	CreateKeyPairs(num uint) ([]jwk.Key, error)
	// Signs a JWT with the given claims using the holder private key of holderPubKey: a
	// KB-JWT (see CreateKbJwt), or the Verifiable Presentation that envelopes an
	// SD-JWT-secured VCDM credential. The header gets alg ES256 on top of customHeaders.
	// The implementation sets iat to the time of signing by its own clock, replacing any
	// iat in claims, so a binder on a server stamps the server's time.
	CreateHolderSignedJwt(holderPubKey jwk.Key, customHeaders map[string]any, claims map[string]any) (string, error)
	// Takes in a list of pub keys for which it should delete the corresponding private keys
	RemovePrivateKeys(pubKeys []jwk.Key) error
	// Removes all holder binding private keys
	RemoveAllPrivateKeys() error
}

type DefaultKeyBinder struct {
	clock   jwt.Clock
	storage KeyBindingStorage
}

func NewDefaultKeyBinder(storage KeyBindingStorage) KeyBinder {
	return &DefaultKeyBinder{
		clock:   systemClock{},
		storage: storage,
	}
}

func NewDefaultKeyBinderWithInMemoryStorage() KeyBinder {
	return NewDefaultKeyBinder(NewInMemoryKeyBindingStorage())
}

// CreateKeyPairs will be deprecated in favor of CreateKeyPairsWithProofs when SD-JWT VC issuance over IRMA protocol is removed.
func (c *DefaultKeyBinder) CreateKeyPairs(num uint) ([]jwk.Key, error) {
	result := make([]jwk.Key, num)
	privKeys := make([]*ecdsa.PrivateKey, num)

	for i := range num {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ecdsa private key: %v", err)
		}
		privKeys[i] = privKey

		privJwk, err := jwk.Import[jwk.Key](privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert ecdsa priv key to jwk: %v", err)
		}

		pubJwk, err := privJwk.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to obtain pub key from priv key jwk: %v", err)
		}
		result[i] = pubJwk
	}

	err := c.storage.StorePrivateKeys(privKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to storage private keys: %v", err)
	}

	return result, nil
}

func (c *DefaultKeyBinder) CreateHolderSignedJwt(holderKey jwk.Key, customHeaders map[string]any, claims map[string]any) (string, error) {
	json, err := json.Marshal(WithIssuedAt(claims, c.clock.Now()))
	if err != nil {
		return "", err
	}

	privKey, err := c.storage.GetAndRemovePrivateKey(holderKey)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve private key: %v", err)
	}

	return NewJwtCreator(privKey).CreateSignedJwt(customHeaders, string(json))
}

func (c *DefaultKeyBinder) RemovePrivateKeys(pubKeys []jwk.Key) error {
	return c.storage.RemovePrivateKeys(pubKeys)
}

func (c *DefaultKeyBinder) RemoveAllPrivateKeys() error {
	return c.storage.RemoveAllPrivateKeys()
}
