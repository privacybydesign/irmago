package sdjwtvc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/utils"
)

// KeyBindingJwt is a string containing the key binding jwt (just the jwt, no ~ or something)
type KeyBindingJwt string

type KeyBindingJwtPayload struct {
	// REQUIRED: the hash over the **COMPLETE** issuer signed JWT part of the SD-JWT
	IssuerSignedJwtHash string `json:"sd_hash"`

	// REQUIRED: the nonce for this, should correspond to the one from the authorization
	Nonce string `json:"nonce"`

	// REQUIRED: the time of issuance
	IssuedAt int64 `json:"iat"`

	// Should equal "client_id" field from the openid4vp auth request
	Audience string `json:"aud"`
}

const (
	Key_SdHash   string = "sd_hash"
	Key_Nonce    string = "nonce"
	Key_Audience string = "aud"
)

type KeyBindingStorage interface {
	StorePrivateKeys(keys []*ecdsa.PrivateKey) error
	GetAndRemovePrivateKey(pubKey jwk.Key) (*ecdsa.PrivateKey, error)
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
		privJwk, err := jwk.Import(privKey)
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

	return privKey, nil
}

// KeyBinder is an interface for creating a key binding jwt from a hash.
// Can be used to move creating the kbjwt to a server.
type KeyBinder interface {
	// Creates a batch of key pairs and returns the pub keys.
	// These pub keys should be passed in when calling `CreateKeyBindingJwt()`.
	CreateKeyPairs(num uint) ([]jwk.Key, error)
	// takes in the hash over the issuer signed JWT and the selected disclosures
	CreateKeyBindingJwt(hash string, holderPubKey jwk.Key, nonce string, audience string) (KeyBindingJwt, error)
}

type DefaultKeyBinder struct {
	clock   Clock
	storage KeyBindingStorage
}

func NewDefaultKeyBinder(storage KeyBindingStorage) *DefaultKeyBinder {
	return &DefaultKeyBinder{
		clock:   NewSystemClock(),
		storage: storage,
	}
}

func NewDefaultKeyBinderWithInMemoryStorage() *DefaultKeyBinder {
	return NewDefaultKeyBinder(NewInMemoryKeyBindingStorage())
}

func (c *DefaultKeyBinder) CreateKeyPairs(num uint) ([]jwk.Key, error) {
	result := make([]jwk.Key, num)
	privKeys := make([]*ecdsa.PrivateKey, num)

	for i := range num {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ecdsa private key: %v", err)
		}
		privKeys[i] = privKey

		privJwk, err := jwk.Import(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert ecdsa priv key to jwk: %v", err)
		}

		pubJwk, err := privJwk.PublicKey()
		result[i] = pubJwk
	}

	err := c.storage.StorePrivateKeys(privKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to storage private keys: %v", err)
	}

	return result, nil
}

func (c *DefaultKeyBinder) CreateKeyBindingJwt(hash string, holderKey jwk.Key, nonce string, audience string) (KeyBindingJwt, error) {
	payload := KeyBindingJwtPayload{
		IssuerSignedJwtHash: hash,
		Nonce:               nonce,
		IssuedAt:            c.clock.Now(),
		Audience:            audience,
	}
	json, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	customHeaders := map[string]any{
		"typ": KbJwtTyp,
	}

	privKey, err := c.storage.GetAndRemovePrivateKey(holderKey)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve private key: %v", err)
	}

	jwtCreator := NewJwtCreator(privKey)

	jwt, err := jwtCreator.CreateSignedJwt(customHeaders, string(json))
	return KeyBindingJwt(jwt), err
}

func CreateKbJwt(sdJwt SdJwtVc, creator KeyBinder, nonce string, audience string) (KeyBindingJwt, error) {
	alg, holderKey, err := extractHashingAlgorithmAndHolderPubKey(sdJwt)
	if err != nil {
		return "", err
	}

	hash, err := CreateHash(alg, string(sdJwt))
	if err != nil {
		return "", nil
	}

	return creator.CreateKeyBindingJwt(hash, holderKey, nonce, audience)
}

func extractHashingAlgorithmAndHolderPubKey(sdJwt SdJwtVc) (HashingAlgorithm, jwk.Key, error) {
	issuerSignedJwt, _, _, err := SplitSdJwtVc(sdJwt)
	if err != nil {
		return "", nil, err
	}
	_, claims, err := decodeJwtWithoutCheckingSignature(string(issuerSignedJwt))
	if err != nil {
		return "", nil, err
	}

	alg, ok := claims[Key_SdAlg].(string)
	if !ok {
		return "", nil, fmt.Errorf("failed to get %s field from claims", Key_SdAlg)
	}

	confirm, err := utils.ExtractOptionalWith(claims, Key_Confirmationkey, parseConfirmField)

	if err != nil {
		return "", nil, err
	}

	keyJson, err := json.Marshal(confirm.Jwk)
	if err != nil {
		return "", nil, err
	}
	key, err := jwk.ParseKey(keyJson)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse key (%v) from json: %v", keyJson, err)
	}

	return HashingAlgorithm(alg), key, nil
}
