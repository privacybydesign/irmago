package services

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/eudi/internal/storage"
	"github.com/privacybydesign/irmago/eudi/internal/storage/models"
	"gorm.io/gorm"
)

// HolderBindingKeyService implements the KeyBinder interface.
// This will be refactored later to use the HolderBindingKeyStore and be more decoupled from the sdjwtvc package, so we can also use it for other purposes if needed.
type HolderBindingKeyService interface {
}

type holderBindingKeyService struct {
	uow storage.UnitOfWork
}

type keyTuple struct {
	privKey    *ecdsa.PrivateKey
	jwkPrivKey jwk.Key
	jwkPubKey  jwk.Key
}

func NewHolderBindingKeyService(uow storage.UnitOfWork) *holderBindingKeyService {
	return &holderBindingKeyService{
		uow: uow,
	}
}

func (s *holderBindingKeyService) CreateKeyPairs(num uint) ([]jwk.Key, error) {
	return nil, fmt.Errorf("func is not implemented on purpose")
}

// CreateKeyPairsWithProofs creates the specified number of ECDSA key pairs, stores the private keys, and returns the corresponding proofs built using the provided proof builder.
func (s *holderBindingKeyService) CreateKeyPairsWithProofs(num uint, proofBuilder proofs.ProofBuilder) ([]string, error) {
	keyTuples := make([]keyTuple, num)
	proofs := make([]string, num)

	for i := range num {
		// TODO: base the choice key type on the supported algorithms in the credential configuration (proof_types_supported / proof_signing_alg_values_supported)
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ecdsa private key: %v", err)
		}

		// Create JWK for the key, which we'll use both in storage and in the proof builder
		jwkPrivKey, err := jwk.Import(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert ecdsa priv key to jwk: %v", err)
		}

		jwkPubKey, err := jwkPrivKey.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("failed to obtain pub key from priv jwk: %v", err)
		}
		err = jwkPubKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
		if err != nil {
			return nil, fmt.Errorf("failed to set key usage on jwk pub key: %v", err)
		}

		// TODO: rebuild proof builder to take the JWK as input instead of the private key, so we can avoid converting back and forth between JWK and ecdsa.PrivateKey

		proof, err := proofBuilder.Build(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to build proof: %v", err)
		}

		// TODO: this currently only supports the proof builder returning a string (which is the case for the JwtProofBuilder), but we need to support other types of proof in the future
		if proofStr, ok := proof.(string); ok {
			proofs[i] = proofStr
		} else {
			return nil, fmt.Errorf("proof builder did not return a string")
		}

		keyTuples[i] = keyTuple{
			privKey:    privKey,
			jwkPrivKey: jwkPrivKey,
			jwkPubKey:  jwkPubKey,
		}
	}

	err := s.storePrivateKeys(keyTuples)
	if err != nil {
		return nil, fmt.Errorf("failed to storage private keys: %v", err)
	}

	return proofs, nil
}

func (s *holderBindingKeyService) storePrivateKeys(keys []keyTuple) error {
	return s.uow.Do(func(tx *gorm.DB) error {
		for _, key := range keys {
			privKeyBytes, err := x509.MarshalPKCS8PrivateKey(key.privKey)
			if err != nil {
				return fmt.Errorf("failed to marshal private key to bytes: %v", err)
			}

			// TODO: does not need to be encrypted anymore, as we introduced encryption at rest at the database level.
			thumbprint, err := key.jwkPubKey.Thumbprint(crypto.SHA256)
			if err != nil {
				return fmt.Errorf("failed to create thumbprint of jwk pub key: %v", err)
			}

			keyModel := &models.HolderBindingKey{
				Algorithm:           models.KeyAlgorithmECDSA,
				PrivateKey:          privKeyBytes,
				PublicKeyThumbprint: hex.EncodeToString(thumbprint),
				ECDSA: &models.ECDSAKeyMetadata{
					CurveName: key.privKey.Curve.Params().Name,
				},
			}

			err = s.uow.HolderBindingKeyStorage().StoreKey(tx, keyModel)
			if err != nil {
				return fmt.Errorf("failed to store holder binding key: %v", err)
			}
		}
		return nil
	})
}

func (s *holderBindingKeyService) CreateKeyBindingJwt(hash string, holderPubKey jwk.Key, nonce string, audience string) (sdjwtvc.KeyBindingJwt, error) {
	return sdjwtvc.KeyBindingJwt("invalid"), fmt.Errorf("func is not implemented on purpose")
}

func (s *holderBindingKeyService) RemovePrivateKeys(pubKeys []jwk.Key) error {
	// Removes all holder binding private keys
	return fmt.Errorf("func is not implemented on purpose")
}

func (s *holderBindingKeyService) RemoveAllPrivateKeys() error {
	// Removes all holder binding private keys
	return s.uow.Do(func(tx *gorm.DB) error {
		return s.uow.HolderBindingKeyStorage().DeleteAll(tx)
	})
}
