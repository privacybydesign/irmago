package openid4vci

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/internal/storage"
	"github.com/privacybydesign/irmago/eudi/internal/storage/models"
)

// HolderBindingKeyService implements the KeyBinder interface.
type HolderBindingKeyService interface {
	CreateKeyPairsWithProofs(num uint, proofBuilder proofs.ProofBuilder) (uuid.UUIDs, []string, error)
}

type holderBindingKeyService struct {
	store storage.HolderBindingKeyStore
}

type keyTuple struct {
	privKey    *ecdsa.PrivateKey
	jwkPrivKey jwk.Key
	jwkPubKey  jwk.Key
	didUrl     *string
}

func NewHolderBindingKeyService(db storage.Storage) *holderBindingKeyService {
	return &holderBindingKeyService{
		store: storage.NewHolderBindingKeyStore(db.Db()),
	}
}

// CreateKeyPairsWithProofs creates the specified number of ECDSA key pairs, stores the private keys, and returns the corresponding proofs built using the provided proof builder.
func (s *holderBindingKeyService) CreateKeyPairsWithProofs(num uint, proofBuilder proofs.ProofBuilder) (uuid.UUIDs, []string, error) {
	keyTuples := make([]keyTuple, num)
	proofs := make([]string, num)

	for i := range num {
		// TODO: base the choice key type on the supported algorithms in the credential configuration (proof_types_supported / proof_signing_alg_values_supported)
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ecdsa private key: %v", err)
		}

		// Create JWK for the key, which we'll use both in storage and in the proof builder
		jwkPrivKey, err := jwk.Import(privKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert ecdsa priv key to jwk: %v", err)
		}

		jwkPubKey, err := jwkPrivKey.PublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to obtain pub key from priv jwk: %v", err)
		}
		err = jwkPubKey.Set(jwk.KeyUsageKey, jwk.ForSignature)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to set key usage on jwk pub key: %v", err)
		}

		// TODO: rebuild proof builder to take the JWK as input instead of the private key, so we can avoid converting back and forth between JWK and ecdsa.PrivateKey

		proof, err := proofBuilder.Build(privKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to build proof: %v", err)
		}

		keyTuples[i] = keyTuple{
			privKey:    privKey,
			jwkPrivKey: jwkPrivKey,
			jwkPubKey:  jwkPubKey,
		}

		// TODO: this currently only supports the proof builder returning a string (which is the case for the JwtProofBuilder), but we need to support other types of proof in the future
		if proofStr, ok := proof.(string); ok {
			proofs[i] = proofStr

			// Extract the DID URL (if any)
			keyTuples[i].didUrl = extractDidUrlFromProof(&proofStr)
		} else {
			return nil, nil, fmt.Errorf("proof builder did not return a string")
		}
	}

	keyIds, err := s.storePrivateKeys(keyTuples)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to storage private keys: %v", err)
	}

	return keyIds, proofs, nil
}

func (s *holderBindingKeyService) storePrivateKeys(keys []keyTuple) (uuid.UUIDs, error) {
	keyModels := make([]models.HolderBindingKey, len(keys))
	ids := make(uuid.UUIDs, len(keys))

	for i, key := range keys {
		privKeyBytes, err := x509.MarshalPKCS8PrivateKey(key.privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key to bytes: %v", err)
		}

		keyModels[i] = models.HolderBindingKey{
			Algorithm:  models.KeyAlgorithmECDSA,
			PrivateKey: privKeyBytes,
			ECDSA: &models.ECDSAKeyMetadata{
				CurveName: key.privKey.Curve.Params().Name,
			},
		}

		// If a DID has been generated as proof, we store the DID instead of the public key thumbprint, to be able to link the key to the proof. If no DID is present, we fall back to storing the thumbprint of the public key.
		if key.didUrl != nil {
			keyModels[i].DidUrl = key.didUrl
		} else {
			thumbprintBytes, err := key.jwkPubKey.Thumbprint(crypto.SHA256)
			if err != nil {
				return nil, fmt.Errorf("failed to create thumbprint of jwk pub key: %v", err)
			}
			thumbprint := hex.EncodeToString(thumbprintBytes)
			keyModels[i].PublicKeyThumbprint = &thumbprint
		}
	}

	err := s.store.StoreKeys(keyModels)
	if err != nil {
		return nil, fmt.Errorf("failed to store holder binding keys: %v", err)
	}

	// Return the KeyIDs of the stored keys
	for i, keyModel := range keyModels {
		ids[i] = keyModel.ID
	}

	return ids, nil
}

func (s *holderBindingKeyService) RemoveAllKeys() error {
	// Removes all holder binding private keys
	return s.store.DeleteAll()
}

func (s *holderBindingKeyService) RemoveKeys(ids uuid.UUIDs) error {
	// Removes holder binding private keys by their IDs
	for _, id := range ids {
		if err := s.store.DeleteKey(id); err != nil {
			return err
		}
	}
	return nil
}

// extractDidUrlFromProof extracts the DID URL from the `kid` JWS header of a proof JWT,
// returning nil if the proof is absent or if the `kid` is not a DID URL.
func extractDidUrlFromProof(proof *string) *string {
	if proof == nil {
		return nil
	}

	msg, err := jws.Parse([]byte(*proof))
	if err != nil {
		return nil
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil
	}

	kid, ok := sigs[0].ProtectedHeaders().KeyID()
	if !ok || !strings.HasPrefix(kid, "did:") {
		return nil
	}

	return &kid
}
