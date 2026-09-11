package services

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
)

// MdocKeyService mints mdoc device keys for an issuance and stores them in
// mdoc_device_keys, unbound until the issued document that carries the public
// half is stored. It is the mso_mdoc HolderKeyBinder.
//
// Every key is recorded under its JWK thumbprint, whatever binding method the
// proof used: an mdoc embeds the device public key as a COSE_Key in the MSO,
// so the thumbprint is the one identity issuance can derive from the credential
// and presentation can derive from the same MSO. A DID the proof may have
// carried in its kid is not stored; it is not needed to find the key again.
type MdocKeyService struct {
	store db.MdocDeviceKeyStore
}

// NewMdocKeyService returns the storage-backed mdoc device key minter.
func NewMdocKeyService(store db.MdocDeviceKeyStore) *MdocKeyService {
	return &MdocKeyService{store: store}
}

var _ HolderKeyBinder = (*MdocKeyService)(nil)

func (s *MdocKeyService) CreateKeyPairsWithProofs(num uint, proofBuilder proofs.ProofBuilder) ([]models.PublicHolderBindingKey, []string, error) {
	keys, proofStrings, err := generateProofKeys(num, proofBuilder)
	if err != nil {
		return nil, nil, err
	}

	stored := make([]models.MdocDeviceKey, len(keys))
	thumbprints := make([]string, len(keys))
	for i, key := range keys {
		privKeyBytes, err := x509.MarshalPKCS8PrivateKey(key.privKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal device key to PKCS#8: %w", err)
		}
		thumbprintBytes, err := key.jwkPubKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute device key thumbprint: %w", err)
		}
		thumbprints[i] = hex.EncodeToString(thumbprintBytes)
		stored[i] = models.MdocDeviceKey{
			PublicKeyThumbprint: thumbprints[i],
			PrivateKey:          privKeyBytes,
			Curve:               key.privKey.Curve.Params().Name,
		}
	}

	if err := s.store.StoreKeys(stored); err != nil {
		return nil, nil, fmt.Errorf("failed to store device keys: %w", err)
	}

	identifiers := make([]models.PublicHolderBindingKey, len(stored))
	for i := range stored {
		identifiers[i] = models.PublicHolderBindingKey{
			ID:                  stored[i].ID,
			PublicKeyThumbprint: &thumbprints[i],
		}
	}
	return identifiers, proofStrings, nil
}

func (s *MdocKeyService) RemoveKeys(ids []datatypes.UUID) error {
	return s.store.DeleteKeys(ids)
}
