package services

import (
	"context"
	"crypto"
	"encoding/hex"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/credentials/proofs"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/walletprovider"
	"gorm.io/datatypes"
)

// MdocKeyService mints mdoc device keys for an issuance and stores them in
// mdoc_device_keys, unbound until the issued document that carries the public
// half is stored. It is the issuance-side counterpart of mdocDeviceKeyBinder,
// which resolves those same keys back to a mdoc.DeviceSigner at presentation.
//
// Every key is recorded under its JWK thumbprint, whatever binding method the
// proof used: an mdoc embeds the device public key as a COSE_Key in the MSO,
// so the thumbprint is the one identity issuance can derive from the credential
// and presentation can derive from the same MSO. A DID the proof may have
// carried in its kid is not stored; it is not needed to find the key again.
type MdocKeyService struct {
	store db.MdocDeviceKeyStore

	// provider plays the same part as on holderBindingKeyService.
	provider walletprovider.WalletProvider
}

// NewMdocKeyService returns the storage-backed mdoc device key minter. With a
// wallet provider (non-nil provider) it mints keys in the provider's HSM,
// otherwise in software.
func NewMdocKeyService(store db.MdocDeviceKeyStore, provider walletprovider.WalletProvider) *MdocKeyService {
	return &MdocKeyService{store: store, provider: provider}
}

var _ HolderKeyBinder = (*MdocKeyService)(nil)

func (s *MdocKeyService) KeyProtection(ctx context.Context) (walletprovider.KeyProtection, bool) {
	return providerKeyProtection(ctx, s.provider)
}

func (s *MdocKeyService) CreateKeyPairsWithProofs(ctx context.Context, num uint, proofBuilder proofs.ProofBuilder, attest *KeyAttestationOptions) ([]models.PublicHolderBindingKey, []string, error) {
	keys, proofStrings, err := mintProofKeys(ctx, s.provider, num, proofBuilder, attest)
	if err != nil {
		return nil, nil, err
	}

	stored := make([]models.MdocDeviceKey, len(keys))
	thumbprints := make([]string, len(keys))
	for i, key := range keys {
		privKeyBytes, err := key.privateKeyBytes()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encode device key: %w", err)
		}
		thumbprintBytes, err := key.jwkPubKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to compute device key thumbprint: %w", err)
		}
		thumbprints[i] = hex.EncodeToString(thumbprintBytes)
		stored[i] = models.MdocDeviceKey{
			PublicKeyThumbprint: thumbprints[i],
			KeyBackend:          key.backend(),
			PrivateKey:          privKeyBytes,
			Curve:               key.pub.Curve.Params().Name,
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

// RemoveKeys deletes the device keys with the given ids, telling the wallet
// provider to delete the ones in its HSM; see holderBindingKeyService.RemoveKeys.
func (s *MdocKeyService) RemoveKeys(ids []datatypes.UUID) error {
	keys, err := s.store.GetByIDs(ids)
	if err != nil {
		return err
	}
	var refs []string
	for _, key := range keys {
		if ref := key.ProviderKeyRef(); ref != "" {
			refs = append(refs, ref)
		}
	}
	providerErr := removeProviderKeys(s.provider, refs)
	if err := s.store.DeleteKeys(ids); err != nil {
		return err
	}
	return providerErr
}
