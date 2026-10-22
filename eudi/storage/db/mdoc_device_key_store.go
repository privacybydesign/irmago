package db

import (
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// MdocDeviceKeyStore persists mdoc device keys (models.MdocDeviceKey). Keys are
// created unbound before issuance and linked to their instance afterwards;
// lookup is always by the public key's JWK thumbprint.
type MdocDeviceKeyStore interface {
	// StoreKeys inserts the given keys, unbound.
	StoreKeys(keys []models.MdocDeviceKey) error

	// GetByThumbprint returns the key whose public half has the given hex
	// SHA-256 JWK thumbprint. Returns ErrNotFound if none matches.
	GetByThumbprint(thumbprint string) (*models.MdocDeviceKey, error)

	// LinkToInstance binds a key to the instance whose MSO carries its public
	// half. Returns ErrNotFound if no key has that id.
	LinkToInstance(keyID, instanceID datatypes.UUID) error

	// DeleteKeys deletes the given keys; ids that match nothing are skipped.
	// Used to roll back keys minted for an issuance that failed.
	DeleteKeys(ids []datatypes.UUID) error

	// DeleteAll removes every device key, bound or not.
	DeleteAll() error
}

type mdocDeviceKeyStore struct {
	db *gorm.DB
}

// NewMdocDeviceKeyStore returns an MdocDeviceKeyStore over the given database.
func NewMdocDeviceKeyStore(db *gorm.DB) MdocDeviceKeyStore {
	return &mdocDeviceKeyStore{db: db}
}

func (s *mdocDeviceKeyStore) StoreKeys(keys []models.MdocDeviceKey) error {
	if len(keys) == 0 {
		return fmt.Errorf("no keys to store")
	}
	return s.db.Create(keys).Error
}

func (s *mdocDeviceKeyStore) GetByThumbprint(thumbprint string) (*models.MdocDeviceKey, error) {
	if thumbprint == "" {
		return nil, fmt.Errorf("thumbprint is required")
	}
	var key models.MdocDeviceKey
	err := s.db.First(&key, "public_key_thumbprint = ?", thumbprint).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &key, nil
}

func (s *mdocDeviceKeyStore) LinkToInstance(keyID, instanceID datatypes.UUID) error {
	if keyID.IsNil() || instanceID.IsNil() {
		return fmt.Errorf("keyID and instanceID are required")
	}
	res := s.db.Model(&models.MdocDeviceKey{}).
		Where("id = ?", keyID).
		Update("mdoc_batch_instance_id", instanceID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *mdocDeviceKeyStore) DeleteKeys(ids []datatypes.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	return s.db.Delete(&models.MdocDeviceKey{}, "id IN ?", ids).Error
}

func (s *mdocDeviceKeyStore) DeleteAll() error {
	return s.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&models.MdocDeviceKey{}).Error
}
