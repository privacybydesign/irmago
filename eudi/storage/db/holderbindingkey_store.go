package db

import (
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// HolderBindingKeyStore is the public interface for storing and retrieving holder binding keys.
type HolderBindingKeyStore interface {
	StoreKey(key *models.HolderBindingKey) error
	StoreKeys(keys []models.HolderBindingKey) error
	GetByID(id datatypes.UUID) (*models.HolderBindingKey, error)
	GetByThumbprint(thumbprint string) (*models.HolderBindingKey, error)
	GetByDidUrl(didUrl string) (*models.HolderBindingKey, error)
	DeleteKey(id datatypes.UUID) error
	DeleteKeys(ids []datatypes.UUID) error
	DeleteAll() error
}

// holderBindingKeyStore is the gorm-backed implementation of HolderBindingKeyStore.
type holderBindingKeyStore struct {
	db *gorm.DB
}

// NewHolderBindingKeyStore creates a HolderBindingKeyStore backed by an existing gorm.DB.
func NewHolderBindingKeyStore(db *gorm.DB) HolderBindingKeyStore {
	return &holderBindingKeyStore{db: db}
}

// StoreKey inserts the base key row plus the matching algorithm-specific metadata row.
func (r *holderBindingKeyStore) StoreKey(key *models.HolderBindingKey) error {
	return r.db.Create(key).Error
}

func (r *holderBindingKeyStore) StoreKeys(keys []models.HolderBindingKey) error {
	if keys == nil {
		return fmt.Errorf("keys are nil")
	}

	return r.db.Create(keys).Error
}

// GetByID retrieves a key and preloads both metadata relations.
func (r *holderBindingKeyStore) GetByID(id datatypes.UUID) (*models.HolderBindingKey, error) {
	var key models.HolderBindingKey

	err := r.db.
		Preload("ECDSA").
		Preload("RSA").
		First(&key, "id = ?", id).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &key, nil
}

// GetByThumbprint retrieves a key by thumbprint.
// If your system is multi-tenant, use GetByTenantAndThumbprint instead.
func (r *holderBindingKeyStore) GetByThumbprint(thumbprint string) (*models.HolderBindingKey, error) {
	var key models.HolderBindingKey

	err := r.db.
		Preload("ECDSA").
		Preload("RSA").
		First(&key, "public_key_thumbprint = ?", thumbprint).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &key, nil
}

// DeleteKey deletes the base row.
// Because the model uses OnDelete:CASCADE, related metadata should be deleted too.
func (r *holderBindingKeyStore) DeleteKey(id datatypes.UUID) error {
	res := r.db.Delete(&models.HolderBindingKey{}, "id = ?", id)

	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// DeleteKeys deletes multiple keys by their IDs.
// If the key is not found, it will continue to delete the other keys
func (r *holderBindingKeyStore) DeleteKeys(ids []datatypes.UUID) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, id := range ids {
			res := r.db.Delete(&models.HolderBindingKey{}, "id = ?", id)

			if res.Error != nil {
				return res.Error
			}
		}
		return nil
	})
}

func (r *holderBindingKeyStore) DeleteAll() error {
	return r.db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&models.HolderBindingKey{}).Error
}

func (r *holderBindingKeyStore) GetByDidUrl(didUrl string) (*models.HolderBindingKey, error) {
	var key models.HolderBindingKey
	err := r.db.
		Preload("ECDSA").
		Preload("RSA").
		First(&key, "did_url = ?", didUrl).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &key, nil
}
