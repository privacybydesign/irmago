package storage

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/privacybydesign/irmago/eudi/internal/storage/models"
	"gorm.io/gorm"
)

// HolderBindingKeyStore is the public interface for storing and retrieving holder binding keys.
type HolderBindingKeyStore interface {
	StoreKey(db *gorm.DB, key *models.HolderBindingKey) error
	GetByID(db *gorm.DB, id uuid.UUID) (*models.HolderBindingKey, error)
	GetByThumbprint(db *gorm.DB, thumbprint string) (*models.HolderBindingKey, error)
	DeleteKey(db *gorm.DB, id uuid.UUID) error
	DeleteAll(db *gorm.DB) error
}

// holderBindingKeyStore is the gorm-backed implementation of HolderBindingKeyStore.
type holderBindingKeyStore struct{}

// NewHolderBindingKeyStore creates a HolderBindingKeyStore backed by an existing gorm.DB.
func NewHolderBindingKeyStore(db *gorm.DB) HolderBindingKeyStore {
	return &holderBindingKeyStore{}
}

// StoreKey inserts the base key row plus the matching algorithm-specific metadata row.
func (r *holderBindingKeyStore) StoreKey(db *gorm.DB, key *models.HolderBindingKey) error {
	if key == nil {
		return fmt.Errorf("key is nil")
	}

	return db.Create(key).Error
}

// GetByID retrieves a key and preloads both metadata relations.
func (r *holderBindingKeyStore) GetByID(db *gorm.DB, id uuid.UUID) (*models.HolderBindingKey, error) {
	var key models.HolderBindingKey

	err := db.
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
func (r *holderBindingKeyStore) GetByThumbprint(db *gorm.DB, thumbprint string) (*models.HolderBindingKey, error) {
	var key models.HolderBindingKey

	err := db.
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
func (r *holderBindingKeyStore) DeleteKey(db *gorm.DB, id uuid.UUID) error {
	res := db.Delete(&models.HolderBindingKey{}, "id = ?", id)

	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

func (r *holderBindingKeyStore) DeleteAll(db *gorm.DB) error {
	return db.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&models.HolderBindingKey{}).Error
}
