package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// SdJwtVcStore persists SD-JWT VC credentials: SdJwtVcBatch rows, their
// SdJwtVcBatchInstance copies and the display metadata tree hanging off them.
// SD-JWT VC only; mso_mdoc has its own store (MdocStore).
type SdJwtVcStore interface {
	// StoreBatch inserts a SdJwtVcBatch and all its IssuedCredentialInstances atomically.
	// batch.Instances must be non-empty. GORM sets each instance's BatchID automatically
	// before running the instance's BeforeCreate hook.
	StoreBatch(batch *models.SdJwtVcBatch) error

	// GetCredentialBatchList returns a list of all stored credential batches with preloaded batch metadata, but without preloading instances.
	GetCredentialBatchList() ([]*models.SdJwtVcBatch, error)

	// GetBatchByHash retrieves a SdJwtVcBatch (without preloading instances) by its
	// deterministic hash. Returns ErrNotFound if no matching batch exists.
	GetBatchByHash(hash string) (*models.SdJwtVcBatch, error)

	// GetUnusedInstance returns one SdJwtVcBatchInstance from the given batch that has
	// not yet been marked as used, with its holder binding key (and algorithm-specific
	// metadata) preloaded. Returns ErrNotFound if all instances are used.
	GetUnusedInstance(batchID datatypes.UUID) (*models.SdJwtVcBatchInstance, error)

	// MarkInstanceUsed sets Used = true on the given instance and decrements RemainingCount
	// on its parent batch. Both updates run in the same statement group; callers should wrap
	// the call in a UnitOfWork.Do transaction to keep them atomic.
	MarkInstanceUsed(instanceID datatypes.UUID) error

	// DeleteBatch deletes a SdJwtVcBatch and all its instances (via CASCADE).
	DeleteBatch(batchID datatypes.UUID) error

	// DeleteBatchByHash looks up a SdJwtVcBatch by its deterministic hash and deletes it
	// along with all its instances (via CASCADE). Returns ErrNotFound if no batch exists with that hash.
	DeleteBatchByHash(hash string) error

	// CredentialStatusStore is embedded so RevocationService can treat this
	// store's instances the same way it treats MdocStore's — see
	// credential_status_store.go, where ListInstancesWithStatusReference,
	// ListStatusReferencedInstanceStatuses and UpdateInstanceStatus are
	// documented. SdJwtVcBatchInstance is the concrete row shape behind them
	// here; MdocBatchInstance is mdoc's.
	CredentialStatusStore

	// UpdateBatchHash rewrites a SdJwtVcBatch's deduplication hash. Returns
	// ErrNotFound on no match.
	//
	// Exists for the one job of migrating rows written under an older hash
	// definition, not for ordinary use: the hash is a credential's identity and a
	// unique index, so changing it on a live batch is only correct when the
	// recomputation is over the same inputs the batch already holds.
	UpdateBatchHash(batchID datatypes.UUID, hash string) error
}

type sdJwtVcStore struct {
	db *gorm.DB
}

// NewSdJwtVcStore returns a SdJwtVcStore.
func NewSdJwtVcStore(db *gorm.DB) SdJwtVcStore {
	return &sdJwtVcStore{
		db: db,
	}
}

// withBatchDisplayPreloads eager-loads every association needed to render a
// batch: the issuer's display entries, and the credential metadata tree
// (its display entries, its claims, and each claim's display entries).
//
// Centralized because a missing preload does not fail — it silently yields
// empty display metadata, so the credential surfaces with a blank issuer name
// and unnamed attributes, which is easy to ship and hard to notice. Every
// batch lookup that a display or log path can reach goes through here so the
// lookups cannot drift apart. That already happened once: the mdoc handler,
// while it still read this table, fetched batches through lookups that
// under-preloaded relative to GetCredentialBatchList, leaving permission screens
// and disclosure logs without issuer names or claim display names.
func withBatchDisplayPreloads(db *gorm.DB) *gorm.DB {
	return db.
		Preload("IssuerDisplay").
		Preload("CredentialMetadata").
		Preload("CredentialMetadata.Display").
		Preload("CredentialMetadata.Claims").
		Preload("CredentialMetadata.Claims.Display")
}

func (s *sdJwtVcStore) GetCredentialBatchList() ([]*models.SdJwtVcBatch, error) {
	var batches []*models.SdJwtVcBatch
	err := withBatchDisplayPreloads(s.db.Model(&models.SdJwtVcBatch{})).
		Find(&batches).Error
	return batches, err
}

func (s *sdJwtVcStore) StoreBatch(batch *models.SdJwtVcBatch) error {
	if batch == nil {
		return fmt.Errorf("batch is nil")
	}
	if len(batch.Instances) == 0 {
		return fmt.Errorf("batch must contain at least one credential instance")
	}

	return s.db.Create(batch).Error
}

func (s *sdJwtVcStore) GetBatchByHash(hash string) (*models.SdJwtVcBatch, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}

	var batch models.SdJwtVcBatch
	err := withBatchDisplayPreloads(s.db).First(&batch, "hash = ?", hash).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &batch, nil
}

func (s *sdJwtVcStore) GetUnusedInstance(batchID datatypes.UUID) (*models.SdJwtVcBatchInstance, error) {
	if batchID.IsNil() {
		return nil, fmt.Errorf("batchID is required")
	}

	var instance models.SdJwtVcBatchInstance
	err := s.db.
		Preload("HolderBindingKey").
		Preload("HolderBindingKey.ECDSA").
		Where("credential_batch_id = ? AND used = ?", batchID, false).
		First(&instance).
		Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &instance, nil
}

func (s *sdJwtVcStore) MarkInstanceUsed(instanceID datatypes.UUID) error {
	if instanceID.IsNil() {
		return fmt.Errorf("instanceID is required")
	}

	// Mark the instance as used.
	res := s.db.Model(&models.SdJwtVcBatchInstance{}).
		Where("id = ? AND used = ?", instanceID, false).
		Update("used", true)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}

	// Decrement RemainingCount on the parent batch, guarded by a floor of zero.
	// This runs as a separate statement; wrap both calls in a UnitOfWork.Do
	// transaction to keep them atomic.
	return s.db.Model(&models.SdJwtVcBatch{}).
		Where("id = (SELECT credential_batch_id FROM issued_credential_instances WHERE id = ?) AND remaining_count > 0", instanceID).
		UpdateColumn("remaining_count", gorm.Expr("remaining_count - 1")).
		Error
}

func (s *sdJwtVcStore) DeleteBatchByHash(hash string) error {
	batch, err := s.GetBatchByHash(hash)
	if err != nil {
		return err
	}
	return s.DeleteBatch(batch.ID)
}

func (s *sdJwtVcStore) DeleteBatch(batchID datatypes.UUID) error {
	if batchID.IsNil() {
		return fmt.Errorf("batchID is required")
	}

	res := s.db.Delete(&models.SdJwtVcBatch{}, "id = ?", batchID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

func (s *sdJwtVcStore) ListInstancesWithStatusReference() ([]CredentialStatusInstance, error) {
	return sdJwtVcStatusTables.listInstancesWithStatusReference(s.db)
}

func (s *sdJwtVcStore) ListStatusReferencedInstanceStatuses() ([]BatchInstanceStatus, error) {
	return sdJwtVcStatusTables.listStatusReferencedInstanceStatuses(s.db)
}

func (s *sdJwtVcStore) UpdateBatchHash(batchID datatypes.UUID, hash string) error {
	if batchID.IsNil() {
		return fmt.Errorf("batchID is required")
	}
	if hash == "" {
		return fmt.Errorf("hash is required")
	}
	res := s.db.Model(&models.SdJwtVcBatch{}).
		Where("id = ?", batchID).
		Update("hash", hash)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *sdJwtVcStore) UpdateInstanceStatus(instanceID datatypes.UUID, status uint8, checkedAt time.Time) error {
	return sdJwtVcStatusTables.updateInstanceStatus(s.db, instanceID, status, checkedAt)
}
