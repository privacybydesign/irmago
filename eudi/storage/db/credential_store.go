package db

import (
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// CredentialStore is the public interface for inserting and retrieving issued credentials.
type CredentialStore interface {
	// StoreBatch inserts a CredentialBatch and all its IssuedCredentialInstances atomically.
	// batch.Instances must be non-empty. GORM sets each instance's BatchID automatically
	// before running the instance's BeforeCreate hook.
	StoreBatch(batch *models.CredentialBatch) error

	// GetCredentialBatchList returns a list of all stored credential batches with preloaded batch metadata, but without preloading instances.
	GetCredentialBatchList() ([]*models.CredentialBatch, error)

	// GetBatchByHash retrieves a CredentialBatch (without preloading instances) by its
	// deterministic hash. Returns ErrNotFound if no matching batch exists.
	GetBatchByHash(hash string) (*models.CredentialBatch, error)

	// GetBatchesByVCT returns all CredentialBatches whose VerifiableCredentialType matches
	// the given vct string. Does not preload instances.
	GetBatchesByVCT(vct string) ([]*models.CredentialBatch, error)

	// GetUnusedInstance returns one IssuedCredentialInstance from the given batch that has
	// not yet been marked as used. Returns ErrNotFound if all instances are used.
	GetUnusedInstance(batchID datatypes.UUID) (*models.IssuedCredentialInstance, error)

	// MarkInstanceUsed sets Used = true on the given instance and decrements RemainingCount
	// on its parent batch. Both updates run in the same statement group; callers should wrap
	// the call in a UnitOfWork.Do transaction to keep them atomic.
	MarkInstanceUsed(instanceID datatypes.UUID) error

	// DeleteBatch deletes a CredentialBatch and all its instances (via CASCADE).
	DeleteBatch(batchID datatypes.UUID) error

	// DeleteBatchByHash looks up a CredentialBatch by its deterministic hash and deletes it
	// along with all its instances (via CASCADE). Returns ErrNotFound if no batch exists with that hash.
	DeleteBatchByHash(hash string) error
}

type credentialStore struct {
	db *gorm.DB
}

// NewCredentialStore returns a CredentialStore.
func NewCredentialStore(db *gorm.DB) CredentialStore {
	return &credentialStore{
		db: db,
	}
}

func (s *credentialStore) GetCredentialBatchList() ([]*models.CredentialBatch, error) {
	var batches []*models.CredentialBatch
	err := s.db.
		Model(&models.CredentialBatch{}).
		Preload("IssuerDisplay").
		Preload("CredentialMetadata").
		Preload("CredentialMetadata.Display").
		Preload("CredentialMetadata.Claims").
		Preload("CredentialMetadata.Claims.Display").
		Find(&batches).Error
	return batches, err
}

func (s *credentialStore) StoreBatch(batch *models.CredentialBatch) error {
	if batch == nil {
		return fmt.Errorf("batch is nil")
	}
	if len(batch.Instances) == 0 {
		return fmt.Errorf("batch must contain at least one credential instance")
	}

	return s.db.Create(batch).Error
}

func (s *credentialStore) GetBatchByHash(hash string) (*models.CredentialBatch, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}

	var batch models.CredentialBatch
	err := s.db.First(&batch, "hash = ?", hash).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &batch, nil
}

func (s *credentialStore) GetBatchesByVCT(vct string) ([]*models.CredentialBatch, error) {
	if vct == "" {
		return nil, fmt.Errorf("vct is required")
	}

	var batches []*models.CredentialBatch
	err := s.db.
		Preload("CredentialMetadata").
		Preload("CredentialMetadata.Display").
		Where("verifiable_credential_type = ?", vct).
		Find(&batches).Error
	if err != nil {
		return nil, err
	}

	return batches, nil
}

func (s *credentialStore) GetUnusedInstance(batchID datatypes.UUID) (*models.IssuedCredentialInstance, error) {
	if batchID.IsNil() {
		return nil, fmt.Errorf("batchID is required")
	}

	var instance models.IssuedCredentialInstance
	err := s.db.
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

func (s *credentialStore) MarkInstanceUsed(instanceID datatypes.UUID) error {
	if instanceID.IsNil() {
		return fmt.Errorf("instanceID is required")
	}

	// Mark the instance as used.
	res := s.db.Model(&models.IssuedCredentialInstance{}).
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
	return s.db.Model(&models.CredentialBatch{}).
		Where("id = (SELECT credential_batch_id FROM issued_credential_instances WHERE id = ?) AND remaining_count > 0", instanceID).
		UpdateColumn("remaining_count", gorm.Expr("remaining_count - 1")).
		Error
}

func (s *credentialStore) DeleteBatchByHash(hash string) error {
	batch, err := s.GetBatchByHash(hash)
	if err != nil {
		return err
	}
	return s.DeleteBatch(batch.ID)
}

func (s *credentialStore) DeleteBatch(batchID datatypes.UUID) error {
	if batchID.IsNil() {
		return fmt.Errorf("batchID is required")
	}

	// Explicitly delete holder binding keys (and their cascaded metadata) that belong
	// to this batch's instances. The FK lives on IssuedCredentialInstance (belongs-to),
	// so the DB-level ON DELETE CASCADE does not cover this direction.
	if err := s.db.Exec(`DELETE FROM holder_binding_keys WHERE id IN (
		SELECT holder_binding_key_id FROM issued_credential_instances
		WHERE credential_batch_id = ? AND holder_binding_key_id IS NOT NULL
	)`, batchID).Error; err != nil {
		return err
	}

	res := s.db.Delete(&models.CredentialBatch{}, "id = ?", batchID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}
