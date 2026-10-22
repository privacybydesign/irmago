package db

import (
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// VcdmStore persists SD-JWT-secured W3C VCDM credentials: VcdmBatch rows and
// their VcdmBatchInstance copies. Holder binding keys live in the table the
// SD-JWT VC store uses (HolderBindingKeyStore).
//
// Like the mdoc store there are no display preloads: a VCDM batch carries its
// display metadata as JSON columns that load with the row.
type VcdmStore interface {
	// StoreBatch inserts a VcdmBatch and all its instances atomically.
	// batch.Instances must be non-empty.
	StoreBatch(batch *models.VcdmBatch) error

	// ListBatches returns every stored batch, without instances.
	ListBatches() ([]*models.VcdmBatch, error)

	// GetBatchByHashAndFormat returns the batch with the given content hash and
	// securing format, without instances. Returns ErrNotFound if none matches.
	GetBatchByHashAndFormat(hash string, format models.CredentialFormat) (*models.VcdmBatch, error)

	// GetUnusedInstance returns one instance of the batch that has not been
	// presented. Returns ErrNotFound when every instance is used.
	GetUnusedInstance(batchID datatypes.UUID) (*models.VcdmBatchInstance, error)

	// MarkInstanceUsed sets Used on the instance and decrements the parent
	// batch's RemainingCount, in one transaction. Returns ErrNotFound if the
	// instance does not exist or is already used.
	MarkInstanceUsed(instanceID datatypes.UUID) error

	// DeleteBatch deletes a batch, its instances and their holder binding keys.
	// Returns ErrNotFound if no batch has that id.
	DeleteBatch(batchID datatypes.UUID) error

	// DeleteBatchByHashAndFormat deletes the batch with the given content hash
	// and securing format, the same way. Returns ErrNotFound if none matches.
	DeleteBatchByHashAndFormat(hash string, format models.CredentialFormat) error
}

type vcdmStore struct {
	db *gorm.DB
}

// NewVcdmStore returns a VcdmStore over the given database.
func NewVcdmStore(db *gorm.DB) VcdmStore {
	return &vcdmStore{db: db}
}

func (s *vcdmStore) StoreBatch(batch *models.VcdmBatch) error {
	if batch == nil {
		return fmt.Errorf("batch is nil")
	}
	if len(batch.Instances) == 0 {
		return fmt.Errorf("batch must contain at least one instance")
	}
	return s.db.Create(batch).Error
}

func (s *vcdmStore) ListBatches() ([]*models.VcdmBatch, error) {
	var batches []*models.VcdmBatch
	err := s.db.Find(&batches).Error
	return batches, err
}

func (s *vcdmStore) GetBatchByHashAndFormat(hash string, format models.CredentialFormat) (*models.VcdmBatch, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}
	if format == "" {
		return nil, fmt.Errorf("format is required")
	}
	var batch models.VcdmBatch
	err := s.db.First(&batch, "hash = ? AND format = ?", hash, format).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &batch, nil
}

func (s *vcdmStore) GetUnusedInstance(batchID datatypes.UUID) (*models.VcdmBatchInstance, error) {
	if batchID.IsNil() {
		return nil, fmt.Errorf("batchID is required")
	}
	var instance models.VcdmBatchInstance
	err := s.db.
		Preload("HolderBindingKey").
		Preload("HolderBindingKey.ECDSA").
		Where("vcdm_batch_id = ? AND used = ?", batchID, false).
		First(&instance).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &instance, nil
}

func (s *vcdmStore) MarkInstanceUsed(instanceID datatypes.UUID) error {
	if instanceID.IsNil() {
		return fmt.Errorf("instanceID is required")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.VcdmBatchInstance{}).
			Where("id = ? AND used = ?", instanceID, false).
			Update("used", true)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return tx.Model(&models.VcdmBatch{}).
			Where("id = (SELECT vcdm_batch_id FROM vcdm_batch_instances WHERE id = ?) AND remaining_count > 0", instanceID).
			UpdateColumn("remaining_count", gorm.Expr("remaining_count - 1")).
			Error
	})
}

func (s *vcdmStore) DeleteBatch(batchID datatypes.UUID) error {
	if batchID.IsNil() {
		return fmt.Errorf("batchID is required")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		// Delete the holder binding keys explicitly rather than relying on the
		// cascade: the key table predates vcdm_batch_instance_id, and SQLite cannot
		// add a foreign key to an existing table, so on a database created before
		// VCDM support the column carries no constraint to cascade through.
		if err := tx.
			Where("vcdm_batch_instance_id IN (SELECT id FROM vcdm_batch_instances WHERE vcdm_batch_id = ?)", batchID).
			Delete(&models.HolderBindingKey{}).Error; err != nil {
			return err
		}
		res := tx.Delete(&models.VcdmBatch{}, "id = ?", batchID)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (s *vcdmStore) DeleteBatchByHashAndFormat(hash string, format models.CredentialFormat) error {
	batch, err := s.GetBatchByHashAndFormat(hash, format)
	if err != nil {
		return err
	}
	return s.DeleteBatch(batch.ID)
}
