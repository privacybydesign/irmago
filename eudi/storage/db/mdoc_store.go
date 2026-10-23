package db

import (
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// MdocStore persists mso_mdoc credentials: MdocBatch rows and their
// MdocBatchInstance documents. Device keys have their own store
// (MdocDeviceKeyStore).
//
// There are no display preloads here, unlike the SD-JWT store: an mdoc batch
// carries its display metadata as JSON columns that load with the row, so the
// silent under-preload the SD-JWT store's withBatchDisplayPreloads guards
// against cannot happen.
type MdocStore interface {
	// StoreBatch inserts an MdocBatch and all its instances atomically.
	// batch.Instances must be non-empty.
	StoreBatch(batch *models.MdocBatch) error

	// ListBatches returns every stored batch, without instances.
	ListBatches() ([]*models.MdocBatch, error)

	// GetBatchByHash returns the batch with the given content hash, without
	// instances. Returns ErrNotFound if none matches.
	GetBatchByHash(hash string) (*models.MdocBatch, error)

	// GetBatchesByDocType returns every batch of the given ISO 18013-5 docType,
	// without instances.
	GetBatchesByDocType(docType string) ([]*models.MdocBatch, error)

	// GetUnusedInstance returns one instance of the batch that has not been
	// presented, with its device key preloaded, skipping the instances in
	// excluding. Returns ErrNotFound when every instance is used or excluded.
	GetUnusedInstance(batchID datatypes.UUID, excluding ...datatypes.UUID) (*models.MdocBatchInstance, error)

	// MarkInstanceUsed sets Used on the instance and decrements the parent
	// batch's RemainingCount, in one transaction. Returns ErrNotFound if the
	// instance does not exist or is already used.
	MarkInstanceUsed(instanceID datatypes.UUID) error

	// DeleteBatch deletes a batch; the cascade removes its instances and their
	// device keys. Returns ErrNotFound if no batch has that id.
	DeleteBatch(batchID datatypes.UUID) error

	// DeleteBatchByHash deletes the batch with the given content hash, with the
	// same cascade. Returns ErrNotFound if none matches.
	DeleteBatchByHash(hash string) error

	// KeyIDsByBatchHash returns the IDs of the keys the batch's instances are
	// bound to, so they can be removed where they live before the batch is.
	KeyIDsByBatchHash(hash string) ([]datatypes.UUID, error)
}

type mdocStore struct {
	db *gorm.DB
}

// NewMdocStore returns an MdocStore over the given database.
func NewMdocStore(db *gorm.DB) MdocStore {
	return &mdocStore{db: db}
}

func (s *mdocStore) StoreBatch(batch *models.MdocBatch) error {
	if batch == nil {
		return fmt.Errorf("batch is nil")
	}
	if len(batch.Instances) == 0 {
		return fmt.Errorf("batch must contain at least one instance")
	}
	return s.db.Create(batch).Error
}

func (s *mdocStore) ListBatches() ([]*models.MdocBatch, error) {
	var batches []*models.MdocBatch
	err := s.db.Find(&batches).Error
	return batches, err
}

func (s *mdocStore) GetBatchByHash(hash string) (*models.MdocBatch, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}
	var batch models.MdocBatch
	err := s.db.First(&batch, "hash = ?", hash).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &batch, nil
}

func (s *mdocStore) GetBatchesByDocType(docType string) ([]*models.MdocBatch, error) {
	if docType == "" {
		return nil, fmt.Errorf("docType is required")
	}
	var batches []*models.MdocBatch
	err := s.db.Where("doc_type = ?", docType).Find(&batches).Error
	return batches, err
}

func (s *mdocStore) GetUnusedInstance(batchID datatypes.UUID, excluding ...datatypes.UUID) (*models.MdocBatchInstance, error) {
	if batchID.IsNil() {
		return nil, fmt.Errorf("batchID is required")
	}
	var instance models.MdocBatchInstance
	query := s.db.
		Preload("DeviceKey").
		Where("mdoc_batch_id = ? AND used = ?", batchID, false)
	if len(excluding) > 0 {
		query = query.Where("id NOT IN ?", excluding)
	}
	err := query.First(&instance).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &instance, nil
}

func (s *mdocStore) MarkInstanceUsed(instanceID datatypes.UUID) error {
	if instanceID.IsNil() {
		return fmt.Errorf("instanceID is required")
	}
	return s.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.MdocBatchInstance{}).
			Where("id = ? AND used = ?", instanceID, false).
			Update("used", true)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrNotFound
		}
		// Floor at zero: a batch whose count already reads 0 is left alone rather
		// than wrapped around.
		return tx.Model(&models.MdocBatch{}).
			Where("id = (SELECT mdoc_batch_id FROM mdoc_batch_instances WHERE id = ?) AND remaining_count > 0", instanceID).
			UpdateColumn("remaining_count", gorm.Expr("remaining_count - 1")).
			Error
	})
}

func (s *mdocStore) DeleteBatch(batchID datatypes.UUID) error {
	if batchID.IsNil() {
		return fmt.Errorf("batchID is required")
	}
	res := s.db.Delete(&models.MdocBatch{}, "id = ?", batchID)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// KeyIDsByBatchHash returns the IDs of the device keys the instances of the
// batch with the given hash are bound to.
func (s *mdocStore) KeyIDsByBatchHash(hash string) ([]datatypes.UUID, error) {
	batch, err := s.GetBatchByHash(hash)
	if err != nil {
		return nil, err
	}
	var instanceIDs []datatypes.UUID
	if err := s.db.Model(&models.MdocBatchInstance{}).
		Where("mdoc_batch_id = ?", batch.ID).
		Pluck("id", &instanceIDs).Error; err != nil {
		return nil, err
	}
	var ids []datatypes.UUID
	if len(instanceIDs) == 0 {
		return ids, nil
	}
	err = s.db.Model(&models.MdocDeviceKey{}).
		Where("mdoc_batch_instance_id IN ?", instanceIDs).
		Pluck("id", &ids).Error
	return ids, err
}

func (s *mdocStore) DeleteBatchByHash(hash string) error {
	batch, err := s.GetBatchByHash(hash)
	if err != nil {
		return err
	}
	return s.DeleteBatch(batch.ID)
}
