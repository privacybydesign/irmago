package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// CredentialStatusInstance is an instance's status_list reference.
// BatchID lets callers select a single representative instance per batch, and
// LastKnownStatus lets them tell a status change from a re-confirmation without
// a second read. In the three-layer model BatchID is the owning FormatBinding's
// ID (which the read projection also exposes as CredentialBatch.ID).
type CredentialStatusInstance struct {
	InstanceID      datatypes.UUID
	BatchID         datatypes.UUID
	StatusListURI   string
	StatusListIdx   uint64
	LastKnownStatus uint8
}

// BatchInstanceStatus pairs a credential's deterministic hash with one of its
// instances' last-known Token Status List status. Only instances that carry
// a status_list reference are reported.
type BatchInstanceStatus struct {
	Hash            string
	LastKnownStatus uint8
}

// CredentialStore is the public interface for inserting and retrieving issued credentials.
//
// Storage is the three-layer model (#685): a LogicalCredential owner groups one
// FormatBinding per securing format, each owning its IssuedCredentialInstances.
// The read methods return the flat CredentialBatch shape as a *projection* of a
// FormatBinding (one batch per binding), so the credential-list, DCQL and status
// consumers keep their existing shape; CredentialBatch is no longer a stored
// table on the write path.
type CredentialStore interface {
	// StoreFormatBinding upserts the three-layer model: it finds or creates the
	// LogicalCredential identified by `identity` (the #686 grouping key), replaces
	// any existing FormatBinding for the same (logical credential, format) —
	// cascading away that binding's old instances and display children — and
	// inserts `binding` with its instances and display, all in one transaction.
	// binding.Instances must be non-empty. Re-issuing a credential in a format it
	// already has replaces that one binding while leaving the logical credential
	// and its other formats intact.
	StoreFormatBinding(identity, issuerURL string, binding *models.FormatBinding) error

	// GetCredentialBatchList returns every stored credential as a flat-shaped
	// projection of its FormatBinding, with display metadata preloaded but without
	// instances.
	GetCredentialBatchList() ([]*models.CredentialBatch, error)

	// GetBatchByHash retrieves a credential (projected from its FormatBinding) by
	// its deterministic hash. Returns ErrNotFound if no match exists.
	GetBatchByHash(hash string) (*models.CredentialBatch, error)

	// GetBatchesByVCT returns every credential whose per-format type label matches
	// the given vct string, projected from its FormatBinding. Does not preload
	// instances.
	GetBatchesByVCT(vct string) ([]*models.CredentialBatch, error)

	// GetUnusedInstance returns one not-yet-used IssuedCredentialInstance of the
	// given FormatBinding (addressed by the projected CredentialBatch.ID). Returns
	// ErrNotFound if all instances are used.
	GetUnusedInstance(batchID datatypes.UUID) (*models.IssuedCredentialInstance, error)

	// MarkInstanceUsed sets Used = true on the given instance and decrements
	// RemainingCount on its owning FormatBinding. Both updates run in the same
	// statement group; callers should wrap the call in a UnitOfWork.Do transaction
	// to keep them atomic.
	MarkInstanceUsed(instanceID datatypes.UUID) error

	// DeleteBatch deletes a FormatBinding and all its instances (via CASCADE),
	// addressed by the projected CredentialBatch.ID, and removes the owning
	// LogicalCredential when that was its last format.
	DeleteBatch(batchID datatypes.UUID) error

	// DeleteBatchByHash looks up a FormatBinding by its deterministic hash and
	// deletes it (see DeleteBatch). Returns ErrNotFound if no match exists.
	DeleteBatchByHash(hash string) error

	// ListInstancesWithStatusReference returns every IssuedCredentialInstance
	// with a (status_list.uri, status_list.idx) pair, along with the status the
	// wallet last recorded for it.
	ListInstancesWithStatusReference() ([]CredentialStatusInstance, error)

	// ListStatusReferencedInstanceStatuses returns the (credential hash,
	// last_known_status) pair for every instance carrying a Token Status List
	// reference. Used to surface per-credential revocation in the credential
	// list without loading full instances.
	ListStatusReferencedInstanceStatuses() ([]BatchInstanceStatus, error)

	// UpdateInstanceStatus writes last_known_status and last_status_check_at
	// on a single IssuedCredentialInstance. Returns ErrNotFound on no match.
	UpdateInstanceStatus(instanceID datatypes.UUID, status uint8, checkedAt time.Time) error
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

// projectBinding maps a three-layer FormatBinding (with its LogicalCredential and
// display children loaded) back to the flat CredentialBatch shape the read
// consumers and the wallet client still expect. The projection is read-only: its
// ID is the binding's ID, so instance lookups (GetUnusedInstance) and use-marking
// (MarkInstanceUsed) address the binding; Hash stays the per-credential id.
func projectBinding(fb *models.FormatBinding) *models.CredentialBatch {
	batch := &models.CredentialBatch{
		ID:                         fb.ID,
		VerifiableCredentialType:   fb.TypeLabel,
		Format:                     fb.Format,
		Hash:                       fb.Hash,
		CredentialIssuerIdentifier: fb.CredentialIssuerIdentifier,
		ProcessedSdJwtPayload:      fb.ProcessedPayload,
		IssuedAt:                   fb.IssuedAt,
		ExpiresAt:                  fb.ExpiresAt,
		NotBefore:                  fb.NotBefore,
		BatchSize:                  fb.BatchSize,
		RemainingCount:             fb.RemainingCount,
		IssuerDisplay:              fb.IssuerDisplay,
		CredentialMetadata:         fb.CredentialMetadata,
	}
	if fb.LogicalCredential != nil {
		batch.IssuerIdentifier = fb.LogicalCredential.IssuerURL
	}
	return batch
}

func (s *credentialStore) GetCredentialBatchList() ([]*models.CredentialBatch, error) {
	var bindings []*models.FormatBinding
	err := s.db.
		Preload("LogicalCredential").
		Preload("IssuerDisplay").
		Preload("CredentialMetadata").
		Preload("CredentialMetadata.Display").
		Preload("CredentialMetadata.Claims").
		Preload("CredentialMetadata.Claims.Display").
		Find(&bindings).Error
	if err != nil {
		return nil, err
	}

	batches := make([]*models.CredentialBatch, len(bindings))
	for i, fb := range bindings {
		batches[i] = projectBinding(fb)
	}
	return batches, nil
}

func (s *credentialStore) StoreFormatBinding(identity, issuerURL string, binding *models.FormatBinding) error {
	if binding == nil {
		return fmt.Errorf("binding is nil")
	}
	if identity == "" {
		return fmt.Errorf("identity is required")
	}
	if len(binding.Instances) == 0 {
		return fmt.Errorf("binding must contain at least one credential instance")
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		// Find or create the owning logical credential by its grouping identity.
		var logical models.LogicalCredential
		err := tx.Where("identity = ?", identity).First(&logical).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			logical = models.LogicalCredential{Identity: identity, IssuerURL: issuerURL}
			if err := tx.Create(&logical).Error; err != nil {
				return err
			}
		case err != nil:
			return err
		}

		// Replace any existing binding for this (logical credential, format); its
		// instances and display children cascade away (PRAGMA foreign_keys=ON).
		if err := tx.
			Where("logical_credential_id = ? AND format = ?", logical.ID, binding.Format).
			Delete(&models.FormatBinding{}).Error; err != nil {
			return err
		}

		binding.LogicalCredentialID = logical.ID
		binding.LogicalCredential = nil // FK is set; don't upsert the owner again
		return tx.Create(binding).Error
	})
}

func (s *credentialStore) GetBatchByHash(hash string) (*models.CredentialBatch, error) {
	if hash == "" {
		return nil, fmt.Errorf("hash is required")
	}

	var fb models.FormatBinding
	err := s.db.Preload("LogicalCredential").First(&fb, "hash = ?", hash).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return projectBinding(&fb), nil
}

func (s *credentialStore) GetBatchesByVCT(vct string) ([]*models.CredentialBatch, error) {
	if vct == "" {
		return nil, fmt.Errorf("vct is required")
	}

	var bindings []*models.FormatBinding
	err := s.db.
		Preload("LogicalCredential").
		Preload("CredentialMetadata").
		Preload("CredentialMetadata.Display").
		Where("type_label = ?", vct).
		Find(&bindings).Error
	if err != nil {
		return nil, err
	}

	batches := make([]*models.CredentialBatch, len(bindings))
	for i, fb := range bindings {
		batches[i] = projectBinding(fb)
	}
	return batches, nil
}

func (s *credentialStore) GetUnusedInstance(batchID datatypes.UUID) (*models.IssuedCredentialInstance, error) {
	if batchID.IsNil() {
		return nil, fmt.Errorf("batchID is required")
	}

	var instance models.IssuedCredentialInstance
	err := s.db.
		Where("format_binding_id = ? AND used = ?", batchID, false).
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

	// Decrement RemainingCount on the owning FormatBinding, guarded by a floor of
	// zero. This runs as a separate statement; wrap both calls in a UnitOfWork.Do
	// transaction to keep them atomic.
	return s.db.Model(&models.FormatBinding{}).
		Where("id = (SELECT format_binding_id FROM issued_credential_instances WHERE id = ?) AND remaining_count > 0", instanceID).
		UpdateColumn("remaining_count", gorm.Expr("remaining_count - 1")).
		Error
}

func (s *credentialStore) DeleteBatchByHash(hash string) error {
	var fb models.FormatBinding
	err := s.db.First(&fb, "hash = ?", hash).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	return s.DeleteBatch(fb.ID)
}

func (s *credentialStore) DeleteBatch(batchID datatypes.UUID) error {
	if batchID.IsNil() {
		return fmt.Errorf("batchID is required")
	}

	return s.db.Transaction(func(tx *gorm.DB) error {
		var fb models.FormatBinding
		if err := tx.First(&fb, "id = ?", batchID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		logicalID := fb.LogicalCredentialID

		// Delete the binding; its instances and display cascade (foreign_keys=ON).
		if err := tx.Delete(&models.FormatBinding{}, "id = ?", batchID).Error; err != nil {
			return err
		}

		// Drop the owning logical credential if this was its last format.
		var remaining int64
		if err := tx.Model(&models.FormatBinding{}).
			Where("logical_credential_id = ?", logicalID).
			Count(&remaining).Error; err != nil {
			return err
		}
		if remaining == 0 {
			return tx.Delete(&models.LogicalCredential{}, "id = ?", logicalID).Error
		}
		return nil
	})
}

func (s *credentialStore) ListInstancesWithStatusReference() ([]CredentialStatusInstance, error) {
	var out []CredentialStatusInstance
	err := s.db.
		Model(&models.IssuedCredentialInstance{}).
		Select("id AS instance_id, " +
			"format_binding_id AS batch_id, " +
			"status_list_uri AS status_list_uri, " +
			"status_list_idx AS status_list_idx, " +
			"last_known_status AS last_known_status").
		Where("status_list_uri IS NOT NULL AND status_list_idx IS NOT NULL").
		Scan(&out).Error
	return out, err
}

func (s *credentialStore) ListStatusReferencedInstanceStatuses() ([]BatchInstanceStatus, error) {
	var out []BatchInstanceStatus
	err := s.db.
		Model(&models.IssuedCredentialInstance{}).
		Select("format_bindings.hash AS hash, " +
			"issued_credential_instances.last_known_status AS last_known_status").
		Joins("JOIN format_bindings ON format_bindings.id = issued_credential_instances.format_binding_id").
		Where("issued_credential_instances.status_list_uri IS NOT NULL").
		Scan(&out).Error
	return out, err
}

func (s *credentialStore) UpdateInstanceStatus(instanceID datatypes.UUID, status uint8, checkedAt time.Time) error {
	if instanceID.IsNil() {
		return fmt.Errorf("instanceID is required")
	}
	res := s.db.Model(&models.IssuedCredentialInstance{}).
		Where("id = ?", instanceID).
		Updates(map[string]any{
			"last_known_status":    status,
			"last_status_check_at": checkedAt,
		})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
