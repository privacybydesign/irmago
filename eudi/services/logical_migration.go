package services

import (
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"gorm.io/gorm"
)

// MigrateFlatBatchesToThreeLayer converts every legacy flat CredentialBatch into
// the #685 three-layer model: batches are grouped under a LogicalCredential by
// their #686 logical identity, each becomes a FormatBinding, and the batch's
// instances, issuer display and credential metadata are reparented onto that
// binding — preserving every instance's used flag and status state — before the
// now-childless flat batch is deleted. Each batch migrates in its own
// transaction; the count of migrated batches is returned even on error.
//
// This is destructive to the flat table, so it must run atomically with the
// read-path flip (#685 step 2b-ii): while flat batches remain the read source,
// running this would hide them. It is therefore NOT wired into startup yet.
func MigrateFlatBatchesToThreeLayer(db *gorm.DB) (migrated int, err error) {
	// Fresh installs (and a re-run after the flat table is eventually dropped)
	// have no legacy table to convert.
	if !db.Migrator().HasTable(&models.CredentialBatch{}) {
		return 0, nil
	}

	var batches []models.CredentialBatch
	if err := db.Find(&batches).Error; err != nil {
		return 0, fmt.Errorf("load flat batches: %w", err)
	}

	for i := range batches {
		if err := migrateOneBatch(db, &batches[i]); err != nil {
			return migrated, fmt.Errorf("migrate batch %s: %w", batches[i].ID, err)
		}
		migrated++
	}
	return migrated, nil
}

func migrateOneBatch(db *gorm.DB, batch *models.CredentialBatch) error {
	identity, err := LogicalIdentityFromProcessedPayload(batch.Format, batch.IssuerIdentifier, []byte(batch.ProcessedSdJwtPayload))
	if err != nil {
		return fmt.Errorf("compute identity: %w", err)
	}

	return db.Transaction(func(tx *gorm.DB) error {
		// Find or create the owning logical credential by its grouping identity.
		var logical models.LogicalCredential
		err := tx.Where("identity = ?", identity).First(&logical).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logical = models.LogicalCredential{Identity: identity, IssuerURL: batch.IssuerIdentifier}
			if err := tx.Create(&logical).Error; err != nil {
				return err
			}
		} else if err != nil {
			return err
		}

		// One binding per batch, mirroring its per-format metadata. Children are
		// reparented below, so the binding is created without them.
		binding := models.FormatBinding{
			LogicalCredentialID: logical.ID,
			Format:              batch.Format,
			TypeLabel:           batch.VerifiableCredentialType,
			ProcessedPayload:    batch.ProcessedSdJwtPayload,
			IssuedAt:            batch.IssuedAt,
			ExpiresAt:           batch.ExpiresAt,
			NotBefore:           batch.NotBefore,
			BatchSize:           batch.BatchSize,
			RemainingCount:      batch.RemainingCount,
		}
		if err := tx.Create(&binding).Error; err != nil {
			return err
		}

		// Reparent the batch's children onto the binding, preserving their state
		// (used flag, status references): credential_batch_id -> NULL,
		// format_binding_id -> binding.ID.
		for _, model := range []any{
			&models.IssuedCredentialInstance{},
			&models.IssuerMetadataDisplay{},
			&models.CredentialMetadata{},
		} {
			if err := tx.Model(model).
				Where("credential_batch_id = ?", batch.ID).
				Updates(map[string]any{
					"credential_batch_id": nil,
					"format_binding_id":   binding.ID,
				}).Error; err != nil {
				return err
			}
		}

		// Delete the now-childless flat batch.
		return tx.Delete(&models.CredentialBatch{}, "id = ?", batch.ID).Error
	})
}
