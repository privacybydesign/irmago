package services

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// storeAsBinding stores a flat-shaped test CredentialBatch through the three-layer
// write path (StoreFormatBinding), so services tests can keep building flat
// batches while the store persists the three-layer model that reads project back.
// The assigned binding/instance IDs are reflected back onto the batch.
func storeAsBinding(t *testing.T, store db.CredentialStore, batch *models.CredentialBatch) error {
	t.Helper()
	binding := &models.FormatBinding{
		Format:                     batch.Format,
		TypeLabel:                  batch.VerifiableCredentialType,
		Hash:                       batch.Hash,
		CredentialIssuerIdentifier: batch.CredentialIssuerIdentifier,
		ProcessedPayload:           batch.ProcessedSdJwtPayload,
		IssuedAt:                   batch.IssuedAt,
		ExpiresAt:                  batch.ExpiresAt,
		NotBefore:                  batch.NotBefore,
		BatchSize:                  batch.BatchSize,
		RemainingCount:             batch.RemainingCount,
		Instances:                  batch.Instances,
		IssuerDisplay:              batch.IssuerDisplay,
		CredentialMetadata:         batch.CredentialMetadata,
	}
	issuer := batch.IssuerIdentifier
	if issuer == "" {
		issuer = "https://issuer.example.com"
	}
	if err := store.StoreFormatBinding(batch.Hash, issuer, binding); err != nil {
		return err
	}
	batch.ID = binding.ID
	batch.Instances = binding.Instances
	return nil
}

// newTestHolderDB opens an in-memory holder database with every model migrated.
//
// One list, because three copies of it meant that adding a model to the schema
// had to be remembered in three places, and forgetting one surfaces as an
// opaque "no such table" in an unrelated test. Migrating a table a given test
// never touches costs nothing.
func newTestHolderDB(t *testing.T) *gorm.DB {
	t.Helper()
	d, err := gorm.Open(
		sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("test-key-123"))},
		&gorm.Config{},
	)
	require.NoError(t, err)
	require.NoError(t, d.AutoMigrate(
		&models.HolderBindingKey{},
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
		&models.IssuerMetadataDisplay{},
		&models.CredentialMetadata{},
		&models.CredentialDisplay{},
		&models.CredentialClaim{},
		&models.ClaimDisplay{},
		&models.CredentialBatch{},
		&models.IssuedCredentialInstance{},
		&models.LogicalCredential{},
		&models.FormatBinding{},
		&models.StatusListCacheEntry{},
		&models.EudiLogEntry{},
		&models.EudiLogCredential{},
	))
	return d
}
