package db

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newTestVcdmStore(t *testing.T) VcdmStore {
	t.Helper()
	d, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("super-secret-key-123"))}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, d.AutoMigrate(
		&models.VcdmBatch{},
		&models.VcdmBatchInstance{},
		&models.HolderBindingKey{},
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
	))
	return NewVcdmStore(d)
}

func newVcdmBatch(hash string) *models.VcdmBatch {
	return &models.VcdmBatch{
		TypeIdentity:     "https://www.w3.org/ns/credentials/v2 VerifiableCredential ExampleCredential",
		IssuerIdentifier: "https://issuer.example.com",
		CredentialIssuer: "https://issuer.example.com",
		Format:           models.CredentialFormatSdJwtVcdm,
		Hash:             hash,
		ProcessedPayload: datatypes.JSON(`{"credentialSubject":{"given_name":"Alice"}}`),
		IssuedAt:         time.Now().UTC().Truncate(time.Second),
		BatchSize:        1,
		RemainingCount:   1,
		Instances:        []models.VcdmBatchInstance{{RawCredential: []byte("raw-sd-jwt~")}},
	}
}

func TestVcdmStore_StoreBatchReplacesTheSameCredential(t *testing.T) {
	store := newTestVcdmStore(t)
	require.NoError(t, store.StoreBatch(newVcdmBatch("hash-a")))
	other := newVcdmBatch("hash-b")
	require.NoError(t, store.StoreBatch(other))

	reissued := newVcdmBatch("hash-a")
	require.NoError(t, store.StoreBatch(reissued))

	batches, err := store.ListBatches()
	require.NoError(t, err)
	require.Len(t, batches, 2, "the re-issuance replaces the batch with its hash, and only that one")
	stored, err := store.GetBatchByHashAndFormat("hash-a", models.CredentialFormatSdJwtVcdm)
	require.NoError(t, err)
	require.Equal(t, reissued.ID, stored.ID)
}

// The batch a re-issuance replaces is deleted in the transaction that stores
// the new one, so a failed store rolls the delete back.
func TestVcdmStore_FailedReplacementKeepsTheStoredCredential(t *testing.T) {
	store := newTestVcdmStore(t)
	original := newVcdmBatch("hash-a")
	require.NoError(t, store.StoreBatch(original))

	broken := newVcdmBatch("hash-a")
	broken.Instances[0].RawCredential = nil // refused by the instance's own validation
	require.Error(t, store.StoreBatch(broken))

	stored, err := store.GetBatchByHashAndFormat("hash-a", models.CredentialFormatSdJwtVcdm)
	require.NoError(t, err, "the stored credential must survive a replacement that failed")
	require.Equal(t, original.ID, stored.ID)
}
