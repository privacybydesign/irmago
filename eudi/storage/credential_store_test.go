package storage

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/privacybydesign/irmago/eudi/storage/models"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newTestCredentialStore(t *testing.T) CredentialStore {
	t.Helper()

	const passphrase = "super-secret-key-123"
	dsn := sqlcipher.DSN(":memory:", passphrase)
	db, err := gorm.Open(sqlcipher.Dialector{DSN: dsn}, &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(
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
	)
	require.NoError(t, err)

	return &credentialStore{db: db}
}

func newBatch(hash string) *models.CredentialBatch {
	return &models.CredentialBatch{
		IssuerURL:                "https://issuer.example.com",
		VerifiableCredentialType: "https://vct.example.com/MyCredential",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                 time.Now().UTC().Truncate(time.Second),
		BatchSize:                1,
		RemainingCount:           1,
		CredentialIssuer:         "https://issuer.example.com",
		IssuerDisplay: []models.IssuerMetadataDisplay{
			models.IssuerMetadataDisplay{
				Locale: datatypes.NullString{V: "nl", Valid: true},
				Name:   "Issuer Name",
			},
			models.IssuerMetadataDisplay{
				Locale: datatypes.NullString{V: "en", Valid: true},
				Name:   "Issuer Name",
			},
		},
		CredentialMetadata: &models.CredentialMetadata{
			Display: []models.CredentialDisplay{
				models.CredentialDisplay{
					Locale: datatypes.NullString{V: "nl", Valid: true},
					Name:   "Credential Name",
				},
			},
			Claims: []models.CredentialClaim{
				models.CredentialClaim{
					Path:      datatypes.JSON(`["a", "b", "c"]`),
					Mandatory: false,
					Display: []models.ClaimDisplay{
						models.ClaimDisplay{
							Name:   "Claim Name",
							Locale: datatypes.NullString{V: "nl", Valid: true},
						},
						models.ClaimDisplay{
							Name:   "Claim Name",
							Locale: datatypes.NullString{V: "en", Valid: true},
						},
					},
				},
				models.CredentialClaim{
					Path:      datatypes.JSON(`["x", "y", "z"]`),
					Mandatory: true,
					Display: []models.ClaimDisplay{
						models.ClaimDisplay{
							Name:   "Claim Name",
							Locale: datatypes.NullString{V: "nl", Valid: true},
						},
						models.ClaimDisplay{
							Name:   "Claim Name",
							Locale: datatypes.NullString{V: "en", Valid: true},
						},
					},
				},
			},
		},
		Instances: []models.IssuedCredentialInstance{
			{RawCredential: []byte("raw-credential-token")},
		},
	}
}

func newBatchWithInstances(hash string, instanceCount int) *models.CredentialBatch {
	instances := make([]models.IssuedCredentialInstance, instanceCount)
	for i := range instances {
		instances[i] = models.IssuedCredentialInstance{RawCredential: []byte("raw-credential-token")}
	}
	return &models.CredentialBatch{
		IssuerURL:                "https://issuer.example.com",
		VerifiableCredentialType: "https://vct.example.com/MyCredential",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                 time.Now().UTC().Truncate(time.Second),
		BatchSize:                uint(instanceCount),
		RemainingCount:           uint(instanceCount),
		CredentialIssuer:         "https://issuer.example.com",
		IssuerDisplay: []models.IssuerMetadataDisplay{
			models.IssuerMetadataDisplay{
				Locale: datatypes.NullString{V: "nl", Valid: true},
				Name:   "Issuer Name",
			},
			models.IssuerMetadataDisplay{
				Locale: datatypes.NullString{V: "en", Valid: true},
				Name:   "Issuer Name",
			},
		},
		Instances: instances,
	}
}

// --- StoreBatch ---

func TestStoreBatch_Success(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-store-success")
	err := store.StoreBatch(batch)
	require.NoError(t, err)
	assert.NotZero(t, batch.ID)
}

func TestStoreBatch_AssignsInstanceIDs(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-instance-ids")
	require.NoError(t, store.StoreBatch(batch))

	for _, inst := range batch.Instances {
		assert.NotEqual(t, uuid.Nil, inst.ID)
	}
}

func TestStoreBatch_NilBatch(t *testing.T) {
	store := newTestCredentialStore(t)

	err := store.StoreBatch(nil)
	require.Error(t, err)
}

func TestStoreBatch_EmptyInstances(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-empty-instances")
	batch.Instances = nil

	err := store.StoreBatch(batch)
	require.Error(t, err)
}

func TestStoreBatch_UniqueHashConstraint(t *testing.T) {
	store := newTestCredentialStore(t)

	require.NoError(t, store.StoreBatch(newBatch("hash-duplicate")))

	err := store.StoreBatch(newBatch("hash-duplicate"))
	require.Error(t, err)
}

func TestStoreBatch_MultipleInstances(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatchWithInstances("hash-multi", 3)
	require.NoError(t, store.StoreBatch(batch))
	assert.Len(t, batch.Instances, 3)
}

// --- GetCredentialBatchList ---

func TestGetCredentialBatchList_Empty(t *testing.T) {
	store := newTestCredentialStore(t)

	batches, err := store.GetCredentialBatchList()
	require.NoError(t, err)
	assert.Empty(t, batches)
}

func TestGetCredentialBatchList_ReturnsBatches(t *testing.T) {
	store := newTestCredentialStore(t)

	require.NoError(t, store.StoreBatch(newBatch("hash-list-1")))
	require.NoError(t, store.StoreBatch(newBatch("hash-list-2")))

	batches, err := store.GetCredentialBatchList()
	require.NoError(t, err)
	assert.Len(t, batches, 2)
}

func TestGetCredentialBatchList_ContainsBatchFields(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-fields-check")
	require.NoError(t, store.StoreBatch(batch))

	batches, err := store.GetCredentialBatchList()
	require.NoError(t, err)
	require.Len(t, batches, 1)

	got := batches[0]
	assert.Equal(t, batch.IssuerURL, got.IssuerURL)
	assert.Equal(t, batch.VerifiableCredentialType, got.VerifiableCredentialType)
	assert.Equal(t, batch.Hash, got.Hash)
	assert.Equal(t, batch.Format, got.Format)
}

func TestGetCredentialBatchList_ContainsIssuerAndCredentialMetadataDisplays(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-fields-check")
	require.NoError(t, store.StoreBatch(batch))

	batches, err := store.GetCredentialBatchList()
	require.NoError(t, err)
	require.Len(t, batches, 1)

	got := batches[0]
	assert.Equal(t, batch.CredentialIssuer, got.CredentialIssuer)
	assert.Greater(t, len(got.IssuerDisplay), 0)
	require.NotNil(t, got.CredentialMetadata)
	assert.Greater(t, len(got.CredentialMetadata.Display), 0)
	assert.Greater(t, len(got.CredentialMetadata.Claims), 0)
	assert.Greater(t, len(got.CredentialMetadata.Claims[0].Display), 0)
}

// --- GetBatchByHash ---

func TestGetBatchByHash_Found(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-get-by-hash")
	require.NoError(t, store.StoreBatch(batch))

	got, err := store.GetBatchByHash("hash-get-by-hash")
	require.NoError(t, err)
	assert.Equal(t, batch.ID, got.ID)
	assert.Equal(t, "hash-get-by-hash", got.Hash)
}

func TestGetBatchByHash_NotFound(t *testing.T) {
	store := newTestCredentialStore(t)

	_, err := store.GetBatchByHash("nonexistent-hash")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestGetBatchByHash_EmptyHash(t *testing.T) {
	store := newTestCredentialStore(t)

	_, err := store.GetBatchByHash("")
	require.Error(t, err)
}

// --- GetBatchesByVCT ---

func TestGetBatchesByVCT_Found(t *testing.T) {
	store := newTestCredentialStore(t)

	require.NoError(t, store.StoreBatch(newBatch("hash-vct-1")))
	require.NoError(t, store.StoreBatch(newBatch("hash-vct-2")))

	batches, err := store.GetBatchesByVCT("https://vct.example.com/MyCredential")
	require.NoError(t, err)
	assert.Len(t, batches, 2)
}

func TestGetBatchesByVCT_NoMatch(t *testing.T) {
	store := newTestCredentialStore(t)

	require.NoError(t, store.StoreBatch(newBatch("hash-vct-nomatch")))

	batches, err := store.GetBatchesByVCT("https://vct.example.com/OtherCredential")
	require.NoError(t, err)
	assert.Empty(t, batches)
}

func TestGetBatchesByVCT_EmptyVCT(t *testing.T) {
	store := newTestCredentialStore(t)

	_, err := store.GetBatchesByVCT("")
	require.Error(t, err)
}

func TestGetBatchesByVCT_FiltersCorrectly(t *testing.T) {
	store := newTestCredentialStore(t)

	batch1 := newBatch("hash-filter-1")
	batch2 := newBatch("hash-filter-2")
	batch2.VerifiableCredentialType = "https://vct.example.com/OtherCredential"

	require.NoError(t, store.StoreBatch(batch1))
	require.NoError(t, store.StoreBatch(batch2))

	batches, err := store.GetBatchesByVCT("https://vct.example.com/MyCredential")
	require.NoError(t, err)
	require.Len(t, batches, 1)
	assert.Equal(t, batch1.Hash, batches[0].Hash)
}

// --- GetUnusedInstance ---

func TestGetUnusedInstance_ZeroBatchID(t *testing.T) {
	store := newTestCredentialStore(t)

	_, err := store.GetUnusedInstance(datatypes.UUID(datatypes.NewNilBinUUID()))
	require.Error(t, err)
}

func TestGetUnusedInstance_NotFound(t *testing.T) {
	store := newTestCredentialStore(t)

	_, err := store.GetUnusedInstance(datatypes.NewUUIDv4())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestGetUnusedInstance_ReturnsUnusedInstance(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-unused-instance")
	require.NoError(t, store.StoreBatch(batch))

	instance, err := store.GetUnusedInstance(batch.ID)
	require.NoError(t, err)
	assert.False(t, instance.Used)
}

// --- MarkInstanceUsed ---

func TestMarkInstanceUsed_NilInstanceID(t *testing.T) {
	store := newTestCredentialStore(t)

	err := store.MarkInstanceUsed(datatypes.UUID(datatypes.NewNilBinUUID()))
	require.Error(t, err)
}

func TestMarkInstanceUsed_NotFound(t *testing.T) {
	store := newTestCredentialStore(t)

	err := store.MarkInstanceUsed(datatypes.NewUUIDv4())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestMarkInstanceUsed_SetsUsedTrue(t *testing.T) {
	store := newTestCredentialStore(t)
	db := store.(*credentialStore).db

	batch := newBatch("hash-mark-used")
	require.NoError(t, store.StoreBatch(batch))

	instanceID := batch.Instances[0].ID
	require.NoError(t, store.MarkInstanceUsed(instanceID))

	var instance models.IssuedCredentialInstance
	require.NoError(t, db.First(&instance, "id = ?", instanceID).Error)
	assert.True(t, instance.Used)
}

func TestMarkInstanceUsed_DecrementsRemainingCount(t *testing.T) {
	store := newTestCredentialStore(t)
	db := store.(*credentialStore).db

	batch := newBatchWithInstances("hash-decrement", 2)
	require.NoError(t, store.StoreBatch(batch))

	instanceID := batch.Instances[0].ID
	require.NoError(t, store.MarkInstanceUsed(instanceID))

	var updated models.CredentialBatch
	require.NoError(t, db.First(&updated, batch.ID).Error)
	assert.Equal(t, uint(1), updated.RemainingCount)
}

func TestMarkInstanceUsed_AlreadyUsed_ReturnsNotFound(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-already-used")
	require.NoError(t, store.StoreBatch(batch))

	instanceID := batch.Instances[0].ID
	require.NoError(t, store.MarkInstanceUsed(instanceID))

	err := store.MarkInstanceUsed(instanceID)
	require.ErrorIs(t, err, ErrNotFound)
}

// --- DeleteBatch ---

func TestDeleteBatch_ZeroBatchID(t *testing.T) {
	store := newTestCredentialStore(t)

	err := store.DeleteBatch(datatypes.UUID(datatypes.NewNilBinUUID()))
	require.Error(t, err)
}

func TestDeleteBatch_NotFound(t *testing.T) {
	store := newTestCredentialStore(t)

	err := store.DeleteBatch(datatypes.NewUUIDv4())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteBatch_Success(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-delete-success")
	require.NoError(t, store.StoreBatch(batch))

	require.NoError(t, store.DeleteBatch(batch.ID))

	_, err := store.GetBatchByHash("hash-delete-success")
	require.ErrorIs(t, err, ErrNotFound)
}
