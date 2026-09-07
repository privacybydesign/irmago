package db

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newTestCredentialStore(t *testing.T) CredentialStore {
	t.Helper()

	db, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("super-secret-key-123"))}, &gorm.Config{})
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
	iss := "https://issuer.example.com"
	return &models.CredentialBatch{
		IssuerIdentifier:           iss,
		CredentialType:             "https://vct.example.com/MyCredential",
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       hash,
		ProcessedSdJwtPayload:      datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                   datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                  1,
		RemainingCount:             1,
		CredentialIssuerIdentifier: iss,
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
	iss := "https://issuer.example.com"
	for i := range instances {
		instances[i] = models.IssuedCredentialInstance{RawCredential: []byte("raw-credential-token")}
	}
	return &models.CredentialBatch{
		IssuerIdentifier:           iss,
		CredentialType:             "https://vct.example.com/MyCredential",
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       hash,
		ProcessedSdJwtPayload:      datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                   datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                  uint(instanceCount),
		RemainingCount:             uint(instanceCount),
		CredentialIssuerIdentifier: iss,
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

func newBatchWithInstancesAndKeys(hash string, instanceCount int) *models.CredentialBatch {
	instances := make([]models.IssuedCredentialInstance, instanceCount)
	iss := "https://issuer.example.com"
	for i := range instances {
		instances[i] = models.IssuedCredentialInstance{
			RawCredential: []byte("raw-credential-token"),
			HolderBindingKey: &models.HolderBindingKey{
				Algorithm:           models.KeyAlgorithmECDSA,
				PublicKeyThumbprint: datatypes.NullString{V: fmt.Sprintf("thumbprint-%s-%d", hash, i), Valid: true},
				PrivateKey:          []byte("fake-pkcs8-private-key"),
				ECDSA:               &models.ECDSAKeyMetadata{CurveName: "P-256"},
			},
		}
	}
	return &models.CredentialBatch{
		IssuerIdentifier:           iss,
		CredentialType:             "https://vct.example.com/MyCredential",
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       hash,
		ProcessedSdJwtPayload:      datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                   datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                  uint(instanceCount),
		RemainingCount:             uint(instanceCount),
		CredentialIssuerIdentifier: iss,
		IssuerDisplay: []models.IssuerMetadataDisplay{
			{Locale: datatypes.NullString{V: "en", Valid: true}, Name: "Issuer Name"},
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

	// The uniqueness key is (hash, format): a second batch with the same hash
	// AND the same format collides.
	require.NoError(t, store.StoreBatch(newBatch("hash-duplicate")))

	err := store.StoreBatch(newBatch("hash-duplicate"))
	require.Error(t, err)
}

func TestStoreBatch_SameHashDifferentFormatCoexist(t *testing.T) {
	store := newTestCredentialStore(t)

	// One logical credential held under two securing formats shares a content
	// hash but must be stored as two distinct batches.
	sdJwtVcBatch := newBatch("hash-shared")
	sdJwtVcBatch.Format = models.CredentialFormatSdJwtVc
	require.NoError(t, store.StoreBatch(sdJwtVcBatch))

	vcdmBatch := newBatch("hash-shared")
	vcdmBatch.Format = models.CredentialFormatSdJwtVcdm
	require.NoError(t, store.StoreBatch(vcdmBatch))

	// Each is retrievable by its own (hash, format), and they are distinct rows.
	gotSdJwtVc, err := store.GetBatchByHashAndFormat("hash-shared", models.CredentialFormatSdJwtVc)
	require.NoError(t, err)
	assert.Equal(t, sdJwtVcBatch.ID, gotSdJwtVc.ID)

	gotVcdm, err := store.GetBatchByHashAndFormat("hash-shared", models.CredentialFormatSdJwtVcdm)
	require.NoError(t, err)
	assert.Equal(t, vcdmBatch.ID, gotVcdm.ID)
	assert.NotEqual(t, gotSdJwtVc.ID, gotVcdm.ID)
}

func TestStoreBatch_PersistsStatusListColumns(t *testing.T) {
	store := newTestCredentialStore(t)

	uri := "https://issuer.example/sl/1"
	idx := uint64(42)
	checked := time.Now().UTC().Truncate(time.Second)
	batch := newBatch("hash-status-cols")
	batch.Instances[0].StatusListURI = &uri
	batch.Instances[0].StatusListIdx = &idx
	batch.Instances[0].LastKnownStatus = 1 // StatusValid
	batch.Instances[0].LastStatusCheckAt = &checked

	require.NoError(t, store.StoreBatch(batch))

	got, err := store.GetUnusedInstance(batch.ID)
	require.NoError(t, err)
	require.NotNil(t, got.StatusListURI)
	require.Equal(t, uri, *got.StatusListURI)
	require.NotNil(t, got.StatusListIdx)
	require.Equal(t, idx, *got.StatusListIdx)
	require.Equal(t, uint8(1), got.LastKnownStatus)
	require.NotNil(t, got.LastStatusCheckAt)
	require.WithinDuration(t, checked, got.LastStatusCheckAt.UTC(), time.Second)
}

func TestListStatusReferencedInstanceStatuses(t *testing.T) {
	store := newTestCredentialStore(t)

	uri := "https://issuer.example/sl/1"
	idx := uint64(7)
	withStatus := newBatch("hash-with-status")
	withStatus.Instances[0].StatusListURI = &uri
	withStatus.Instances[0].StatusListIdx = &idx
	withStatus.Instances[0].LastKnownStatus = 2 // StatusInvalid
	require.NoError(t, store.StoreBatch(withStatus))

	// Batch without a status reference must be excluded (status_list_uri IS NULL).
	require.NoError(t, store.StoreBatch(newBatch("hash-no-status")))

	got, err := store.ListStatusReferencedInstanceStatuses()
	require.NoError(t, err)
	require.Equal(t, []BatchInstanceStatus{{Hash: "hash-with-status", LastKnownStatus: 2}}, got)
}

func TestStoreBatch_StatusListColumnsDefaultToNil(t *testing.T) {
	store := newTestCredentialStore(t)
	batch := newBatch("hash-no-status")
	require.NoError(t, store.StoreBatch(batch))

	got, err := store.GetUnusedInstance(batch.ID)
	require.NoError(t, err)
	require.Nil(t, got.StatusListURI)
	require.Nil(t, got.StatusListIdx)
	require.Equal(t, uint8(0), got.LastKnownStatus)
	require.Nil(t, got.LastStatusCheckAt)
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
	assert.Equal(t, batch.IssuerIdentifier, got.IssuerIdentifier)
	assert.Equal(t, batch.CredentialType, got.CredentialType)
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
	assert.Equal(t, batch.CredentialIssuerIdentifier, got.CredentialIssuerIdentifier)
	assert.Greater(t, len(got.IssuerDisplay), 0)
	require.NotNil(t, got.CredentialMetadata)
	assert.Greater(t, len(got.CredentialMetadata.Display), 0)
	assert.Greater(t, len(got.CredentialMetadata.Claims), 0)
	assert.Greater(t, len(got.CredentialMetadata.Claims[0].Display), 0)
}

// --- GetBatchByHashAndFormat ---

func TestGetBatchByHashAndFormat_Found(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-get-by-hash")
	require.NoError(t, store.StoreBatch(batch))

	got, err := store.GetBatchByHashAndFormat("hash-get-by-hash", models.CredentialFormatSdJwtVc)
	require.NoError(t, err)
	assert.Equal(t, batch.ID, got.ID)
	assert.Equal(t, "hash-get-by-hash", got.Hash)
}

func TestGetBatchByHashAndFormat_NotFound(t *testing.T) {
	store := newTestCredentialStore(t)

	_, err := store.GetBatchByHashAndFormat("nonexistent-hash", models.CredentialFormatSdJwtVc)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestGetBatchByHashAndFormat_WrongFormatNotFound(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-format-mismatch") // stored under dc+sd-jwt
	require.NoError(t, store.StoreBatch(batch))

	// The same hash under a different format is a different credential.
	_, err := store.GetBatchByHashAndFormat("hash-format-mismatch", models.CredentialFormatSdJwtVcdm)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestGetBatchByHashAndFormat_EmptyHash(t *testing.T) {
	store := newTestCredentialStore(t)

	_, err := store.GetBatchByHashAndFormat("", models.CredentialFormatSdJwtVc)
	require.Error(t, err)
}

// --- GetBatchesByType ---

func TestGetBatchesByType_Found(t *testing.T) {
	store := newTestCredentialStore(t)

	require.NoError(t, store.StoreBatch(newBatch("hash-vct-1")))
	require.NoError(t, store.StoreBatch(newBatch("hash-vct-2")))

	batches, err := store.GetBatchesByType("https://vct.example.com/MyCredential")
	require.NoError(t, err)
	assert.Len(t, batches, 2)
}

func TestGetBatchesByType_NoMatch(t *testing.T) {
	store := newTestCredentialStore(t)

	require.NoError(t, store.StoreBatch(newBatch("hash-vct-nomatch")))

	batches, err := store.GetBatchesByType("https://vct.example.com/OtherCredential")
	require.NoError(t, err)
	assert.Empty(t, batches)
}

func TestGetBatchesByType_EmptyVCT(t *testing.T) {
	store := newTestCredentialStore(t)

	_, err := store.GetBatchesByType("")
	require.Error(t, err)
}

func TestGetBatchesByType_FiltersCorrectly(t *testing.T) {
	store := newTestCredentialStore(t)

	batch1 := newBatch("hash-filter-1")
	batch2 := newBatch("hash-filter-2")
	batch2.CredentialType = "https://vct.example.com/OtherCredential"

	require.NoError(t, store.StoreBatch(batch1))
	require.NoError(t, store.StoreBatch(batch2))

	batches, err := store.GetBatchesByType("https://vct.example.com/MyCredential")
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

// --- DeleteBatchByHashAndFormat ---

func TestDeleteBatchByHashAndFormat_Success(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-delete-by-hash")
	require.NoError(t, store.StoreBatch(batch))

	require.NoError(t, store.DeleteBatchByHashAndFormat("hash-delete-by-hash", models.CredentialFormatSdJwtVc))

	_, err := store.GetBatchByHashAndFormat("hash-delete-by-hash", models.CredentialFormatSdJwtVc)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteBatchByHashAndFormat_NotFound(t *testing.T) {
	store := newTestCredentialStore(t)

	err := store.DeleteBatchByHashAndFormat("nonexistent-hash", models.CredentialFormatSdJwtVc)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteBatchByHashAndFormat_CascadeDeletesInstances(t *testing.T) {
	store := newTestCredentialStore(t)
	db := store.(*credentialStore).db

	batch := newBatchWithInstances("hash-cascade-delete", 3)
	require.NoError(t, store.StoreBatch(batch))

	// Verify instances exist before deletion.
	var countBefore int64
	db.Model(&models.IssuedCredentialInstance{}).Where("credential_batch_id = ?", batch.ID).Count(&countBefore)
	assert.Equal(t, int64(3), countBefore)

	require.NoError(t, store.DeleteBatchByHashAndFormat("hash-cascade-delete", models.CredentialFormatSdJwtVc))

	// Verify all instances are gone after deletion.
	var countAfter int64
	db.Model(&models.IssuedCredentialInstance{}).Where("credential_batch_id = ?", batch.ID).Count(&countAfter)
	assert.Equal(t, int64(0), countAfter)
}

func TestDeleteBatchByHashAndFormat_CascadeDeletesHolderBindingKeys(t *testing.T) {
	store := newTestCredentialStore(t)
	db := store.(*credentialStore).db

	batch := newBatchWithInstancesAndKeys("hash-cascade-delete-keys", 2)
	require.NoError(t, store.StoreBatch(batch))

	// Collect holder binding key IDs from the stored instances.
	var keyIDs []datatypes.UUID
	for _, inst := range batch.Instances {
		require.NotNil(t, inst.HolderBindingKey)
		keyIDs = append(keyIDs, inst.HolderBindingKey.ID)
	}

	// Verify keys and ECDSA metadata exist before deletion.
	var keyCountBefore int64
	db.Model(&models.HolderBindingKey{}).Where("id IN ?", keyIDs).Count(&keyCountBefore)
	assert.Equal(t, int64(2), keyCountBefore)

	var ecdsaCountBefore int64
	db.Model(&models.ECDSAKeyMetadata{}).Where("holder_binding_key_id IN ?", keyIDs).Count(&ecdsaCountBefore)
	assert.Equal(t, int64(2), ecdsaCountBefore)

	// Delete the batch.
	require.NoError(t, store.DeleteBatchByHashAndFormat("hash-cascade-delete-keys", models.CredentialFormatSdJwtVc))

	// Verify keys are gone.
	var keyCountAfter int64
	db.Model(&models.HolderBindingKey{}).Where("id IN ?", keyIDs).Count(&keyCountAfter)
	assert.Equal(t, int64(0), keyCountAfter)

	// Verify ECDSA metadata is gone.
	var ecdsaCountAfter int64
	db.Model(&models.ECDSAKeyMetadata{}).Where("holder_binding_key_id IN ?", keyIDs).Count(&ecdsaCountAfter)
	assert.Equal(t, int64(0), ecdsaCountAfter)
}

func TestDeleteBatchByHashAndFormat_EmptyHash(t *testing.T) {
	store := newTestCredentialStore(t)

	err := store.DeleteBatchByHashAndFormat("", models.CredentialFormatSdJwtVc)
	require.Error(t, err)
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

	_, err := store.GetBatchByHashAndFormat("hash-delete-success", models.CredentialFormatSdJwtVc)
	require.ErrorIs(t, err, ErrNotFound)
}
