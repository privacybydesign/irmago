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
	return &models.CredentialBatch{
		IssuerURL:                "https://issuer.example.com",
		VerifiableCredentialType: "https://vct.example.com/MyCredential",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                 datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
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
		IssuedAt:                 datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
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

func newBatchWithInstancesAndKeys(hash string, instanceCount int) *models.CredentialBatch {
	instances := make([]models.IssuedCredentialInstance, instanceCount)
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
		IssuerURL:                "https://issuer.example.com",
		VerifiableCredentialType: "https://vct.example.com/MyCredential",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(`{"sub":"user123"}`),
		IssuedAt:                 datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                uint(instanceCount),
		RemainingCount:           uint(instanceCount),
		CredentialIssuer:         "https://issuer.example.com",
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

	require.NoError(t, store.StoreBatch(newBatch("hash-duplicate")))

	err := store.StoreBatch(newBatch("hash-duplicate"))
	require.Error(t, err)
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

// --- GetBatchesByDocType ---

func TestGetBatchesByDocType_MultipleMatches(t *testing.T) {
	store := newTestCredentialStore(t)

	for _, hash := range []string{"hash-doctype-multi-1", "hash-doctype-multi-2"} {
		batch := newBatch(hash)
		batch.Format = models.CredentialFormatMsoMdoc
		batch.VerifiableCredentialType = "eu.europa.ec.av.1"
		require.NoError(t, store.StoreBatch(batch))
	}

	batches, err := store.GetBatchesByDocType("eu.europa.ec.av.1")
	require.NoError(t, err)
	assert.Len(t, batches, 2)
}

func TestGetBatchesByDocType_NoMatch(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-doctype-nomatch")
	batch.Format = models.CredentialFormatMsoMdoc
	batch.VerifiableCredentialType = "eu.europa.ec.av.1"
	require.NoError(t, store.StoreBatch(batch))

	batches, err := store.GetBatchesByDocType("eu.europa.ec.pid.1")
	require.NoError(t, err)
	assert.Empty(t, batches)
}

// One shared table serves every credential format, distinguished only by the Format column,
// so GetBatchesByDocType has to filter on both.
func TestGetBatchesByDocType_Found(t *testing.T) {
	store := newTestCredentialStore(t)

	mdocBatch := newBatch("hash-doctype-1")
	mdocBatch.Format = models.CredentialFormatMsoMdoc
	mdocBatch.VerifiableCredentialType = "eu.europa.ec.av.1"
	require.NoError(t, store.StoreBatch(mdocBatch))

	batches, err := store.GetBatchesByDocType("eu.europa.ec.av.1")
	require.NoError(t, err)
	require.Len(t, batches, 1)
	assert.Equal(t, "hash-doctype-1", batches[0].Hash)
}

// A docType is only meaningful for mso_mdoc. Without the format filter this returned the
// SD-JWT batch too, and the mdoc DCQL handler -- which never re-checks the format -- went on
// to read an SD-JWT payload as a namespace map.
func TestGetBatchesByDocType_ExcludesOtherFormatsWithTheSameTypeString(t *testing.T) {
	store := newTestCredentialStore(t)

	const shared = "eu.europa.ec.av.1"

	mdocBatch := newBatch("hash-doctype-mdoc")
	mdocBatch.Format = models.CredentialFormatMsoMdoc
	mdocBatch.VerifiableCredentialType = shared
	require.NoError(t, store.StoreBatch(mdocBatch))

	sdJwtBatch := newBatch("hash-doctype-sdjwt")
	sdJwtBatch.Format = models.CredentialFormatSdJwtVc
	sdJwtBatch.VerifiableCredentialType = shared
	require.NoError(t, store.StoreBatch(sdJwtBatch))

	batches, err := store.GetBatchesByDocType(shared)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	assert.Equal(t, "hash-doctype-mdoc", batches[0].Hash)
	assert.Equal(t, models.CredentialFormatMsoMdoc, batches[0].Format)
}

func TestGetBatchesByDocType_EmptyDocType(t *testing.T) {
	store := newTestCredentialStore(t)

	_, err := store.GetBatchesByDocType("")
	require.Error(t, err)
}

func TestGetBatchesByDocType_FiltersCorrectly(t *testing.T) {
	store := newTestCredentialStore(t)

	batch1 := newBatch("hash-filter-1")
	batch1.Format = models.CredentialFormatMsoMdoc
	batch1.VerifiableCredentialType = "eu.europa.ec.av.1"
	batch2 := newBatch("hash-filter-2")
	batch2.Format = models.CredentialFormatMsoMdoc
	batch2.VerifiableCredentialType = "eu.europa.ec.pid.1"

	require.NoError(t, store.StoreBatch(batch1))
	require.NoError(t, store.StoreBatch(batch2))

	batches, err := store.GetBatchesByDocType("eu.europa.ec.av.1")
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

func TestGetUnusedInstance_PreloadsHolderBindingKey(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatchWithInstancesAndKeys("hash-unused-instance-key", 1)
	require.NoError(t, store.StoreBatch(batch))

	instance, err := store.GetUnusedInstance(batch.ID)
	require.NoError(t, err)
	require.NotNil(t, instance.HolderBindingKey)
	require.NotNil(t, instance.HolderBindingKey.ECDSA)
	assert.Equal(t, "P-256", instance.HolderBindingKey.ECDSA.CurveName)
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

// --- DeleteBatchByHash ---

func TestDeleteBatchByHash_Success(t *testing.T) {
	store := newTestCredentialStore(t)

	batch := newBatch("hash-delete-by-hash")
	require.NoError(t, store.StoreBatch(batch))

	require.NoError(t, store.DeleteBatchByHash("hash-delete-by-hash"))

	_, err := store.GetBatchByHash("hash-delete-by-hash")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteBatchByHash_NotFound(t *testing.T) {
	store := newTestCredentialStore(t)

	err := store.DeleteBatchByHash("nonexistent-hash")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteBatchByHash_CascadeDeletesInstances(t *testing.T) {
	store := newTestCredentialStore(t)
	db := store.(*credentialStore).db

	batch := newBatchWithInstances("hash-cascade-delete", 3)
	require.NoError(t, store.StoreBatch(batch))

	// Verify instances exist before deletion.
	var countBefore int64
	db.Model(&models.IssuedCredentialInstance{}).Where("credential_batch_id = ?", batch.ID).Count(&countBefore)
	assert.Equal(t, int64(3), countBefore)

	require.NoError(t, store.DeleteBatchByHash("hash-cascade-delete"))

	// Verify all instances are gone after deletion.
	var countAfter int64
	db.Model(&models.IssuedCredentialInstance{}).Where("credential_batch_id = ?", batch.ID).Count(&countAfter)
	assert.Equal(t, int64(0), countAfter)
}

func TestDeleteBatchByHash_CascadeDeletesHolderBindingKeys(t *testing.T) {
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
	require.NoError(t, store.DeleteBatchByHash("hash-cascade-delete-keys"))

	// Verify keys are gone.
	var keyCountAfter int64
	db.Model(&models.HolderBindingKey{}).Where("id IN ?", keyIDs).Count(&keyCountAfter)
	assert.Equal(t, int64(0), keyCountAfter)

	// Verify ECDSA metadata is gone.
	var ecdsaCountAfter int64
	db.Model(&models.ECDSAKeyMetadata{}).Where("holder_binding_key_id IN ?", keyIDs).Count(&ecdsaCountAfter)
	assert.Equal(t, int64(0), ecdsaCountAfter)
}

func TestDeleteBatchByHash_EmptyHash(t *testing.T) {
	store := newTestCredentialStore(t)

	err := store.DeleteBatchByHash("")
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

	_, err := store.GetBatchByHash("hash-delete-success")
	require.ErrorIs(t, err, ErrNotFound)
}

// TestBatchLookupsPreloadDisplayMetadata pins that every batch lookup a display
// or log path can reach eager-loads the same associations. A missing preload
// does not fail — it silently yields empty display metadata, which is how
// mdoc_dcql ended up rendering permission screens with a blank issuer name and
// unnamed attributes while the SD-JWT handler (which uses the fully-preloaded
// GetCredentialBatchList) looked fine.
func TestBatchLookupsPreloadDisplayMetadata(t *testing.T) {
	assertPreloaded := func(t *testing.T, batch *models.CredentialBatch) {
		t.Helper()
		require.NotNil(t, batch)
		assert.NotEmpty(t, batch.IssuerDisplay, "IssuerDisplay must be preloaded (issuer name/logo)")
		require.NotNil(t, batch.CredentialMetadata, "CredentialMetadata must be preloaded")
		assert.NotEmpty(t, batch.CredentialMetadata.Display, "credential display entries must be preloaded")
		require.NotEmpty(t, batch.CredentialMetadata.Claims, "claims must be preloaded (claim display names)")
		assert.NotEmpty(t, batch.CredentialMetadata.Claims[0].Display, "each claim's display entries must be preloaded")
	}

	t.Run("GetCredentialBatchList", func(t *testing.T) {
		store := newTestCredentialStore(t)
		require.NoError(t, store.StoreBatch(newBatch("hash-preload-list")))

		batches, err := store.GetCredentialBatchList()
		require.NoError(t, err)
		require.Len(t, batches, 1)
		assertPreloaded(t, batches[0])
	})

	t.Run("GetBatchByHash", func(t *testing.T) {
		store := newTestCredentialStore(t)
		require.NoError(t, store.StoreBatch(newBatch("hash-preload-byhash")))

		batch, err := store.GetBatchByHash("hash-preload-byhash")
		require.NoError(t, err)
		assertPreloaded(t, batch)
	})

	t.Run("GetBatchesByDocType", func(t *testing.T) {
		store := newTestCredentialStore(t)
		mdocBatch := newBatch("hash-preload-bydoctype")
		mdocBatch.Format = models.CredentialFormatMsoMdoc
		mdocBatch.VerifiableCredentialType = "eu.europa.ec.av.1"
		require.NoError(t, store.StoreBatch(mdocBatch))

		batches, err := store.GetBatchesByDocType("eu.europa.ec.av.1")
		require.NoError(t, err)
		require.Len(t, batches, 1)
		assertPreloaded(t, batches[0])
	})
}
