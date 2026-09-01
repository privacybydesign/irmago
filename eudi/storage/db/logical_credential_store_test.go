package db

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// newThreeLayerTestDB opens an in-memory encrypted DB and migrates the flat
// model plus the #685 three-layer models (LogicalCredential / FormatBinding),
// exercising them through the same sqlcipher path the app uses.
func newThreeLayerTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("super-secret-key-123"))}, &gorm.Config{})
	require.NoError(t, err)

	require.NoError(t, db.AutoMigrate(
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
	))
	return db
}

// TestLogicalCredential_ThreeLayerGraph_PersistsReloadsAndCascades exercises the
// #685 three-layer model end-to-end through GORM + sqlcipher: a LogicalCredential
// owning a FormatBinding that owns reparented instances and display children,
// each attached via the nullable FormatBindingID FK (credential_batch_id NULL).
func TestLogicalCredential_ThreeLayerGraph_PersistsReloadsAndCascades(t *testing.T) {
	db := newThreeLayerTestDB(t)

	lc := &models.LogicalCredential{
		Identity:  "identity-abc",
		IssuerURL: "https://issuer.example.com",
		FormatBindings: []models.FormatBinding{
			{
				Format:           models.CredentialFormatSdJwtVcdm,
				TypeLabel:        "https://www.w3.org/ns/credentials/v2|AcademicBaseCredential",
				ProcessedPayload: datatypes.JSON(`{"hello":"world"}`),
				BatchSize:        2,
				RemainingCount:   2,
				Instances: []models.IssuedCredentialInstance{
					{RawCredential: []byte("raw-1")},
					{RawCredential: []byte("raw-2")},
				},
				IssuerDisplay: []models.IssuerMetadataDisplay{
					{Name: "Example University"},
				},
				CredentialMetadata: &models.CredentialMetadata{},
			},
		},
	}
	require.NoError(t, db.Create(lc).Error)

	var loaded models.LogicalCredential
	require.NoError(t, db.
		Preload("FormatBindings.Instances").
		Preload("FormatBindings.IssuerDisplay").
		Preload("FormatBindings.CredentialMetadata").
		First(&loaded, "identity = ?", "identity-abc").Error)

	require.Len(t, loaded.FormatBindings, 1)
	fb := loaded.FormatBindings[0]
	assert.Equal(t, loaded.ID, fb.LogicalCredentialID, "binding FK points at owner")
	require.Len(t, fb.Instances, 2)
	require.Len(t, fb.IssuerDisplay, 1)
	require.NotNil(t, fb.CredentialMetadata)

	// Reparented children carry FormatBindingID and a NULL CredentialBatchID.
	for _, inst := range fb.Instances {
		require.NotNil(t, inst.FormatBindingID)
		assert.Equal(t, fb.ID, *inst.FormatBindingID)
		assert.Nil(t, inst.CredentialBatchID, "reparented instance has no batch parent")
	}
	require.NotNil(t, fb.IssuerDisplay[0].FormatBindingID)
	assert.Equal(t, fb.ID, *fb.IssuerDisplay[0].FormatBindingID)
	require.NotNil(t, fb.CredentialMetadata.FormatBindingID)
	assert.Equal(t, fb.ID, *fb.CredentialMetadata.FormatBindingID)
	assert.Nil(t, fb.CredentialMetadata.CredentialBatchID)

	// Deleting the owner row cascades through the FK graph (PRAGMA foreign_keys=ON).
	require.NoError(t, db.Delete(&models.LogicalCredential{}, "id = ?", loaded.ID).Error)

	var bindingCount, instanceCount int64
	require.NoError(t, db.Model(&models.FormatBinding{}).Count(&bindingCount).Error)
	require.NoError(t, db.Model(&models.IssuedCredentialInstance{}).Count(&instanceCount).Error)
	assert.Equal(t, int64(0), bindingCount, "format bindings cascade-deleted with the logical credential")
	assert.Equal(t, int64(0), instanceCount, "instances cascade-deleted with the format binding")
}

// TestFormatBinding_UniquePerLogicalAndFormat verifies the composite unique index
// (LogicalCredentialID, Format): one binding per format under a logical credential,
// while a different format under the same owner is allowed.
func TestFormatBinding_UniquePerLogicalAndFormat(t *testing.T) {
	db := newThreeLayerTestDB(t)

	lc := &models.LogicalCredential{Identity: "identity-dup", IssuerURL: "https://issuer.example.com"}
	require.NoError(t, db.Create(lc).Error)

	mk := func() *models.FormatBinding {
		return &models.FormatBinding{
			LogicalCredentialID: lc.ID,
			Format:              models.CredentialFormatSdJwtVc,
			ProcessedPayload:    datatypes.JSON(`{}`),
			BatchSize:           1,
			RemainingCount:      1,
		}
	}
	require.NoError(t, db.Create(mk()).Error)
	require.Error(t, db.Create(mk()).Error, "second binding with the same (logical, format) violates the unique index")

	other := mk()
	other.Format = models.CredentialFormatSdJwtVcdm
	require.NoError(t, db.Create(other).Error, "a different format under the same logical credential is allowed")
}

// TestStoreFormatBinding_UpsertsLogicalAndReplacesBinding covers the store-side
// upsert the service rewire (#685 step 2b) will call: find-or-create the logical
// credential by identity, replace an existing binding for the same format
// (cascading its old instances), and group a second format under the same owner.
func TestStoreFormatBinding_UpsertsLogicalAndReplacesBinding(t *testing.T) {
	store := &credentialStore{db: newThreeLayerTestDB(t)}
	db := store.db

	mkBinding := func(format models.CredentialFormat, payload, raw string) *models.FormatBinding {
		return &models.FormatBinding{
			Format:           format,
			TypeLabel:        "label",
			ProcessedPayload: datatypes.JSON(payload),
			BatchSize:        1,
			RemainingCount:   1,
			Instances:        []models.IssuedCredentialInstance{{RawCredential: []byte(raw)}},
		}
	}

	// First store: creates the logical credential and one binding.
	require.NoError(t, store.StoreFormatBinding("id-x", "https://issuer", mkBinding(models.CredentialFormatSdJwtVcdm, `{"v":1}`, "raw-1")))

	var logicals []models.LogicalCredential
	require.NoError(t, db.Find(&logicals).Error)
	require.Len(t, logicals, 1)
	assert.Equal(t, "id-x", logicals[0].Identity)
	assert.Equal(t, "https://issuer", logicals[0].IssuerURL)

	// Re-store the same (identity, format) with new content: the logical
	// credential is reused, the binding replaced, and old instances cascade away.
	require.NoError(t, store.StoreFormatBinding("id-x", "https://issuer", mkBinding(models.CredentialFormatSdJwtVcdm, `{"v":2}`, "raw-2")))

	require.NoError(t, db.Find(&logicals).Error)
	require.Len(t, logicals, 1, "logical credential reused, not duplicated")

	var bindings []models.FormatBinding
	require.NoError(t, db.Find(&bindings).Error)
	require.Len(t, bindings, 1, "binding replaced, not duplicated")
	assert.JSONEq(t, `{"v":2}`, string(bindings[0].ProcessedPayload))

	var instances []models.IssuedCredentialInstance
	require.NoError(t, db.Find(&instances).Error)
	require.Len(t, instances, 1, "old instance cascade-deleted on replace")
	assert.Equal(t, []byte("raw-2"), instances[0].RawCredential)

	// A different format under the same identity groups under the same owner.
	require.NoError(t, store.StoreFormatBinding("id-x", "https://issuer", mkBinding(models.CredentialFormatSdJwtVc, `{"v":3}`, "raw-3")))

	require.NoError(t, db.Find(&logicals).Error)
	require.Len(t, logicals, 1, "still one logical credential across two formats")
	require.NoError(t, db.Find(&bindings).Error)
	require.Len(t, bindings, 2, "two format bindings under one logical credential")
}

func TestStoreFormatBinding_Guards(t *testing.T) {
	store := &credentialStore{db: newThreeLayerTestDB(t)}
	withInstance := func() *models.FormatBinding {
		return &models.FormatBinding{
			Format:           models.CredentialFormatSdJwtVc,
			ProcessedPayload: datatypes.JSON("{}"),
			BatchSize:        1,
			RemainingCount:   1,
			Instances:        []models.IssuedCredentialInstance{{RawCredential: []byte("r")}},
		}
	}
	require.Error(t, store.StoreFormatBinding("id", "iss", nil), "nil binding")
	require.Error(t, store.StoreFormatBinding("", "iss", withInstance()), "empty identity")

	noInstances := withInstance()
	noInstances.Instances = nil
	require.Error(t, store.StoreFormatBinding("id", "iss", noInstances), "no instances")
}
