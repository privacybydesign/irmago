package services

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// TestMigrateFlatBatchesToThreeLayer_ReparentsAndGroups covers the #685 step-3
// data migration: a dc+sd-jwt batch and a vc+sd-jwt batch carrying the SAME
// content from the same issuer must group under ONE LogicalCredential (the #686
// cross-data-model grouping) as two FormatBindings, with instances reparented
// and their used flag preserved, and the flat batches deleted.
func TestMigrateFlatBatchesToThreeLayer_ReparentsAndGroups(t *testing.T) {
	db := newTestHolderDB(t)

	issuer := "https://issuer.example.com"
	sdJwtPayload, err := json.Marshal(map[string]any{
		"iss": issuer, "vct": "ExampleCredential", "given_name": "Alice", "age": float64(30),
	})
	require.NoError(t, err)
	vcdmPayload, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential", "ExampleCredential"},
		"issuer":            issuer,
		"credentialSubject": map[string]any{"given_name": "Alice", "age": float64(30)},
	})
	require.NoError(t, err)

	sdJwtBatch := &models.CredentialBatch{
		IssuerIdentifier:           issuer,
		VerifiableCredentialType:   "ExampleCredential",
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       "hash-sdjwt",
		CredentialIssuerIdentifier: issuer,
		ProcessedSdJwtPayload:      datatypes.JSON(sdJwtPayload),
		IssuedAt:                   datatypes.NullTime{V: time.Unix(1700000000, 0), Valid: true},
		BatchSize:                  2,
		RemainingCount:             1,
		IssuerDisplay:              []models.IssuerMetadataDisplay{{Name: "Example"}},
		Instances: []models.IssuedCredentialInstance{
			{RawCredential: []byte("raw-a"), Used: true},
			{RawCredential: []byte("raw-b")},
		},
	}
	vcdmBatch := &models.CredentialBatch{
		IssuerIdentifier:           issuer,
		VerifiableCredentialType:   "https://www.w3.org/ns/credentials/v2|ExampleCredential",
		Format:                     models.CredentialFormatSdJwtVcdm,
		Hash:                       "hash-vcdm",
		CredentialIssuerIdentifier: issuer,
		ProcessedSdJwtPayload:      datatypes.JSON(vcdmPayload),
		IssuedAt:                   datatypes.NullTime{V: time.Unix(1700000000, 0), Valid: true},
		BatchSize:                  1,
		RemainingCount:             1,
		Instances:                  []models.IssuedCredentialInstance{{RawCredential: []byte("raw-c")}},
	}
	require.NoError(t, db.Create(sdJwtBatch).Error)
	require.NoError(t, db.Create(vcdmBatch).Error)

	migrated, err := MigrateFlatBatchesToThreeLayer(db)
	require.NoError(t, err)
	assert.Equal(t, 2, migrated)

	// Flat batches are gone.
	var batchCount int64
	require.NoError(t, db.Model(&models.CredentialBatch{}).Count(&batchCount).Error)
	assert.Equal(t, int64(0), batchCount, "flat batches deleted")

	// One logical credential grouping both data models, as two format bindings.
	var logicals []models.LogicalCredential
	require.NoError(t, db.Preload("FormatBindings").Find(&logicals).Error)
	require.Len(t, logicals, 1, "same content+issuer across two data models grouped into one logical credential")
	assert.Equal(t, issuer, logicals[0].IssuerURL)
	require.Len(t, logicals[0].FormatBindings, 2, "two format bindings (dc+sd-jwt and vc+sd-jwt)")

	// Identity equals what the shared store-time function computes (parity).
	wantID, err := LogicalIdentityFromProcessedPayload(models.CredentialFormatSdJwtVc, issuer, sdJwtPayload)
	require.NoError(t, err)
	assert.Equal(t, wantID, logicals[0].Identity)

	// Instances reparented onto bindings, none left pointing at a batch, and the
	// used flag survived.
	var instances []models.IssuedCredentialInstance
	require.NoError(t, db.Find(&instances).Error)
	require.Len(t, instances, 3)
	for _, inst := range instances {
		require.NotNil(t, inst.FormatBindingID, "instance reparented onto a binding")
		assert.Nil(t, inst.CredentialBatchID, "instance no longer points at a batch")
	}
	var usedCount int64
	require.NoError(t, db.Model(&models.IssuedCredentialInstance{}).Where("used = ?", true).Count(&usedCount).Error)
	assert.Equal(t, int64(1), usedCount, "used flag preserved through migration")

	// Issuer display reparented too (credential_batch_id cleared).
	var danglingDisplay int64
	require.NoError(t, db.Model(&models.IssuerMetadataDisplay{}).Where("credential_batch_id IS NOT NULL").Count(&danglingDisplay).Error)
	assert.Equal(t, int64(0), danglingDisplay, "issuer display reparented off the batch")
}
