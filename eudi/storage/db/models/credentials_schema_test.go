package models_test

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// openHolderDB opens an encrypted in-memory holder database.
func openHolderDB(t *testing.T) *gorm.DB {
	t.Helper()
	d, err := gorm.Open(
		sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("test-key-123"))},
		&gorm.Config{},
	)
	require.NoError(t, err)
	return d
}

// TestCredentialBatchKeepsLegacyClaimsColumn pins the column backing
// CredentialBatch.ProcessedSdJwtPayload to its original name.
//
// AutoMigrate is the only schema mechanism the holder database has, and it can
// only add columns — never rename one. Renaming the Go field therefore makes it
// try to ADD a NOT NULL column, which SQLite refuses once the table holds rows,
// so a wallet that already has a credential fails to open its database at all.
//
// The field name is misleading on purpose: the column also stores mso_mdoc
// claims, but the cost of correcting the name is a broken upgrade for every
// existing wallet. Rename the field only alongside a real migration.
func TestCredentialBatchKeepsLegacyClaimsColumn(t *testing.T) {
	d := openHolderDB(t)
	require.NoError(t, d.AutoMigrate(&models.CredentialBatch{}))

	var columns []string
	require.NoError(t, d.Raw(
		`SELECT name FROM pragma_table_info('credential_batches')`,
	).Scan(&columns).Error)

	require.Contains(t, columns, "processed_sd_jwt_payload",
		"the claims column must stay named processed_sd_jwt_payload; renaming "+
			"CredentialBatch.ProcessedSdJwtPayload renames the column, which breaks "+
			"AutoMigrate for every wallet that already holds a credential")
}

// TestAutoMigrateOverPopulatedDatabase runs AutoMigrate against a database that
// already contains a credential, which is what an upgrading wallet has and what
// every other test misses by starting from an empty schema.
func TestAutoMigrateOverPopulatedDatabase(t *testing.T) {
	d := openHolderDB(t)
	require.NoError(t, d.AutoMigrate(&models.CredentialBatch{}))

	batch := &models.CredentialBatch{
		IssuerURL:                "https://issuer.example",
		VerifiableCredentialType: "https://vct.example/x",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     "hash-existing",
		ProcessedSdJwtPayload:    []byte(`{"sub":"pre-existing-user"}`),
		IssuedAt:                 datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                1,
		RemainingCount:           1,
		CredentialIssuer:         "https://issuer.example",
	}
	require.NoError(t, d.Create(batch).Error)

	// The upgrade path: the same AutoMigrate the wallet runs on every startup.
	require.NoError(t, d.AutoMigrate(&models.CredentialBatch{}),
		"AutoMigrate must succeed against a database that already holds credentials")

	// The stored claims must still be readable after the migration.
	var got models.CredentialBatch
	require.NoError(t, d.Where("hash = ?", "hash-existing").First(&got).Error)
	require.JSONEq(t, `{"sub":"pre-existing-user"}`, string(got.ProcessedSdJwtPayload))
}
