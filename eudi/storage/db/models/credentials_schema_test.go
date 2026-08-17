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

// legacyCredentialBatch is CredentialBatch as it stood before IssuerVerified was
// added, and builds the schema an already-installed wallet has. It names the
// table explicitly, since GORM derives that from the struct name.
type legacyCredentialBatch struct {
	ID                       datatypes.UUID `gorm:"type:uuid;primaryKey"`
	IssuerURL                string
	VerifiableCredentialType string
	Format                   models.CredentialFormat
	Hash                     string         `gorm:"uniqueIndex"`
	ProcessedSdJwtPayload    datatypes.JSON `gorm:"type:JSON;not null"`
	IssuedAt                 datatypes.NullTime
	BatchSize                uint
	RemainingCount           uint
	CredentialIssuer         string
}

func (legacyCredentialBatch) TableName() string { return "credential_batches" }

// TestAutoMigrateAddsIssuerVerifiedToPopulatedBatchTable runs the upgrade an
// existing wallet performs: a credential_batches table without IssuerVerified,
// holding a credential, migrated by the AutoMigrate that runs on every startup.
//
// AutoMigrate is the only schema mechanism the holder database has, so a new
// column arrives as an ALTER TABLE ADD COLUMN — which SQLite rejects for a NOT
// NULL column once the table has rows. Getting that wrong leaves every wallet
// holding a credential unable to open its database, so the property is pinned
// here rather than discovered on an upgrade.
func TestAutoMigrateAddsIssuerVerifiedToPopulatedBatchTable(t *testing.T) {
	d := openHolderDB(t)
	require.NoError(t, d.AutoMigrate(&legacyCredentialBatch{}))

	var before []string
	require.NoError(t, d.Raw(
		`SELECT name FROM pragma_table_info('credential_batches')`,
	).Scan(&before).Error)
	require.NotContains(t, before, "issuer_verified",
		"the legacy fixture must not already carry the column under test")

	require.NoError(t, d.Create(&legacyCredentialBatch{
		ID:                       datatypes.NewUUIDv4(),
		IssuerURL:                "https://issuer.example",
		VerifiableCredentialType: "https://vct.example/x",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     "hash-legacy",
		ProcessedSdJwtPayload:    []byte(`{"sub":"pre-existing-user"}`),
		IssuedAt:                 datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                1,
		RemainingCount:           1,
		CredentialIssuer:         "https://issuer.example",
	}).Error)

	require.NoError(t, d.AutoMigrate(&models.CredentialBatch{}),
		"AutoMigrate must add issuer_verified to a table that already holds credentials")

	// A batch written before the column existed reads back unverified, and the
	// rest of it survives the migration.
	var migrated models.CredentialBatch
	require.NoError(t, d.Where("hash = ?", "hash-legacy").First(&migrated).Error)
	require.False(t, migrated.IssuerVerified)
	require.JSONEq(t, `{"sub":"pre-existing-user"}`, string(migrated.ProcessedSdJwtPayload))

	// And one written after it round-trips the flag, so the column is readable as
	// well as present.
	require.NoError(t, d.Create(&models.CredentialBatch{
		IssuerURL:                "https://issuer.example",
		VerifiableCredentialType: "https://vct.example/x",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     "hash-verified",
		ProcessedSdJwtPayload:    []byte(`{"sub":"new-user"}`),
		IssuedAt:                 datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                1,
		RemainingCount:           1,
		CredentialIssuer:         "https://issuer.example",
		IssuerVerified:           true,
	}).Error)

	var reread models.CredentialBatch
	require.NoError(t, d.Where("hash = ?", "hash-verified").First(&reread).Error)
	require.True(t, reread.IssuerVerified)
}
