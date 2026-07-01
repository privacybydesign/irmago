package db

import (
	"database/sql"
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
)

func newTestSqlDB(t *testing.T) *sql.DB {
	t.Helper()

	connector := sqlcipher.NewConnector(":memory:", []byte("super-secret-key-123"))
	sqlDB := sql.OpenDB(connector)
	// A single connection is required: each new connection to an in-memory SQLite database
	// gets its own separate database, and the underlying C bindings are not safe for
	// concurrent use (see sqlcipher.Dialector.Initialize, which sets this for the same reason).
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return sqlDB
}

func hasColumn(t *testing.T, sqlDB *sql.DB, table, column string) bool {
	t.Helper()

	var count int
	require.NoError(t, sqlDB.QueryRow(
		"SELECT count(*) FROM pragma_table_info(?) WHERE name=?", table, column,
	).Scan(&count))
	return count > 0
}

func hasTable(t *testing.T, sqlDB *sql.DB, table string) bool {
	t.Helper()

	var count int
	require.NoError(t, sqlDB.QueryRow(
		"SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table,
	).Scan(&count))
	return count > 0
}

func TestRunFullRepair_CreatesAllTablesAndColumnsOnEmptyDatabase(t *testing.T) {
	sqlDB := newTestSqlDB(t)

	require.NoError(t, RunFullRepair(sqlDB))

	for _, table := range []string{
		"holder_binding_keys", "ecdsa_key_metadata", "rsa_key_metadata", "credential_batches",
		"issued_credential_instances", "issuer_metadata_displays", "credential_metadata",
		"credential_displays", "credential_claims", "claim_displays", "eudi_log_entries",
		"eudi_log_credentials", "kb_jwt_replay_entries",
	} {
		require.True(t, hasTable(t, sqlDB, table), "expected table %q to exist", table)
	}

	for _, column := range []string{"credential_type", "processed_claims", "issuance_date"} {
		require.True(t, hasColumn(t, sqlDB, "credential_batches", column), "expected column %q to exist", column)
	}
}

func TestRunFullRepair_IsIdempotent(t *testing.T) {
	sqlDB := newTestSqlDB(t)

	require.NoError(t, RunFullRepair(sqlDB))
	require.NoError(t, RunFullRepair(sqlDB))
}

// TestRunFullRepair_RepairsLegacyDatabaseMissingCanonicalColumns reproduces the reported bug:
// a database that only ever had the 000001 schema applied (credential_batches without the
// canonical credential_type/processed_claims/issuance_date columns added by 000002). Running
// RunFullRepair must add the missing columns and backfill them from the legacy columns, without
// erroring on the tables/columns that already exist.
func TestRunFullRepair_RepairsLegacyDatabaseMissingCanonicalColumns(t *testing.T) {
	sqlDB := newTestSqlDB(t)

	_, err := sqlDB.Exec("CREATE TABLE `credential_batches` (" +
		"`id` TEXT, `issuer_url` text, `verifiable_credential_type` text, `format` text, `hash` text, " +
		"`processed_sd_jwt_payload` JSON NOT NULL, `issued_at` datetime, `expires_at` datetime, " +
		"`not_before` datetime, `batch_size` integer, `remaining_count` integer, `credential_issuer` text, " +
		"PRIMARY KEY (`id`))")
	require.NoError(t, err)

	_, err = sqlDB.Exec(
		"INSERT INTO `credential_batches` (`id`, `issuer_url`, `verifiable_credential_type`, `format`, `hash`, "+
			"`processed_sd_jwt_payload`, `issued_at`, `batch_size`, `remaining_count`, `credential_issuer`) "+
			"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		"batch-1", "https://issuer.example.com", "https://vct.example.com/MyCredential", "dc+sd-jwt",
		"hash-1", `{"sub":"user123"}`, "2024-01-01T00:00:00Z", 1, 1, "https://issuer.example.com",
	)
	require.NoError(t, err)

	require.NoError(t, RunFullRepair(sqlDB))

	require.True(t, hasColumn(t, sqlDB, "credential_batches", "credential_type"))
	require.True(t, hasColumn(t, sqlDB, "credential_batches", "processed_claims"))
	require.True(t, hasColumn(t, sqlDB, "credential_batches", "issuance_date"))

	var credentialType, processedClaims string
	require.NoError(t, sqlDB.QueryRow(
		"SELECT `credential_type`, `processed_claims` FROM `credential_batches` WHERE `id` = ?", "batch-1",
	).Scan(&credentialType, &processedClaims))
	require.Equal(t, "https://vct.example.com/MyCredential", credentialType)
	require.Equal(t, `{"sub":"user123"}`, processedClaims)
}
