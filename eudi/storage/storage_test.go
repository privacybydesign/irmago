package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
)

// TestNewStorage_EncryptsDatabase is the direct regression guard for the bug where
// the AES key was never passed to the database connection, leaving the on-disk
// database unencrypted despite the "encrypted-at-rest" claim.
func TestNewStorage_EncryptsDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, DbFilename)

	var aesKey [32]byte
	copy(aesKey[:], "0123456789abcdef0123456789abcdef")

	s, err := NewStorage(aesKey, dbPath, dir)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// The on-disk database must be encrypted, not plaintext SQLite.
	plaintext, err := sqlcipher.IsPlaintext(dbPath)
	require.NoError(t, err)
	assert.False(t, plaintext, "NewStorage must produce an encrypted database")

	// It opens again with the same key (and does not spuriously re-migrate).
	s, err = NewStorage(aesKey, dbPath, dir)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// It fails with a different key.
	var wrongKey [32]byte
	copy(wrongKey[:], "fedcba9876543210fedcba9876543210")
	_, err = NewStorage(wrongKey, dbPath, dir)
	require.Error(t, err, "opening the encrypted database with the wrong key must fail")
}

// TestNewStorageWithDialector_MigratesViaSeam checks the dialector seam runs the
// holder-model AutoMigrate independently of the concrete driver (here sqlcipher
// in-memory), so callers can supply their own dialector (e.g. Postgres).
func TestNewStorageWithDialector_MigratesViaSeam(t *testing.T) {
	var aesKey [32]byte
	copy(aesKey[:], "0123456789abcdef0123456789abcdef")

	connector := sqlcipher.NewConnector(":memory:", aesKey[:])
	s, err := NewStorageWithDialector(
		sqlcipher.Dialector{Connector: connector},
		filesystem.NewFileSystemStorage(aesKey, t.TempDir()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	assert.True(t, s.Db().Migrator().HasTable(&models.CredentialMetadata{}),
		"the seam must auto-migrate the holder models")
}

// TestNewStorageWithDialector_Postgres proves the holder models migrate onto a
// Postgres dialector — the server-side, multi-tenant deployment path. Skipped
// unless EUDI_TEST_POSTGRES_DSN points at a (throwaway) database.
func TestNewStorageWithDialector_Postgres(t *testing.T) {
	dsn := os.Getenv("EUDI_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set EUDI_TEST_POSTGRES_DSN to run the Postgres-backed holder storage test")
	}

	s, err := NewStorageWithDialector(postgres.Open(dsn), filesystem.NewFileSystemStorage([32]byte{}, t.TempDir()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	assert.True(t, s.Db().Migrator().HasTable(&models.CredentialMetadata{}),
		"the Postgres seam must auto-migrate the holder models")
}
