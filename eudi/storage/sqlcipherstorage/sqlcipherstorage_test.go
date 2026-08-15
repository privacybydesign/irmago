package sqlcipherstorage_test

import (
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipherstorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNew_EncryptsDatabase is the direct regression guard for the bug where the
// AES key was never passed to the database connection, leaving the on-disk
// database unencrypted despite the "encrypted-at-rest" claim.
func TestNew_EncryptsDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, storage.DbFilename)

	var aesKey [32]byte
	copy(aesKey[:], "0123456789abcdef0123456789abcdef")

	s, err := sqlcipherstorage.New(aesKey, dbPath, dir)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// The on-disk database must be encrypted, not plaintext SQLite.
	plaintext, err := sqlcipher.IsPlaintext(dbPath)
	require.NoError(t, err)
	assert.False(t, plaintext, "New must produce an encrypted database")

	// It opens again with the same key (and does not spuriously re-migrate).
	s, err = sqlcipherstorage.New(aesKey, dbPath, dir)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	// It fails with a different key.
	var wrongKey [32]byte
	copy(wrongKey[:], "fedcba9876543210fedcba9876543210")
	_, err = sqlcipherstorage.New(wrongKey, dbPath, dir)
	require.Error(t, err, "opening the encrypted database with the wrong key must fail")
}
