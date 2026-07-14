package sqlcipher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestIsPlaintext(t *testing.T) {
	dir := t.TempDir()

	// An unencrypted database is plaintext.
	plainPath := filepath.Join(dir, "plain.db")
	db := openAndMigrateTestDB(t, &Connector{Path: plainPath})
	require.NoError(t, db.Create(newECDSAKey()).Error)
	closeGormDB(t, db)
	isPlain, err := IsPlaintext(plainPath)
	require.NoError(t, err)
	assert.True(t, isPlain, "unencrypted DB should be detected as plaintext")

	// An encrypted database is not.
	encPath := filepath.Join(dir, "enc.db")
	db = openAndMigrateTestDB(t, NewConnector(encPath, []byte("a-key")))
	require.NoError(t, db.Create(newECDSAKey()).Error)
	closeGormDB(t, db)
	isPlain, err = IsPlaintext(encPath)
	require.NoError(t, err)
	assert.False(t, isPlain, "encrypted DB should not be detected as plaintext")

	// A missing file is not plaintext.
	isPlain, err = IsPlaintext(filepath.Join(dir, "does-not-exist.db"))
	require.NoError(t, err)
	assert.False(t, isPlain)

	// An empty file (as freshly created by EnsureFileExists) is not plaintext.
	emptyPath := filepath.Join(dir, "empty.db")
	require.NoError(t, os.WriteFile(emptyPath, nil, 0600))
	isPlain, err = IsPlaintext(emptyPath)
	require.NoError(t, err)
	assert.False(t, isPlain)
}

func TestEncryptInPlace(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "yivi-eudi.db")
	key := []byte("migration-test-key")

	// Create a plaintext database with a known record.
	db := openAndMigrateTestDB(t, &Connector{Path: dbPath})
	original := newECDSAKey()
	require.NoError(t, db.Create(original).Error)
	closeGormDB(t, db)

	isPlain, err := IsPlaintext(dbPath)
	require.NoError(t, err)
	require.True(t, isPlain, "precondition: database starts plaintext")

	// Migrate it in place.
	require.NoError(t, EncryptInPlace(dbPath, key))

	// It is now encrypted, so the header gate makes any re-migration a no-op.
	isPlain, err = IsPlaintext(dbPath)
	require.NoError(t, err)
	assert.False(t, isPlain, "database should be encrypted after migration")

	// The data survived and reads back with the correct key.
	db = openGormDB(t, NewConnector(dbPath, key))
	var got models.HolderBindingKey
	require.NoError(t, db.First(&got, "id = ?", original.ID).Error)
	assert.Equal(t, original.PublicKeyThumbprint, got.PublicKeyThumbprint)
	closeGormDB(t, db)

	// The wrong key must fail.
	_, err = gorm.Open(Dialector{Connector: NewConnector(dbPath, []byte("the-wrong-key"))}, &gorm.Config{})
	require.Error(t, err, "opening the migrated database with the wrong key must fail")

	// The temp file and the stale plaintext sidecars are gone.
	for _, suffix := range []string{".migrating", "-wal", "-shm"} {
		_, statErr := os.Stat(dbPath + suffix)
		assert.Truef(t, os.IsNotExist(statErr), "expected %s to be absent", dbPath+suffix)
	}
}
