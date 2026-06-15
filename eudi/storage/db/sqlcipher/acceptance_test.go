package sqlcipher

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// openAndMigrateTestDB opens a GORM database backed by SQLCipher and runs AutoMigrate.
func openAndMigrateTestDB(t *testing.T, c *Connector) *gorm.DB {
	t.Helper()
	db := openGormDB(t, c)
	require.NoError(t, db.AutoMigrate(
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
		&models.HolderBindingKey{},
		&models.IssuerMetadataDisplay{},
		&models.CredentialMetadata{},
		&models.CredentialDisplay{},
		&models.CredentialClaim{},
		&models.ClaimDisplay{},
		&models.CredentialBatch{},
		&models.IssuedCredentialInstance{},
	))
	return db
}

// openGormDB opens a GORM database backed by SQLCipher without running migrations.
func openGormDB(t *testing.T, c *Connector) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(Dialector{Connector: c}, &gorm.Config{})
	require.NoError(t, err)
	return db
}

func closeGormDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())
}

// --- Encryption round-trip ---

func TestSQLCipher_EncryptedFileCanOnlyBeOpenedWithCorrectKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	passphrase := []byte("correct-horse-battery-staple")

	// Create a database with a passphrase and insert a record.
	db := openAndMigrateTestDB(t, NewConnector(dbPath, passphrase))
	key := newECDSAKey()
	require.NoError(t, db.Create(key).Error)
	closeGormDB(t, db)

	// Re-open with the same passphrase — the record must be readable.
	db = openGormDB(t, NewConnector(dbPath, passphrase))
	var got models.HolderBindingKey
	require.NoError(t, db.First(&got, "id = ?", key.ID).Error)
	assert.Equal(t, key.PublicKeyThumbprint, got.PublicKeyThumbprint)
	closeGormDB(t, db)

	// Opening with the wrong passphrase must fail.
	_, err := gorm.Open(Dialector{Connector: NewConnector(dbPath, []byte("wrong-key"))}, &gorm.Config{})
	require.Error(t, err, "opening with the wrong key should fail")
}

// --- GORM CRUD through SQLCipher ---

func TestSQLCipher_CreateAndReadBackAllColumnTypes(t *testing.T) {
	db := openAndMigrateTestDB(t, NewConnector(":memory:", []byte("test-key")))

	// Use a large random blob to stress the []byte binding path.
	blob := make([]byte, 4096)
	_, err := rand.Read(blob)
	require.NoError(t, err)

	original := &models.HolderBindingKey{
		ID:                  datatypes.NewUUIDv4(),
		Algorithm:           models.KeyAlgorithmECDSA,
		PublicKeyThumbprint: datatypes.NullString{V: "thumb-readback", Valid: true},
		PrivateKey:          blob,
		ECDSA:               &models.ECDSAKeyMetadata{CurveName: "P-384"},
	}
	require.NoError(t, db.Create(original).Error)

	var got models.HolderBindingKey
	require.NoError(t, db.Preload("ECDSA").First(&got, "id = ?", original.ID).Error)

	assert.Equal(t, original.ID, got.ID)
	assert.Equal(t, original.Algorithm, got.Algorithm)
	assert.Equal(t, original.PublicKeyThumbprint, got.PublicKeyThumbprint)
	assert.Equal(t, original.PrivateKey, got.PrivateKey, "blob round-trip must be lossless")
	assert.False(t, got.CreatedAt.IsZero(), "CreatedAt should be populated")

	require.NotNil(t, got.ECDSA)
	//assert.Equal(t, original.ID, got.ECDSA.ID)
	assert.Equal(t, "P-384", got.ECDSA.CurveName)
}

func TestSQLCipher_UpdateRecord(t *testing.T) {
	db := openAndMigrateTestDB(t, NewConnector(":memory:", []byte("test-key")))

	key := newRSAKey()
	require.NoError(t, db.Create(key).Error)

	require.NoError(t, db.Model(key).Update("public_key_thumbprint", "updated-thumbprint").Error)

	var got models.HolderBindingKey
	require.NoError(t, db.First(&got, "id = ?", key.ID).Error)
	assert.Equal(t, "updated-thumbprint", got.PublicKeyThumbprint.V)
}

func TestSQLCipher_DeleteRecord(t *testing.T) {
	db := openAndMigrateTestDB(t, NewConnector(":memory:", []byte("test-key")))

	key := newECDSAKey()
	require.NoError(t, db.Create(key).Error)

	require.NoError(t, db.Delete(&models.HolderBindingKey{}, "id = ?", key.ID).Error)

	err := db.First(&models.HolderBindingKey{}, "id = ?", key.ID).Error
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

// --- Transactions ---

func TestSQLCipher_TransactionCommit(t *testing.T) {
	db := openAndMigrateTestDB(t, NewConnector(":memory:", []byte("test-key")))

	err := db.Transaction(func(tx *gorm.DB) error {
		return tx.Create(newECDSAKey()).Error
	})
	require.NoError(t, err)

	var count int64
	db.Model(&models.HolderBindingKey{}).Count(&count)
	assert.Equal(t, int64(1), count)
}

func TestSQLCipher_TransactionRollback(t *testing.T) {
	db := openAndMigrateTestDB(t, NewConnector(":memory:", []byte("test-key")))

	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(newECDSAKey()).Error; err != nil {
			return err
		}
		return assert.AnError // force rollback
	})
	require.Error(t, err)

	var count int64
	db.Model(&models.HolderBindingKey{}).Count(&count)
	assert.Equal(t, int64(0), count, "row should not exist after rollback")
}

// --- Constraints ---

func TestSQLCipher_UniqueIndexEnforced(t *testing.T) {
	db := openAndMigrateTestDB(t, NewConnector(":memory:", []byte("test-key")))

	require.NoError(t, db.Create(newECDSAKey()).Error)
	err := db.Create(newECDSAKey()).Error // same thumbprint
	require.Error(t, err, "duplicate thumbprint should violate unique index")
}

func TestSQLCipher_ForeignKeyCascadeDelete(t *testing.T) {
	db := openAndMigrateTestDB(t, NewConnector(":memory:", []byte("test-key")))

	key := newECDSAKey()
	require.NoError(t, db.Create(key).Error)

	// Verify the child row exists.
	var metaCount int64
	db.Model(&models.ECDSAKeyMetadata{}).Count(&metaCount)
	require.Equal(t, int64(1), metaCount)

	// Delete parent — child must be cascade-deleted.
	require.NoError(t, db.Delete(&models.HolderBindingKey{}, "id = ?", key.ID).Error)

	db.Model(&models.ECDSAKeyMetadata{}).Count(&metaCount)
	assert.Equal(t, int64(0), metaCount, "metadata should be cascade-deleted")
}

// --- File-based persistence ---

func TestSQLCipher_PersistsToDisk(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "persist.db")

	// Write.
	db := openAndMigrateTestDB(t, NewConnector(dbPath, []byte("key")))
	key := newRSAKey()
	require.NoError(t, db.Create(key).Error)
	closeGormDB(t, db)

	// The file must exist and be non-empty.
	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))

	// Read back from the same file (no migration needed).
	db = openGormDB(t, NewConnector(dbPath, []byte("key")))
	var got models.HolderBindingKey
	require.NoError(t, db.Preload("RSA").First(&got, "id = ?", key.ID).Error)
	assert.Equal(t, 2048, got.RSA.ModulusBits)
	closeGormDB(t, db)
}

// --- Unencrypted mode ---

func TestSQLCipher_WorksWithoutEncryption(t *testing.T) {
	db := openAndMigrateTestDB(t, &Connector{Path: ":memory:"})

	key := newECDSAKey()
	require.NoError(t, db.Create(key).Error)

	var got models.HolderBindingKey
	require.NoError(t, db.Preload("ECDSA").First(&got, "id = ?", key.ID).Error)
	assert.Equal(t, key.PublicKeyThumbprint, got.PublicKeyThumbprint)
}
