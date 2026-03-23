package storage

import (
	"testing"

	"github.com/google/uuid"
	"github.com/privacybydesign/irmago/eudi/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newTestStore(t *testing.T) (HolderBindingKeyStore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.HolderBindingKey{}, &models.ECDSAKeyMetadata{}, &models.RSAKeyMetadata{})
	require.NoError(t, err)

	return NewHolderBindingKeyStore(db), db
}

func newECDSAKey() *models.HolderBindingKey {
	return &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmECDSA,
		PublicKeyThumbprint: "test-thumbprint-ecdsa",
		PrivateKeyEncrypted: []byte("encrypted-private-key"),
		ECDSA: &models.ECDSAKeyMetadata{
			CurveName: "P-256",
		},
	}
}

func newRSAKey() *models.HolderBindingKey {
	return &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmRSA,
		PublicKeyThumbprint: "test-thumbprint-rsa",
		PrivateKeyEncrypted: []byte("encrypted-private-key"),
		RSA: &models.RSAKeyMetadata{
			ModulusBits:    2048,
			PublicExponent: 65537,
		},
	}
}

func TestStoreKey_ECDSA(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	err := store.StoreKey(db, key)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, key.ID)
}

func TestStoreKey_RSA(t *testing.T) {
	store, db := newTestStore(t)

	err := store.StoreKey(db, newRSAKey())
	require.NoError(t, err)
}

func TestStoreKey_AssignsIDWhenNil(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	key.ID = uuid.Nil

	require.NoError(t, store.StoreKey(db, key))
	assert.NotEqual(t, uuid.Nil, key.ID)
}

func TestStoreKey_PreservesProvidedID(t *testing.T) {
	store, db := newTestStore(t)

	id := uuid.New()
	key := newECDSAKey()
	key.ID = id

	require.NoError(t, store.StoreKey(db, key))
	assert.Equal(t, id, key.ID)
}

func TestStoreKey_NilKey(t *testing.T) {
	store, db := newTestStore(t)

	err := store.StoreKey(db, nil)
	require.Error(t, err)
}

func TestStoreKey_DuplicateThumbprint(t *testing.T) {
	store, db := newTestStore(t)

	require.NoError(t, store.StoreKey(db, newECDSAKey()))

	err := store.StoreKey(db, newECDSAKey()) // same thumbprint
	require.Error(t, err)
}

func TestStoreKey_ValidationFailsWithoutThumbprint(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	key.PublicKeyThumbprint = ""

	err := store.StoreKey(db, key)
	require.Error(t, err)
}

func TestStoreKey_ValidationFailsWithoutPrivateKey(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	key.PrivateKeyEncrypted = nil

	err := store.StoreKey(db, key)
	require.Error(t, err)
}

func TestStoreKey_ValidationFailsECDSAWithoutMetadata(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	key.ECDSA = nil

	err := store.StoreKey(db, key)
	require.Error(t, err)
}

func TestStoreKey_ValidationFailsECDSAWithRSAMetadata(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	key.RSA = &models.RSAKeyMetadata{ModulusBits: 2048, PublicExponent: 65537}

	err := store.StoreKey(db, key)
	require.Error(t, err)
}

func TestGetByID(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	require.NoError(t, store.StoreKey(db, key))

	got, err := store.GetByID(db, key.ID)
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
	assert.Equal(t, key.Algorithm, got.Algorithm)
	assert.Equal(t, key.PublicKeyThumbprint, got.PublicKeyThumbprint)
	require.NotNil(t, got.ECDSA)
	assert.Equal(t, "P-256", got.ECDSA.CurveName)
	assert.Nil(t, got.RSA)
}

func TestGetByID_PreloadsRSAMetadata(t *testing.T) {
	store, db := newTestStore(t)

	key := newRSAKey()
	require.NoError(t, store.StoreKey(db, key))

	got, err := store.GetByID(db, key.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RSA)
	assert.Equal(t, 2048, got.RSA.ModulusBits)
	assert.Equal(t, 65537, got.RSA.PublicExponent)
	assert.Nil(t, got.ECDSA)
}

func TestGetByID_NotFound(t *testing.T) {
	store, db := newTestStore(t)

	_, err := store.GetByID(db, uuid.New())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestGetByThumbprint(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	require.NoError(t, store.StoreKey(db, key))

	got, err := store.GetByThumbprint(db, key.PublicKeyThumbprint)
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
	assert.Equal(t, key.PublicKeyThumbprint, got.PublicKeyThumbprint)
	require.NotNil(t, got.ECDSA)
	assert.Equal(t, "P-256", got.ECDSA.CurveName)
}

func TestGetByThumbprint_NotFound(t *testing.T) {
	store, db := newTestStore(t)

	_, err := store.GetByThumbprint(db, "nonexistent-thumbprint")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteKey(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	require.NoError(t, store.StoreKey(db, key))

	require.NoError(t, store.DeleteKey(db, key.ID))

	_, err := store.GetByID(db, key.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteKey_NotFound(t *testing.T) {
	store, db := newTestStore(t)

	err := store.DeleteKey(db, uuid.New())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteKey_CascadesMetadata(t *testing.T) {
	store, db := newTestStore(t)

	key := newECDSAKey()
	require.NoError(t, store.StoreKey(db, key))

	require.NoError(t, store.DeleteKey(db, key.ID))

	// Verify that re-inserting with the same thumbprint succeeds (unique index freed)
	key2 := newECDSAKey()
	require.NoError(t, store.StoreKey(db, key2))
}

func TestDeleteAll(t *testing.T) {
	store, db := newTestStore(t)

	require.NoError(t, store.StoreKey(db, newECDSAKey()))
	require.NoError(t, store.StoreKey(db, newRSAKey()))

	require.NoError(t, store.DeleteAll(db))

	_, err := store.GetByThumbprint(db, "test-thumbprint-ecdsa")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = store.GetByThumbprint(db, "test-thumbprint-rsa")
	require.ErrorIs(t, err, ErrNotFound)
}
