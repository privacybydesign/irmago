package storage

import (
	"testing"

	"github.com/google/uuid"
	"github.com/privacybydesign/irmago/eudi/storage/models"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newTestStore(t *testing.T) HolderBindingKeyStore {
	t.Helper()

	const passphrase = "super-secret-key-123"

	dsn := sqlcipher.DSN(":memory:", passphrase)
	db, err := gorm.Open(sqlcipher.Dialector{DSN: dsn}, &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(&models.HolderBindingKey{}, &models.ECDSAKeyMetadata{}, &models.RSAKeyMetadata{})
	require.NoError(t, err)

	return NewHolderBindingKeyStore(db)
}

func newECDSAKey() *models.HolderBindingKey {
	return &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmECDSA,
		PublicKeyThumbprint: datatypes.NullString{V: "test-thumbprint-ecdsa", Valid: true},
		PrivateKey:          []byte("encrypted-private-key"),
		ECDSA: &models.ECDSAKeyMetadata{
			CurveName: "P-256",
		},
	}
}

func newRSAKey() *models.HolderBindingKey {
	return &models.HolderBindingKey{
		Algorithm:           models.KeyAlgorithmRSA,
		PublicKeyThumbprint: datatypes.NullString{V: "test-thumbprint-rsa", Valid: true},
		PrivateKey:          []byte("encrypted-private-key"),
		RSA: &models.RSAKeyMetadata{
			ModulusBits:    2048,
			PublicExponent: 65537,
		},
	}
}

func TestStoreKey_ECDSA(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	err := store.StoreKey(key)
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, key.ID)
}

func TestStoreKey_RSA(t *testing.T) {
	store := newTestStore(t)

	err := store.StoreKey(newRSAKey())
	require.NoError(t, err)
}

func TestStoreKey_AssignsIDWhenNil(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	key.ID = datatypes.UUID(datatypes.NewNilBinUUID())

	require.NoError(t, store.StoreKey(key))
	assert.NotEqual(t, datatypes.NewNilBinUUID(), key.ID)
}

func TestStoreKey_PreservesProvidedID(t *testing.T) {
	store := newTestStore(t)

	id := datatypes.NewUUIDv4()
	key := newECDSAKey()
	key.ID = id

	require.NoError(t, store.StoreKey(key))
	assert.Equal(t, id, key.ID)
}

func TestStoreKey_DuplicateThumbprint(t *testing.T) {
	store := newTestStore(t)

	require.NoError(t, store.StoreKey(newECDSAKey()))

	err := store.StoreKey(newECDSAKey()) // same thumbprint
	require.Error(t, err)
}

func TestStoreKey_WithDidUrl(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	key.PublicKeyThumbprint = datatypes.NullString{Valid: false}
	key.DidUrl = datatypes.NullString{V: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", Valid: true}

	require.NoError(t, store.StoreKey(key))
	assert.NotEqual(t, uuid.Nil, key.ID)
}

func TestStoreKey_DuplicateDidUrl(t *testing.T) {
	store := newTestStore(t)

	didUrl := datatypes.NullString{V: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", Valid: true}

	key1 := newECDSAKey()
	key1.PublicKeyThumbprint = datatypes.NullString{Valid: false}
	key1.DidUrl = didUrl
	require.NoError(t, store.StoreKey(key1))

	key2 := newECDSAKey()
	key2.PublicKeyThumbprint = datatypes.NullString{Valid: false}
	key2.DidUrl = didUrl
	require.Error(t, store.StoreKey(key2))
}

func TestStoreKey_ValidationFailsWithBothThumbprintAndDidUrl(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	key.DidUrl = datatypes.NullString{V: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", Valid: true}

	err := store.StoreKey(key)
	require.Error(t, err)
}

func TestStoreKey_ValidationFailsWithoutThumbprint(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	key.PublicKeyThumbprint = datatypes.NullString{Valid: false}

	err := store.StoreKey(key)
	require.Error(t, err)
}

func TestStoreKey_ValidationFailsWithoutPrivateKey(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	key.PrivateKey = nil

	err := store.StoreKey(key)
	require.Error(t, err)
}

func TestStoreKey_ValidationFailsECDSAWithoutMetadata(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	key.ECDSA = nil

	err := store.StoreKey(key)
	require.Error(t, err)
}

func TestStoreKey_ValidationFailsECDSAWithRSAMetadata(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	key.RSA = &models.RSAKeyMetadata{ModulusBits: 2048, PublicExponent: 65537}

	err := store.StoreKey(key)
	require.Error(t, err)
}

func TestGetByID(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	require.NoError(t, store.StoreKey(key))

	got, err := store.GetByID(key.ID)
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
	assert.Equal(t, key.Algorithm, got.Algorithm)
	require.NotNil(t, got.PublicKeyThumbprint)
	require.True(t, key.PublicKeyThumbprint.Valid)
	assert.Equal(t, key.PublicKeyThumbprint.V, got.PublicKeyThumbprint.V)
	require.NotNil(t, got.ECDSA)
	assert.Equal(t, "P-256", got.ECDSA.CurveName)
	assert.Nil(t, got.RSA)
}

func TestGetByID_PreloadsRSAMetadata(t *testing.T) {
	store := newTestStore(t)

	key := newRSAKey()
	require.NoError(t, store.StoreKey(key))

	got, err := store.GetByID(key.ID)
	require.NoError(t, err)
	require.NotNil(t, got.RSA)
	assert.Equal(t, 2048, got.RSA.ModulusBits)
	assert.Equal(t, 65537, got.RSA.PublicExponent)
	assert.Nil(t, got.ECDSA)
}

func TestGetByID_NotFound(t *testing.T) {
	store := newTestStore(t)

	_, err := store.GetByID(datatypes.NewUUIDv4())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestGetByThumbprint(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	require.NoError(t, store.StoreKey(key))

	got, err := store.GetByThumbprint(key.PublicKeyThumbprint.V)
	require.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)
	require.NotNil(t, got.PublicKeyThumbprint)
	require.True(t, key.PublicKeyThumbprint.Valid)
	assert.Equal(t, key.PublicKeyThumbprint.V, got.PublicKeyThumbprint.V)
	require.NotNil(t, got.ECDSA)
	assert.Equal(t, "P-256", got.ECDSA.CurveName)
}

func TestGetByThumbprint_NotFound(t *testing.T) {
	store := newTestStore(t)

	_, err := store.GetByThumbprint("nonexistent-thumbprint")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteKey(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	require.NoError(t, store.StoreKey(key))

	require.NoError(t, store.DeleteKey(key.ID))

	_, err := store.GetByID(key.ID)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteKey_NotFound(t *testing.T) {
	store := newTestStore(t)

	err := store.DeleteKey(datatypes.NewUUIDv4())
	require.ErrorIs(t, err, ErrNotFound)
}

func TestDeleteKey_CascadesMetadata(t *testing.T) {
	store := newTestStore(t)

	key := newECDSAKey()
	require.NoError(t, store.StoreKey(key))

	require.NoError(t, store.DeleteKey(key.ID))

	// Verify that re-inserting with the same thumbprint succeeds (unique index freed)
	key2 := newECDSAKey()
	require.NoError(t, store.StoreKey(key2))
}

func TestDeleteAll(t *testing.T) {
	store := newTestStore(t)

	require.NoError(t, store.StoreKey(newECDSAKey()))
	require.NoError(t, store.StoreKey(newRSAKey()))

	require.NoError(t, store.DeleteAll())

	_, err := store.GetByThumbprint("test-thumbprint-ecdsa")
	require.ErrorIs(t, err, ErrNotFound)
	_, err = store.GetByThumbprint("test-thumbprint-rsa")
	require.ErrorIs(t, err, ErrNotFound)
}
