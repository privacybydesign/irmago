package db

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newTestStatusListCacheStore(t *testing.T) (*statusListCacheStore, *gorm.DB) {
	t.Helper()
	const passphrase = "super-secret-key-123"
	dsn := sqlcipher.DSN(":memory:", passphrase)
	db, err := gorm.Open(sqlcipher.Dialector{DSN: dsn}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.StatusListCacheEntry{}))
	return &statusListCacheStore{db: db}, db
}

func Test_StatusListCacheStore_PutThenGet_RoundtripsValue(t *testing.T) {
	store, _ := newTestStatusListCacheStore(t)
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, store.Put("https://issuer.example/sl/1", []byte("raw-jwt"), expires))

	raw, gotExpires, ok := store.Get("https://issuer.example/sl/1")
	require.True(t, ok)
	require.Equal(t, []byte("raw-jwt"), raw)
	require.WithinDuration(t, expires, gotExpires.UTC(), time.Second)
}

func Test_StatusListCacheStore_Get_Miss_ReturnsFalse(t *testing.T) {
	store, _ := newTestStatusListCacheStore(t)
	_, _, ok := store.Get("https://issuer.example/sl/missing")
	require.False(t, ok)
}

func Test_StatusListCacheStore_Put_Upserts(t *testing.T) {
	store, _ := newTestStatusListCacheStore(t)
	require.NoError(t, store.Put("uri", []byte("v1"), time.Now().Add(time.Hour)))
	require.NoError(t, store.Put("uri", []byte("v2"), time.Now().Add(2*time.Hour)))

	raw, _, ok := store.Get("uri")
	require.True(t, ok)
	require.Equal(t, []byte("v2"), raw)
}

func Test_StatusListCacheStore_Delete_RemovesEntry(t *testing.T) {
	store, _ := newTestStatusListCacheStore(t)
	require.NoError(t, store.Put("uri", []byte("v"), time.Now().Add(time.Hour)))
	require.NoError(t, store.Delete("uri"))
	_, _, ok := store.Get("uri")
	require.False(t, ok)
}

func Test_StatusListCacheStore_Delete_NonexistentIsNoop(t *testing.T) {
	store, _ := newTestStatusListCacheStore(t)
	require.NoError(t, store.Delete("never-stored"))
}

func Test_StatusListCacheStore_Put_EmptyURI_Errors(t *testing.T) {
	store, _ := newTestStatusListCacheStore(t)
	require.Error(t, store.Put("", []byte("v"), time.Now().Add(time.Hour)))
}

func Test_StatusListCacheStore_Put_EmptyRawJwt_Errors(t *testing.T) {
	store, _ := newTestStatusListCacheStore(t)
	require.Error(t, store.Put("uri", nil, time.Now().Add(time.Hour)))
}

func Test_StatusListCacheStore_Get_EmptyURI_ReturnsFalse(t *testing.T) {
	store, _ := newTestStatusListCacheStore(t)
	_, _, ok := store.Get("")
	require.False(t, ok)
}

func Test_StatusListCacheStore_DeleteExpired_RemovesOnlyExpired(t *testing.T) {
	store, _ := newTestStatusListCacheStore(t)
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	require.NoError(t, store.Put("expired", []byte("v"), past))
	require.NoError(t, store.Put("fresh", []byte("v"), future))

	require.NoError(t, store.DeleteExpired(time.Now()))

	_, _, ok := store.Get("expired")
	require.False(t, ok)
	_, _, ok = store.Get("fresh")
	require.True(t, ok)
}
