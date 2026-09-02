package db

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newTestWalletConfigStore(t *testing.T) *WalletConfigStore {
	t.Helper()
	db, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("super-secret-key-123"))}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.WalletConfigDocument{}))
	return NewWalletConfigStore(db)
}

func Test_WalletConfigStore_PutThenGet_RoundtripsTheDocument(t *testing.T) {
	store := newTestWalletConfigStore(t)
	require.NoError(t, store.Put("production", []byte("signed config")))

	raw, ok := store.Get("production")
	require.True(t, ok)
	require.Equal(t, []byte("signed config"), raw)
}

func Test_WalletConfigStore_Get_Miss_ReturnsFalse(t *testing.T) {
	store := newTestWalletConfigStore(t)
	_, ok := store.Get("production")
	require.False(t, ok)
	_, ok = store.Get("")
	require.False(t, ok)
}

func Test_WalletConfigStore_Put_ReplacesTheEnvironmentsDocument(t *testing.T) {
	store := newTestWalletConfigStore(t)
	require.NoError(t, store.Put("production", []byte("v1")))
	require.NoError(t, store.Put("production", []byte("v2")))

	raw, ok := store.Get("production")
	require.True(t, ok)
	require.Equal(t, []byte("v2"), raw)
}

func Test_WalletConfigStore_KeepsEnvironmentsApart(t *testing.T) {
	store := newTestWalletConfigStore(t)
	require.NoError(t, store.Put("production", []byte("prod")))
	require.NoError(t, store.Put("staging", []byte("stag")))

	raw, _ := store.Get("production")
	require.Equal(t, []byte("prod"), raw)
	raw, _ = store.Get("staging")
	require.Equal(t, []byte("stag"), raw)
}

func Test_WalletConfigStore_Put_RejectsEmptyKeyOrDocument(t *testing.T) {
	store := newTestWalletConfigStore(t)
	require.ErrorContains(t, store.Put("", []byte("x")), "empty environment")
	require.ErrorContains(t, store.Put("production", nil), "empty document")
}
