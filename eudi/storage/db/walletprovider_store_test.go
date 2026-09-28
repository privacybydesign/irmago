package db

import (
	"errors"
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/privacybydesign/irmago/walletprovider"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newTestWalletProviderStorage(t *testing.T) walletprovider.Storage {
	t.Helper()
	db, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("super-secret-key-123"))}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.WalletProviderValue{}))
	return NewWalletProviderStorage(db)
}

func TestWalletProviderStoragePutGetDelete(t *testing.T) {
	s := newTestWalletProviderStorage(t)

	_, err := s.Get("missing")
	require.ErrorIs(t, err, walletprovider.ErrNotFound)

	require.NoError(t, s.Update(func(tx walletprovider.StorageTx) error {
		if err := tx.Put("a", []byte("one")); err != nil {
			return err
		}
		// Overwriting within the same transaction, and reading it back.
		if err := tx.Put("a", []byte("two")); err != nil {
			return err
		}
		v, err := tx.Get("a")
		require.NoError(t, err)
		require.Equal(t, []byte("two"), v)
		return tx.Put("b", []byte("bee"))
	}))

	v, err := s.Get("a")
	require.NoError(t, err)
	require.Equal(t, []byte("two"), v)

	require.NoError(t, s.Update(func(tx walletprovider.StorageTx) error { return tx.Delete("a") }))
	_, err = s.Get("a")
	require.ErrorIs(t, err, walletprovider.ErrNotFound)
	v, err = s.Get("b")
	require.NoError(t, err)
	require.Equal(t, []byte("bee"), v)
}

func TestWalletProviderStorageUpdateRollsBackOnError(t *testing.T) {
	s := newTestWalletProviderStorage(t)
	require.NoError(t, s.Update(func(tx walletprovider.StorageTx) error { return tx.Put("sn", []byte("1")) }))

	boom := errors.New("boom")
	err := s.Update(func(tx walletprovider.StorageTx) error {
		if err := tx.Put("sn", []byte("2")); err != nil {
			return err
		}
		if err := tx.Put("other", []byte("x")); err != nil {
			return err
		}
		return boom
	})
	require.ErrorIs(t, err, boom)

	v, err := s.Get("sn")
	require.NoError(t, err)
	require.Equal(t, []byte("1"), v)
	_, err = s.Get("other")
	require.ErrorIs(t, err, walletprovider.ErrNotFound)
}
