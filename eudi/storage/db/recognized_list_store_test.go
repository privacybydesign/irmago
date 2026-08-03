package db

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/lote"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newTestRecognizedListStore(t *testing.T) lote.Store {
	t.Helper()
	const passphrase = "super-secret-key-123"
	db, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte(passphrase))}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.RecognizedTrustListEntry{}))
	return NewRecognizedListStore(db)
}

func Test_RecognizedListStore_PutThenGet_RoundtripsTheList(t *testing.T) {
	store := newTestRecognizedListStore(t)
	nextUpdate := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	require.NoError(t, store.Put("yivi", &lote.StoredList{
		Raw:            []byte("signed-list"),
		SequenceNumber: 7,
		NextUpdate:     nextUpdate,
	}))

	stored, err := store.Get("yivi")
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Equal(t, []byte("signed-list"), stored.Raw)
	require.Equal(t, int64(7), stored.SequenceNumber)
	require.WithinDuration(t, nextUpdate, stored.NextUpdate.UTC(), time.Second)
}

func Test_RecognizedListStore_Get_Miss_ReturnsNothing(t *testing.T) {
	store := newTestRecognizedListStore(t)

	stored, err := store.Get("yivi")
	require.NoError(t, err)
	require.Nil(t, stored, "an absent list is not an error: the wallet ranks without it")
}

func Test_RecognizedListStore_Put_Upserts(t *testing.T) {
	store := newTestRecognizedListStore(t)
	require.NoError(t, store.Put("yivi", &lote.StoredList{Raw: []byte("revision-1"), SequenceNumber: 1}))
	require.NoError(t, store.Put("yivi", &lote.StoredList{Raw: []byte("revision-2"), SequenceNumber: 2}))

	stored, err := store.Get("yivi")
	require.NoError(t, err)
	require.Equal(t, []byte("revision-2"), stored.Raw)
	require.Equal(t, int64(2), stored.SequenceNumber)
}

func Test_RecognizedListStore_Put_RejectsAnEmptyList(t *testing.T) {
	store := newTestRecognizedListStore(t)
	require.Error(t, store.Put("", &lote.StoredList{Raw: []byte("signed-list")}))
	require.Error(t, store.Put("yivi", &lote.StoredList{}))
	require.Error(t, store.Put("yivi", nil))
}
