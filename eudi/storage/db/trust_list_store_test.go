package db

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newTestTrustListStore(t *testing.T) (*TrustListStore, *gorm.DB) {
	t.Helper()

	db, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("super-secret-key-123"))}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.TrustListDocument{}))

	return NewTrustListStore(db), db
}

// Put and Get are the two halves of the wallet's offline copy, and they are wired
// up in different places: Put on every successful refresh, Get only at startup. A
// column name that Put wrote and Get could not read would therefore look like a
// wallet that simply never caches — no error, just a re-fetch every launch.
func TestTrustListStore_GetReadsWhatPutWrote(t *testing.T) {
	store, _ := newTestTrustListStore(t)

	require.NoError(t, store.Put("yivi-staging", []byte("a signed document")))

	got, ok := store.Get("yivi-staging")
	require.True(t, ok)
	require.Equal(t, []byte("a signed document"), got)
}

func TestTrustListStore_ReplacesTheDocumentUnderOneKey(t *testing.T) {
	store, db := newTestTrustListStore(t)

	require.NoError(t, store.Put("yivi-staging", []byte("first")))
	require.NoError(t, store.Put("yivi-staging", []byte("second")))

	got, ok := store.Get("yivi-staging")
	require.True(t, ok)
	require.Equal(t, []byte("second"), got, "a re-issue replaces rather than accumulates")

	var rows int64
	require.NoError(t, db.Model(&models.TrustListDocument{}).Count(&rows).Error)
	require.EqualValues(t, 1, rows)
}

func TestTrustListStore_SourcesAreIndependent(t *testing.T) {
	store, _ := newTestTrustListStore(t)

	require.NoError(t, store.Put("yivi", []byte("one")))
	require.NoError(t, store.Put("some-other-list", []byte("two")))

	first, ok := store.Get("yivi")
	require.True(t, ok)
	require.Equal(t, []byte("one"), first)

	second, ok := store.Get("some-other-list")
	require.True(t, ok)
	require.Equal(t, []byte("two"), second)
}

func TestTrustListStore_MissesAreNotErrors(t *testing.T) {
	store, _ := newTestTrustListStore(t)

	_, ok := store.Get("never-written")
	require.False(t, ok)

	_, ok = store.Get("")
	require.False(t, ok, "an empty key is a miss, not a query")
}

func TestTrustListStore_RefusesToWriteNothing(t *testing.T) {
	store, _ := newTestTrustListStore(t)

	require.Error(t, store.Put("", []byte("document")))
	require.Error(t, store.Put("yivi", nil))
}
