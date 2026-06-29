package db

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newTestKbJwtReplayStore(t *testing.T) KbJwtReplayStore {
	t.Helper()

	database, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("super-secret-key-123"))}, &gorm.Config{})
	require.NoError(t, err)

	sqlDB, err := database.DB()
	require.NoError(t, err)
	require.NoError(t, RunMigrations(sqlDB))

	return NewKbJwtReplayStore(database)
}

func TestKbJwtReplayStore_StoreAndExistsDigest(t *testing.T) {
	store := newTestKbJwtReplayStore(t)

	expiresAt := time.Now().UTC().Add(5 * time.Minute)
	require.NoError(t, store.StoreDigest("digest-1", expiresAt))

	exists, err := store.ExistsDigest("digest-1")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestKbJwtReplayStore_StoreDigestDuplicateFails(t *testing.T) {
	store := newTestKbJwtReplayStore(t)

	expiresAt := time.Now().UTC().Add(5 * time.Minute)
	require.NoError(t, store.StoreDigest("digest-duplicate", expiresAt))

	err := store.StoreDigest("digest-duplicate", expiresAt)
	require.Error(t, err)
}

func TestKbJwtReplayStore_DeleteExpired(t *testing.T) {
	store := newTestKbJwtReplayStore(t)

	now := time.Now().UTC()
	require.NoError(t, store.StoreDigest("digest-expired", now.Add(-1*time.Minute)))
	require.NoError(t, store.StoreDigest("digest-future", now.Add(5*time.Minute)))

	require.NoError(t, store.DeleteExpired(now))

	existsExpired, err := store.ExistsDigest("digest-expired")
	require.NoError(t, err)
	assert.False(t, existsExpired)

	existsFuture, err := store.ExistsDigest("digest-future")
	require.NoError(t, err)
	assert.True(t, existsFuture)
}

func TestKbJwtReplayStore_DeleteAll(t *testing.T) {
	store := newTestKbJwtReplayStore(t)

	now := time.Now().UTC().Add(5 * time.Minute)
	require.NoError(t, store.StoreDigest("digest-a", now))
	require.NoError(t, store.StoreDigest("digest-b", now))

	require.NoError(t, store.DeleteAll())

	existsA, err := store.ExistsDigest("digest-a")
	require.NoError(t, err)
	assert.False(t, existsA)

	existsB, err := store.ExistsDigest("digest-b")
	require.NoError(t, err)
	assert.False(t, existsB)
}
