package keyshareserver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryDBUserManagement(t *testing.T) {
	db := NewMemoryDB()

	user := &User{Username: "testuser"}
	err := db.AddUser(context.Background(), user)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)

	nuser, err := db.user(context.Background(), "testuser")
	require.NoError(t, err)
	assert.Equal(t, context.Background(), "testuser", nuser.Username)

	_, err = db.user(context.Background(), "nonexistent")
	assert.Error(t, err)

	user = &User{Username: "testuser"}
	err = db.AddUser(context.Background(), user)
	assert.Error(t, err)

	err = db.updateUser(context.Background(), nuser)
	assert.NoError(t, err)

	err = db.addEmailVerification(context.Background(), nuser, "test@example.com", "testtoken", 168)
	assert.NoError(t, err)

	err = db.addLog(context.Background(), nuser, eventTypePinCheckSuccess, nil)
	assert.NoError(t, err)

	ok, tries, wait, err := db.reservePinTry(context.Background(), nuser)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, tries > 0)
	assert.Equal(t, int64(0), wait)

	err = db.setSeen(context.Background(), nuser)
	assert.NoError(t, err)
}
