package keyshareserver

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryDBUserManagement(t *testing.T) {
	db := NewMemoryDB()

	user := &User{Username: "testuser"}
	err := db.AddUser(user)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)

	nuser, err := db.user("testuser")
	require.NoError(t, err)
	assert.Equal(t, "testuser", nuser.Username)

	_, err = db.user("nonexistent")
	assert.Error(t, err)

	user = &User{Username: "testuser"}
	err = db.AddUser(user)
	assert.Error(t, err)

	err = db.updateUser(nuser)
	assert.NoError(t, err)

	err = db.addEmailVerification(nuser, "test@test.com", "testtoken")
	assert.NoError(t, err)

	err = db.addLog(nuser, eventTypePinCheckSuccess, nil)
	assert.NoError(t, err)

	ok, tries, wait, err := db.reservePinTry(nuser)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, tries > 0)
	assert.Equal(t, int64(0), wait)

	err = db.setSeen(nuser)
	assert.NoError(t, err)
}
