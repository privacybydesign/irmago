//+build !local_tests

package keyshareserver

import (
	"database/sql"
	"io/ioutil"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const postgresTestUrl = "postgresql://localhost:5432/test"

func TestPostgresDBUserManagement(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := NewPostgresDatabase(postgresTestUrl)
	require.NoError(t, err)

	user, err := db.NewUser(KeyshareUserData{Username: "testuser"})
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Data().Username)

	nuser, err := db.User("testuser")
	require.NoError(t, err)
	assert.Equal(t, "testuser", nuser.Data().Username)

	_, err = db.User("notexist")
	assert.Error(t, err)

	err = db.UpdateUser(nuser)
	assert.NoError(t, err)

	_, err = db.NewUser(KeyshareUserData{Username: "testuser"})
	assert.Error(t, err)

	err = db.AddLog(nuser, PinCheckFailed, 15)
	assert.NoError(t, err)

	err = db.AddEmailVerification(nuser, "test@example.com", "testtoken")
	assert.NoError(t, err)

	err = db.SetSeen(nuser)
	assert.NoError(t, err)
}

func TestPostgresDBPinReservation(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := NewPostgresDatabase(postgresTestUrl)
	require.NoError(t, err)

	user, err := db.NewUser(KeyshareUserData{Username: "testuser"})
	require.NoError(t, err)

	ok, tries, wait, err := db.ReservePincheck(user)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, tries > 0)
	assert.Equal(t, int64(0), wait)
	for tries != 0 {
		ok, tries, wait, err = db.ReservePincheck(user)
		require.NoError(t, err)
		assert.True(t, ok)
	}

	time.Sleep(time.Duration(wait-5) * time.Second)

	ok, tries, wait, err = db.ReservePincheck(user)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, 0, tries)
	assert.True(t, wait > 0)

	time.Sleep(time.Duration(10 * time.Second))

	ok, tries, wait, err = db.ReservePincheck(user)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 0, tries)
	assert.True(t, wait > 0)

	ok, tries, wait, err = db.ReservePincheck(user)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, 0, tries)
	assert.True(t, wait > 0)

	err = db.ClearPincheck(user)
	assert.NoError(t, err)

	ok, tries, wait, err = db.ReservePincheck(user)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, tries > 0)
	assert.Equal(t, int64(0), wait)
}

func RunScriptOnDB(t *testing.T, filename string) {
	db, err := sql.Open("pgx", postgresTestUrl)
	require.NoError(t, err)
	defer db.Close()
	scriptData, err := ioutil.ReadFile(filename)
	require.NoError(t, err)
	_, err = db.Exec(string(scriptData))
	require.NoError(t, err)
}

func SetupDatabase(t *testing.T) {
	RunScriptOnDB(t, "schema.sql")
}

func TeardownDatabase(t *testing.T) {
	RunScriptOnDB(t, "cleanup.sql")
}
