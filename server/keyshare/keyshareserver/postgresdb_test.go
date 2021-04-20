//+build !local_tests

package keyshareserver

import (
	"database/sql"
	"io/ioutil"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const postgresTestUrl = "postgresql://localhost:5432/test"

func TestPostgresDBUserManagement(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := NewPostgresDatabase(postgresTestUrl)
	require.NoError(t, err)

	user := &KeyshareUser{Username: "testuser"}
	err = db.NewUser(user)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)

	nuser, err := db.User("testuser")
	require.NoError(t, err)
	assert.Equal(t, "testuser", nuser.Username)

	_, err = db.User("notexist")
	assert.Error(t, err)

	err = db.UpdateUser(nuser)
	assert.NoError(t, err)

	user = &KeyshareUser{Username: "testuser"}
	err = db.NewUser(user)
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

	BACKOFF_START = 2

	db, err := NewPostgresDatabase(postgresTestUrl)
	require.NoError(t, err)

	user := &KeyshareUser{Username: "testuser"}
	err = db.NewUser(user)
	require.NoError(t, err)

	// ReservePincheck sets user fields in the database as if the attempt was wrong. If the attempt
	// was in fact correct, then these fields are cleared again later by the keyshare server by
	// invoking db.ClearPincheck(user). So below we may think of ReservePincheck invocations as
	// wrong pin attempts.

	ok, tries, wait, err := db.ReservePincheck(user)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, MAX_PIN_TRIES-1, tries)
	assert.Equal(t, int64(0), wait)

	// Try until we have no tries left
	for tries != 0 {
		ok, tries, wait, err = db.ReservePincheck(user)
		require.NoError(t, err)
		assert.True(t, ok)
	}

	assert.Equal(t, BACKOFF_START, wait) // next attempt after first timeout

	// We have used all tries; we are now blocked. Wait till just before block end
	time.Sleep(time.Duration(wait-1) * time.Second)

	// Try again, not yet allowed
	ok, tries, wait, err = db.ReservePincheck(user)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, 0, tries)
	assert.Equal(t, int64(1), wait)

	// Wait till just after block end
	time.Sleep(2 * time.Second)

	// Trying is now allowed
	ok, tries, wait, err = db.ReservePincheck(user)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 0, tries)
	assert.Equal(t, 2*BACKOFF_START, wait) // next attempt after doubled timeout

	// Since we just used another attempt we are now blocked again
	ok, tries, wait, err = db.ReservePincheck(user)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, 0, tries)
	assert.Equal(t, 2*BACKOFF_START, wait)

	// Wait to be unblocked again
	time.Sleep(time.Duration(wait+1) * time.Second)

	// Try a final time
	ok, tries, wait, err = db.ReservePincheck(user)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 0, tries)
	assert.Equal(t, 4*BACKOFF_START, wait) // next attempt after again a doubled timeout

	err = db.ClearPincheck(user)
	assert.NoError(t, err)

	ok, tries, wait, err = db.ReservePincheck(user)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, tries > 0)
	assert.Equal(t, int64(0), wait)
}

func RunScriptOnDB(t *testing.T, filename string, allowErr bool) {
	db, err := sql.Open("pgx", postgresTestUrl)
	require.NoError(t, err)
	defer common.Close(db)
	scriptData, err := ioutil.ReadFile(filename)
	require.NoError(t, err)
	_, err = db.Exec(string(scriptData))
	if !allowErr {
		require.NoError(t, err)
	}
}

func SetupDatabase(t *testing.T) {
	RunScriptOnDB(t, "cleanup.sql", true)
	RunScriptOnDB(t, "schema.sql", false)
}

func TeardownDatabase(t *testing.T) {
	RunScriptOnDB(t, "cleanup.sql", false)
}
