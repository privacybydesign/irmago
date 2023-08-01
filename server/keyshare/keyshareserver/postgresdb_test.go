//go:build !local_tests
// +build !local_tests

package keyshareserver

import (
	"context"
	"fmt"
	"github.com/privacybydesign/irmago/server"
	"math"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresDBUserManagement(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := newPostgresDB(test.PostgresTestUrl, 2, 0, 0, 0)
	require.NoError(t, err)

	user := &User{Username: "testuser", Secrets: []byte{123}}
	err = db.AddUser(context.Background(), user)
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)

	nuser, err := db.user(context.Background(), "testuser")
	require.NoError(t, err)
	assert.Equal(t, user, nuser)

	_, err = db.user(context.Background(), "notexist")
	assert.Error(t, err)

	err = db.updateUser(context.Background(), nuser)
	assert.NoError(t, err)

	user = &User{Username: "testuser", Secrets: []byte{123}}
	err = db.AddUser(context.Background(), user)
	assert.Error(t, err)

	err = db.addLog(context.Background(), nuser, eventTypePinCheckFailed, 15)
	assert.NoError(t, err)

	for i := 0; i < emailTokenRateLimit; i++ {
		err = db.addEmailVerification(context.Background(), nuser, "test@example.com", fmt.Sprintf("testtoken-%d", i), 168)
		assert.NoError(t, err)
	}

	err = db.addEmailVerification(context.Background(), nuser, "test@example.com", "testtoken-rate-limited", 168)
	assert.ErrorIs(t, err, errTooManyTokens)

	err = db.setSeen(context.Background(), nuser)
	assert.NoError(t, err)
}

func TestPostgresDBPinReservation(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	backoffStart = 2

	db, err := newPostgresDB(test.PostgresTestUrl, 2, 0, 0, 0)
	require.NoError(t, err)

	user := &User{Username: "testuser", Secrets: []byte{123}}
	err = db.AddUser(context.Background(), user)
	require.NoError(t, err)

	// reservePinTry sets user fields in the database as if the attempt was wrong. If the attempt
	// was in fact correct, then these fields are cleared again later by the keyshare server by
	// invoking db.resetPinTries(user). So below we may think of reservePinTry invocations as
	// wrong pin attempts.

	ok, tries, wait, err := db.reservePinTry(context.Background(), user)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, maxPinTries-1, tries)
	assert.Equal(t, int64(0), wait)

	// Try until we have no tries left
	for tries != 0 {
		ok, tries, wait, err = db.reservePinTry(context.Background(), user)
		require.NoError(t, err)
		assert.True(t, ok)
	}

	assert.Equal(t, backoffStart, wait) // next attempt after first timeout

	// We have used all tries; we are now blocked. Wait till just before block end
	time.Sleep(time.Duration(wait-1) * time.Second)

	// Try again, not yet allowed
	ok, tries, wait, err = db.reservePinTry(context.Background(), user)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, 0, tries)
	assert.Equal(t, int64(1), wait)

	// Wait till just after block end
	time.Sleep(2 * time.Second)

	// Trying is now allowed
	ok, tries, wait, err = db.reservePinTry(context.Background(), user)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 0, tries)
	assert.Equal(t, 2*backoffStart, wait) // next attempt after doubled timeout

	// Since we just used another attempt we are now blocked again
	ok, tries, wait, err = db.reservePinTry(context.Background(), user)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Equal(t, 0, tries)
	assert.Equal(t, 2*backoffStart, wait)

	// Wait to be unblocked again
	time.Sleep(time.Duration(wait+1) * time.Second)

	// Try a final time
	ok, tries, wait, err = db.reservePinTry(context.Background(), user)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 0, tries)
	assert.Equal(t, 4*backoffStart, wait) // next attempt after again a doubled timeout

	err = db.resetPinTries(context.Background(), user)
	assert.NoError(t, err)

	ok, tries, wait, err = db.reservePinTry(context.Background(), user)
	assert.NoError(t, err)
	assert.True(t, ok)
	assert.True(t, tries > 0)
	assert.Equal(t, int64(0), wait)
}

func TestPostgresDBTimeout(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := newPostgresDB(test.PostgresTestUrl, 2, 0, 0, 0)
	require.NoError(t, err)
	pdb, ok := db.(*postgresDB)
	require.True(t, ok)

	// Delay database queries with server.WriteTimeout to enforce timeouts.
	writeTimeout := int(math.Ceil(server.WriteTimeout.Seconds()))
	delayedDB := &testPostgresDB{pdb, writeTimeout}

	keyshareServer, httpServer := StartKeyshareServer(t, delayedDB, "")
	defer StopKeyshareServer(t, keyshareServer, httpServer)

	// We expect a 500 status, because the database is not responding on time.
	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/client/register",
		`{"pin":"testpin","language":"en"}`, nil,
		500, nil,
	)

	// Reduce delay to check that requests start working again.
	delayedDB.delay = writeTimeout / 2

	test.HTTPPost(t, nil, "http://localhost:8080/api/v1/client/register",
		`{"pin":"testpin","language":"en"}`, nil,
		200, nil,
	)
}

func SetupDatabase(t *testing.T) {
	test.RunScriptOnDB(t, "../cleanup.sql", true)
	test.RunScriptOnDB(t, "../schema.sql", false)
}

func TeardownDatabase(t *testing.T) {
	test.RunScriptOnDB(t, "../cleanup.sql", false)
}

type testPostgresDB struct {
	wrapped *postgresDB
	delay   int
}

func (db *testPostgresDB) AddUser(ctx context.Context, user *User) error {
	if _, err := db.wrapped.db.ExecContext(ctx, "SELECT pg_sleep($1)", db.delay); err != nil {
		return err
	}
	return db.wrapped.AddUser(ctx, user)
}

func (db *testPostgresDB) user(ctx context.Context, username string) (*User, error) {
	if _, err := db.wrapped.db.ExecContext(ctx, "SELECT pg_sleep($1)", db.delay); err != nil {
		return nil, err
	}
	return db.wrapped.user(ctx, username)
}

func (db *testPostgresDB) updateUser(ctx context.Context, user *User) error {
	if _, err := db.wrapped.db.ExecContext(ctx, "SELECT pg_sleep($1)", db.delay); err != nil {
		return err
	}
	return db.wrapped.updateUser(ctx, user)
}

func (db *testPostgresDB) reservePinTry(ctx context.Context, user *User) (bool, int, int64, error) {
	if _, err := db.wrapped.db.ExecContext(ctx, "SELECT pg_sleep($1)", db.delay); err != nil {
		return false, 0, 0, err
	}
	return db.wrapped.reservePinTry(ctx, user)
}

func (db *testPostgresDB) resetPinTries(ctx context.Context, user *User) error {
	if _, err := db.wrapped.db.ExecContext(ctx, "SELECT pg_sleep($1)", db.delay); err != nil {
		return err
	}
	return db.wrapped.resetPinTries(ctx, user)
}

func (db *testPostgresDB) setSeen(ctx context.Context, user *User) error {
	if _, err := db.wrapped.db.ExecContext(ctx, "SELECT pg_sleep($1)", db.delay); err != nil {
		return err
	}
	return db.wrapped.setSeen(ctx, user)
}

func (db *testPostgresDB) addLog(ctx context.Context, user *User, eventType eventType, param interface{}) error {
	if _, err := db.wrapped.db.ExecContext(ctx, "SELECT pg_sleep($1)", db.delay); err != nil {
		return err
	}
	return db.wrapped.addLog(ctx, user, eventType, param)
}

func (db *testPostgresDB) addEmailVerification(ctx context.Context, user *User, emailAddress, token string, validity int) error {
	if _, err := db.wrapped.db.ExecContext(ctx, "SELECT pg_sleep($1)", db.delay); err != nil {
		return err
	}
	return db.wrapped.addEmailVerification(ctx, user, emailAddress, token, validity)
}
