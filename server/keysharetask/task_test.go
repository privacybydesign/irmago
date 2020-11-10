//+build !local_tests

package keysharetask

import (
	"database/sql"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const postgresTestUrl = "postgresql://localhost:5432/test"

func TestCleanupEmails(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", postgresTestUrl)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 15, '', '', 0,0)")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.emails (user_id, email, delete_on) VALUES (15, 'test@test.com', NULL), (15, 'test2@test.com', $1), (15, 'test3@test.com', 0)", time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)

	th, err := New(&Configuration{DBConnstring: postgresTestUrl})
	require.NoError(t, err)

	th.CleanupEmails()

	res, err := db.Query("SELECT COUNT(*) FROM irma.emails")
	require.NoError(t, err)
	require.True(t, res.Next())
	var count int
	require.NoError(t, res.Scan(&count))
	assert.Equal(t, 2, count)
	_ = res.Close()
}

func TestCleanupTokens(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", postgresTestUrl)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 15, '', '', 0,0)")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.email_verification_tokens (token, user_id, email, expiry) VALUES ('t1', 15, 't1@test.com', 0), ('t2', 15, 't2@test.com', $1)", time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.email_login_tokens (token, email, expiry) VALUES ('t1', 't1@test.com', 0), ('t2', 't2@test.com', $1)", time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)

	th, err := New(&Configuration{DBConnstring: postgresTestUrl})
	require.NoError(t, err)

	th.CleanupTokens()

	res, err := db.Query("SELECT COUNT(*) FROM irma.email_verification_tokens")
	require.NoError(t, err)
	require.True(t, res.Next())
	var count int
	require.NoError(t, res.Scan(&count))
	assert.Equal(t, 1, count)
	_ = res.Close()

	res, err = db.Query("SELECT COUNT(*) FROM irma.email_login_tokens")
	require.NoError(t, err)
	require.True(t, res.Next())
	require.NoError(t, res.Scan(&count))
	assert.Equal(t, 1, count)
	_ = res.Close()
}

func TestCleanupAccounts(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", postgresTestUrl)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.users (id, username, language, coredata, pin_counter, pin_block_date, last_seen, delete_on) VALUES (15, 'testuser', '', '', 0,0, 0, NULL), (16, 't2', '', '', 0, 0, 0, $1-3600), (17, 't3', '', '', 0, 0, $1, $1-3600), (18, 't4', '', NULL, 0, 0, $1, $1-3600)", time.Now().Unix())
	require.NoError(t, err)

	th, err := New(&Configuration{DBConnstring: postgresTestUrl})
	require.NoError(t, err)

	th.CleanupAccounts()

	res, err := db.Query("SELECT COUNT(*) FROM irma.users")
	require.NoError(t, err)
	require.True(t, res.Next())
	var count int
	require.NoError(t, res.Scan(&count))
	assert.Equal(t, 2, count)
	_ = res.Close()
}

func TestExpireAccounts(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", postgresTestUrl)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.users(id, username, language, coredata, pin_counter, pin_block_date, last_seen) VALUES (15, 'A', '', '', 0, 0, $1-12*3600), (16, 'B', '', '', 0, 0, 0), (17, 'C', '', '', 0, 0, 0)", time.Now().Unix())
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.emails (user_id, email, delete_on) VALUES (15, 'test@test.com', NULL), (16, 'test@test.com', NULL)")
	require.NoError(t, err)

	th, err := New(&Configuration{
		DBConnstring:    postgresTestUrl,
		DeleteDelay:     30,
		ExpiryDelay:     1,
		EmailServer:     "localhost:1025",
		EmailFrom:       "test@test.com",
		DefaultLanguage: "en",
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteExpiredAccountSubject: map[string]string{
			"en": "testsubject",
		},
	})
	require.NoError(t, err)

	th.ExpireAccounts()

	res, err := db.Query("SELECT COUNT(*) FROM irma.users WHERE delete_on IS NOT NULL")
	require.NoError(t, err)
	require.True(t, res.Next())
	var count int
	require.NoError(t, res.Scan(&count))
	assert.Equal(t, 1, count)
	_ = res.Close()
}

func RunScriptOnDB(t *testing.T, filename string) {
	db, err := sql.Open("pgx", postgresTestUrl)
	require.NoError(t, err)
	scriptData, err := ioutil.ReadFile(filename)
	require.NoError(t, err)
	_, err = db.Exec(string(scriptData))
	require.NoError(t, err)
	_ = db.Close()
}

func SetupDatabase(t *testing.T) {
	RunScriptOnDB(t, "../keyshareserver/schema.sql")
}

func TeardownDatabase(t *testing.T) {
	RunScriptOnDB(t, "../keyshareserver/cleanup.sql")
}
