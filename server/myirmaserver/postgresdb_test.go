//+build !local_tests

package myirmaserver

import (
	"database/sql"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const postgresTestUrl = "postgresql://localhost:5432/test"

func TestPostgresDBUserManagement(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := NewPostgresDatabase(postgresTestUrl, 0)
	require.NoError(t, err)

	pdb := db.(*myirmaPostgresDB)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 0, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.email_verification_tokens (token, email, expiry, user_id) VALUES ('testtoken', 'test@test.com', $1, 15)", time.Now().Unix())
	require.NoError(t, err)

	id, err := db.GetUserID("testuser")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	id, err = db.VerifyEmailToken("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	_, err = db.VerifyEmailToken("testtoken")
	assert.Error(t, err)

	_, err = db.GetUserID("DNE")
	assert.Error(t, err)

	err = db.SetSeen(15)
	assert.NoError(t, err)

	err = db.SetSeen(123456)
	assert.Error(t, err)

	err = db.RemoveUser(15)
	assert.NoError(t, err)

	err = db.RemoveUser(15)
	assert.Error(t, err)
}

func TestPostgresDBLoginToken(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := NewPostgresDatabase(postgresTestUrl, 0)
	require.NoError(t, err)

	pdb := db.(*myirmaPostgresDB)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 0, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (17, 'noemail', 0, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.emails (user_id, email) VALUES (15, 'test@test.com')")
	require.NoError(t, err)

	err = db.AddEmailLoginToken("test2@test.com", "test2token")
	assert.Error(t, err)

	err = db.AddEmailLoginToken("test@test.com", "testtoken")
	require.NoError(t, err)

	cand, err := db.LoginTokenGetCandidates("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, []LoginCandidate{LoginCandidate{Username: "testuser", LastActive: 0}}, cand)

	_, err = db.LoginTokenGetCandidates("DNE")
	assert.Error(t, err)

	email, err := db.LoginTokenGetEmail("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, "test@test.com", email)

	_, err = db.LoginTokenGetEmail("DNE")
	assert.Error(t, err)

	_, err = db.TryUserLoginToken("testtoken", "DNE")
	assert.Error(t, err)

	_, err = db.TryUserLoginToken("testtoken", "noemail")
	assert.Error(t, err)

	ok, err := db.TryUserLoginToken("testtoken", "testuser")
	assert.NoError(t, err)
	assert.True(t, ok)

	_, err = db.TryUserLoginToken("testtoken", "testuser")
	assert.Error(t, err)
}

func TestPostgresDBUserInfo(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := NewPostgresDatabase(postgresTestUrl, 0)
	require.NoError(t, err)

	pdb := db.(*myirmaPostgresDB)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 15, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (17, 'noemail', 20, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.emails (user_id, email) VALUES (15, 'test@test.com')")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.log_entry_records (time, event, param, user_id) VALUES (110, 'test', '', 15), (120, 'test2', '15', 15)")
	require.NoError(t, err)

	info, err := db.GetUserInformation(15)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", info.Username)
	assert.Equal(t, []string{"test@test.com"}, info.Emails)

	info, err = db.GetUserInformation(17)
	assert.NoError(t, err)
	assert.Equal(t, "noemail", info.Username)
	assert.Equal(t, []string(nil), info.Emails)

	_, err = db.GetUserInformation(1231)
	assert.Error(t, err)

	entries, err := db.GetLogs(15, 0, 2)
	assert.NoError(t, err)
	assert.Equal(t, []LogEntry{
		LogEntry{
			Timestamp: 120,
			Event:     "test2",
			Param:     "15",
		},
		LogEntry{
			Timestamp: 110,
			Event:     "test",
			Param:     "",
		},
	}, entries)

	entries, err = db.GetLogs(15, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	entries, err = db.GetLogs(15, 1, 15)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	entries, err = db.GetLogs(15, 100, 20)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(entries))

	entries, err = db.GetLogs(20, 100, 20)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(entries))

	err = db.AddEmail(17, "test@test.com")
	assert.NoError(t, err)

	info, err = db.GetUserInformation(17)
	assert.NoError(t, err)
	assert.Equal(t, []string{"test@test.com"}, info.Emails)

	err = db.AddEmail(20, "bla@bla.com")
	assert.Error(t, err)

	err = db.RemoveEmail(17, "test@test.com")
	assert.NoError(t, err)

	// Need sleep here to ensure time has passed since delete
	time.Sleep(1 * time.Second)

	info, err = db.GetUserInformation(17)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(info.Emails))

	err = db.RemoveEmail(17, "bla@bla.com")
	assert.Error(t, err)

	err = db.RemoveEmail(20, "bl@bla.com")
	assert.Error(t, err)
}

func RunScriptOnDB(t *testing.T, filename string) {
	db, err := sql.Open("pgx", postgresTestUrl)
	require.NoError(t, err)
	defer db.Close()
	script, err := os.Open(filename)
	require.NoError(t, err)
	defer script.Close()
	scriptData, err := ioutil.ReadAll(script)
	require.NoError(t, err)
	_, err = db.Exec(string(scriptData))
	require.NoError(t, err)
}

func SetupDatabase(t *testing.T) {
	RunScriptOnDB(t, "../keyshareserver/schema.sql")
}

func TeardownDatabase(t *testing.T) {
	RunScriptOnDB(t, "../keyshareserver/cleanup.sql")
}
