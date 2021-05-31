//+build !local_tests

package myirmaserver

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresDBUserManagement(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := newPostgresDB(test.PostgresTestUrl)
	require.NoError(t, err)

	pdb := db.(*postgresDB)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 0, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.email_verification_tokens (token, email, expiry, user_id) VALUES ('testtoken', 'test@test.com', $1, 15)", time.Now().Unix())
	require.NoError(t, err)

	id, err := db.userIDByUsername("testuser")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	user, err := db.user(id)
	assert.NoError(t, err)
	assert.Equal(t, []userEmail(nil), user.Emails)

	id, err = db.userIDByEmailToken("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	user, err = db.user(id)
	assert.NoError(t, err)
	assert.Equal(t, []userEmail{{Email: "test@test.com", DeleteInProgress: false}}, user.Emails)

	_, err = db.userIDByEmailToken("testtoken")
	assert.Error(t, err)

	_, err = db.userIDByUsername("DNE")
	assert.Error(t, err)

	err = db.setSeen(15)
	assert.NoError(t, err)

	err = db.setSeen(123456)
	assert.Error(t, err)

	err = db.scheduleUserRemoval(15, 0)
	assert.NoError(t, err)

	err = db.scheduleUserRemoval(15, 0)
	assert.Error(t, err)
}

func TestPostgresDBLoginToken(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := newPostgresDB(test.PostgresTestUrl)
	require.NoError(t, err)

	pdb := db.(*postgresDB)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 0, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (17, 'noemail', 0, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.emails (user_id, email) VALUES (15, 'test@test.com')")
	require.NoError(t, err)

	err = db.addEmailLoginToken("test2@test.com", "test2token")
	assert.Error(t, err)

	err = db.addEmailLoginToken("test@test.com", "testtoken")
	require.NoError(t, err)

	cand, err := db.loginUserCandidates("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, []loginCandidate{{Username: "testuser", LastActive: 0}}, cand)

	currenttime := time.Now().Unix()
	require.NoError(t, db.setSeen(int64(15)))
	cand, err = db.loginUserCandidates("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, []loginCandidate{{Username: "testuser", LastActive: currenttime}}, cand)

	_, err = db.loginUserCandidates("DNE")
	assert.Error(t, err)

	_, err = db.userIDByLoginToken("testtoken", "DNE")
	assert.Error(t, err)

	_, err = db.userIDByLoginToken("testtoken", "noemail")
	assert.Error(t, err)

	id, err := db.userIDByLoginToken("testtoken", "testuser")
	assert.NoError(t, err)
	assert.Equal(t, int64(15), id)

	_, err = db.userIDByLoginToken("testtoken", "testuser")
	assert.Error(t, err)

	assert.NoError(t, db.addEmail(17, "test@test.com"))
	assert.NoError(t, db.addEmailLoginToken("test@test.com", "testtoken"))
	cand, err = db.loginUserCandidates("testtoken")
	assert.NoError(t, err)
	assert.Equal(t, []loginCandidate{
		{Username: "testuser", LastActive: currenttime},
		{Username: "noemail", LastActive: 0},
	}, cand)
}

var (
	str15    = "15"
	strEmpty = ""
)

func TestPostgresDBUserInfo(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := newPostgresDB(test.PostgresTestUrl)
	require.NoError(t, err)

	pdb := db.(*postgresDB)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 15, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (17, 'noemail', 20, '', '', 0,0)")
	require.NoError(t, err)
	_, err = pdb.db.Exec("INSERT INTO irma.emails (user_id, email) VALUES (15, 'test@test.com')")
	require.NoError(t, err)
	_, err = pdb.db.Exec(
		`INSERT INTO irma.log_entry_records (time, event, param, user_id)
		 VALUES (110, 'test', '', 15), (120, 'test2', '15', 15), (130, 'test3', NULL, 15)`)
	require.NoError(t, err)

	info, err := db.user(15)
	assert.NoError(t, err)
	assert.Equal(t, "testuser", info.Username)
	assert.Equal(t, []userEmail{{Email: "test@test.com", DeleteInProgress: false}}, info.Emails)

	info, err = db.user(17)
	assert.NoError(t, err)
	assert.Equal(t, "noemail", info.Username)
	assert.Equal(t, []userEmail(nil), info.Emails)

	_, err = db.user(1231)
	assert.Error(t, err)

	entries, err := db.logs(15, 0, 3)
	assert.NoError(t, err)
	assert.Equal(t, []logEntry{
		{
			Timestamp: 130,
			Event:     "test3",
			Param:     nil,
		},
		{
			Timestamp: 120,
			Event:     "test2",
			Param:     &str15,
		},
		{
			Timestamp: 110,
			Event:     "test",
			Param:     &strEmpty,
		},
	}, entries)

	entries, err = db.logs(15, 0, 1)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))

	entries, err = db.logs(15, 1, 15)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(entries))

	entries, err = db.logs(15, 100, 20)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(entries))

	entries, err = db.logs(20, 100, 20)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(entries))

	err = db.addEmail(17, "test@test.com")
	assert.NoError(t, err)

	info, err = db.user(17)
	assert.NoError(t, err)
	assert.Equal(t, []userEmail{{Email: "test@test.com", DeleteInProgress: false}}, info.Emails)

	err = db.addEmail(20, "bla@bla.com")
	assert.Error(t, err)

	err = db.scheduleEmailRemoval(17, "test@test.com", 0)
	assert.NoError(t, err)

	// Need sleep here to ensure time has passed since delete
	time.Sleep(1 * time.Second)

	info, err = db.user(17)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(info.Emails))

	err = db.scheduleEmailRemoval(17, "bla@bla.com", 0)
	assert.Error(t, err)

	err = db.scheduleEmailRemoval(20, "bl@bla.com", 0)
	assert.Error(t, err)
}

func SetupDatabase(t *testing.T) {
	test.RunScriptOnDB(t, "../keyshareserver/cleanup.sql", true)
	test.RunScriptOnDB(t, "../keyshareserver/schema.sql", false)
}

func TeardownDatabase(t *testing.T) {
	test.RunScriptOnDB(t, "../keyshareserver/cleanup.sql", false)
}
