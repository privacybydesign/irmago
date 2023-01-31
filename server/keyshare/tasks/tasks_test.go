//go:build !local_tests
// +build !local_tests

package tasks

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server/keyshare"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	irma.Logger.SetLevel(logrus.FatalLevel)
}

func countRows(t *testing.T, db *sql.DB, table, where string) int {
	query := "SELECT COUNT(*) FROM irma." + table
	if where != "" {
		query += " WHERE " + where
	}
	res, err := db.Query(query)
	require.NoError(t, err)
	require.True(t, res.Next())
	var count int
	require.NoError(t, res.Scan(&count))
	require.NoError(t, res.Close())
	return count
}

func createUser(t *testing.T, db *sql.DB, id int, username string, last_seen int64, delete_on int64, mails []string) {
	_, err := db.Exec("INSERT INTO irma.users (id, username, language, coredata, last_seen, pin_counter, pin_block_date, delete_on) VALUES ($1,$2, '', '', $3, 0, 0, $4)",
		id,
		username,
		last_seen,
		delete_on)
	require.NoError(t, err)

	if len(mails) > 0 {
		for _, m := range mails {
			_, err = db.Exec("INSERT INTO irma.emails (user_id, email, delete_on) VALUES ($1, $2, NULL)",
				id, m)
			require.NoError(t, err)
		}
	}
}

func TestCleanupEmails(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", test.PostgresTestUrl)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 15, '', '', 0,0)")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.emails (user_id, email, delete_on) VALUES (15, 'test@example.com', NULL), (15, 'test2@example.com', $1), (15, 'test3@example.com', 0)", time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)

	th, err := newHandler(&Configuration{DBConnStr: test.PostgresTestUrl, Logger: irma.Logger})
	require.NoError(t, err)

	th.cleanupEmails()

	assert.Equal(t, 2, countRows(t, db, "emails", ""))
}

func TestCleanupTokens(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", test.PostgresTestUrl)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.users (id, username, last_seen, language, coredata, pin_counter, pin_block_date) VALUES (15, 'testuser', 15, '', '', 0,0)")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.email_verification_tokens (token, user_id, email, expiry) VALUES ('t1', 15, 't1@example.com', 0), ('t2', 15, 't2@example.com', $1)", time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.email_login_tokens (token, email, expiry) VALUES ('t1', 't1@example.com', 0), ('t2', 't2@example.com', $1)", time.Now().Add(time.Hour).Unix())
	require.NoError(t, err)

	th, err := newHandler(&Configuration{DBConnStr: test.PostgresTestUrl, Logger: irma.Logger})
	require.NoError(t, err)

	th.cleanupTokens()

	assert.Equal(t, 1, countRows(t, db, "email_verification_tokens", ""))
	assert.Equal(t, 1, countRows(t, db, "email_login_tokens", ""))
}

func TestCleanupAccounts(t *testing.T) {
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", test.PostgresTestUrl)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.users (id, username, language, coredata, pin_counter, pin_block_date, last_seen, delete_on) VALUES (15, 'testuser', '', '', 0,0, 0, NULL), (16, 't2', '', '', 0, 0, 0, $1-3600), (17, 't3', '', '', 0, 0, $1, $1-3600), (18, 't4', '', NULL, 0, 0, $1, $1-3600)", time.Now().Unix())
	require.NoError(t, err)

	th, err := newHandler(&Configuration{DBConnStr: test.PostgresTestUrl, Logger: irma.Logger})
	require.NoError(t, err)

	th.cleanupAccounts()

	assert.Equal(t, 2, countRows(t, db, "users", ""))
}

func TestExpireAccounts(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", test.PostgresTestUrl)
	require.NoError(t, err)

	// TODO: implement createUser here too?
	// 1 expired user without email address
	//createUser(t, db, 10, "ExpiredUserWithoutMail", time.Now().AddDate(-1, -1, 0).Unix(), time.Now().AddDate(1, 0, 0).Unix(), []string{})
	_, err = db.Exec("INSERT INTO irma.users(id, username, language, coredata, pin_counter, pin_block_date, last_seen) VALUES (10, 'ExpiredUserWithoutMail', '', '', 0, 0, $1)",
		time.Now().AddDate(-1, -1, 0).Unix())
	require.NoError(t, err)

	// 1 expired user with email address
	_, err = db.Exec("INSERT INTO irma.users(id, username, language, coredata, pin_counter, pin_block_date, last_seen) VALUES (20, 'ExpiredUserWithMail', '', '', 0, 0, $1)",
		time.Now().AddDate(-1, -1, 0).Unix())
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.emails (user_id, email, delete_on) VALUES (20, 'test_expired@example.com', NULL)")
	require.NoError(t, err)

	// 1 active user without email address
	_, err = db.Exec("INSERT INTO irma.users(id, username, language, coredata, pin_counter, pin_block_date, last_seen) VALUES (30, 'ActiveUserWithoutMail', '', '', 0, 0, $1)",
		time.Now().AddDate(0, 0, -100).Unix())
	require.NoError(t, err)

	// 1 active user with email address
	_, err = db.Exec("INSERT INTO irma.users(id, username, language, coredata, pin_counter, pin_block_date, last_seen) VALUES (40, 'ActiveUserWithMail', '', '', 0, 0, $1)",
		time.Now().AddDate(0, 0, -100).Unix())
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.emails (user_id, email, delete_on) VALUES (40, 'test_active@example.com', NULL)")
	require.NoError(t, err)

	th, err := newHandler(&Configuration{
		DBConnStr:   test.PostgresTestUrl,
		DeleteDelay: 30,
		ExpiryDelay: 365,
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     "localhost:1025",
			EmailFrom:       "test@example.com",
			DefaultLanguage: "en",
		},
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteExpiredAccountSubjects: map[string]string{
			"en": "testsubject",
		},
		Logger: irma.Logger,
	})
	require.NoError(t, err)

	th.expireAccounts()

	assert.Equal(t, 1, countRows(t, db, "users", "delete_on IS NOT NULL"))
	assert.Equal(t, 3, countRows(t, db, "users", "delete_on IS NULL"))

	// 'forward' in time (setting last_seen further in the past)
	_, err = db.Exec("UPDATE irma.users SET last_seen = $1 WHERE id = 30",
		time.Now().AddDate(-1, -1, 0).Unix())
	require.NoError(t, err)

	_, err = db.Exec("UPDATE irma.users SET last_seen = $1 WHERE id = 40",
		time.Now().AddDate(-1, -1, 0).Unix())
	require.NoError(t, err)

	th.expireAccounts()

	assert.Equal(t, 2, countRows(t, db, "users", "delete_on IS NOT NULL"))
	assert.Equal(t, 2, countRows(t, db, "users", "delete_on IS NULL"))
}

func TestWarnForUpcomingAccountDeletion(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", test.PostgresTestUrl)
	require.NoError(t, err)

	// #10: Expiring user with valid e-mail addresses within the 'normal' boundaries
	createUser(t, db, 10, "ExpiringWithValidMail", time.Now().AddDate(-1, -1, -1).Unix(), time.Now().AddDate(0, 0, 20).Unix(), []string{"user_10@github.com", "alternative_addr@github.com"})

	// #20: Expiring user with an invalid e-mail address within the 'normal' boundaries
	createUser(t, db, 20, "ExpiringWithInvalidMail", time.Now().AddDate(-1, -1, -1).Unix(), time.Now().AddDate(0, 0, 20).Unix(), []string{"user_20@github.com", "invalidaddresscom"})

	// #30: Expiring user with a valid e-mail address within the 'forced' boundaries
	createUser(t, db, 30, "ExpiringSoonWithValidMail", time.Now().AddDate(-1, -1, -1).Unix(), time.Now().AddDate(0, 0, 10).Unix(), []string{"user_30@github.com"})

	// #40: Active user outside the boundaries
	createUser(t, db, 40, "AlsoActiveWithValidMail", time.Now().AddDate(0, -1, 0).Unix(), time.Now().AddDate(1, 0, 0).Unix(), []string{"user_40@github.com"})

	// #50: Expired user, should be deleted already but in some magical way is still in the db
	createUser(t, db, 50, "ShouldBeDeletedAlreadyWithValidMail", time.Now().AddDate(-1, -1, -1).Unix(), time.Now().AddDate(0, -1, 0).Unix(), []string{"user_50@github.com"})

	th, err := newHandler(&Configuration{
		DBConnStr:   test.PostgresTestUrl,
		DeleteDelay: 30,
		ExpiryDelay: 365,
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     "localhost:1025",
			EmailFrom:       "test@example.com",
			DefaultLanguage: "en",
		},
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteExpiredAccountSubjects: map[string]string{
			"en": "testsubject",
		},
		Logger: irma.Logger,
	})
	require.NoError(t, err)

	th.warnForUpcomingAccountDeletion()

	// Two users (#10 - normal, #30 - forced) should be processed and therefore have an updated 'last_seen'
	assert.Equal(t, 2, countRows(t, db, "users", fmt.Sprintf("last_seen = %d", time.Now().Unix())))

	time.Sleep(1 * time.Second)
	th.warnForUpcomingAccountDeletion()

	// No user should be processed twice when the task runs again at a later moment
	assert.Equal(t, 0, countRows(t, db, "users", fmt.Sprintf("last_seen = %d", time.Now().Unix())))

	// Update user #20 (forward time to set delete_on to 10 days from now) so he is now 'forced'
	_, err = db.Exec("UPDATE irma.users SET delete_on = $1 WHERE id = 20",
		time.Now().AddDate(0, 0, 10).Unix())
	require.NoError(t, err)

	th.warnForUpcomingAccountDeletion()

	// User #20 is now processed, getting a 'forced' mail because of one of it's invalid email addresses
	assert.Equal(t, 1, countRows(t, db, "users", fmt.Sprintf("last_seen = %d", time.Now().Unix())))
}

func TestConfiguration(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)

	err := processConfiguration(&Configuration{Logger: irma.Logger})
	assert.NoError(t, err)

	err = processConfiguration(&Configuration{
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     "localhost:1025",
			EmailFrom:       "test@example.com",
			DefaultLanguage: "en",
		},
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteExpiredAccountSubjects: map[string]string{
			"en": "testsubject",
		},
		Logger: irma.Logger,
	})
	assert.NoError(t, err)

	err = processConfiguration(&Configuration{
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer: "localhost:1025",
			EmailFrom:   "test@example.com",
		},
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		DeleteExpiredAccountSubjects: map[string]string{
			"en": "testsubject",
		},
		Logger: irma.Logger,
	})
	assert.Error(t, err)

	err = processConfiguration(&Configuration{
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     "localhost:1025",
			EmailFrom:       "test@example.com",
			DefaultLanguage: "en",
		},
		DeleteExpiredAccountSubjects: map[string]string{
			"en": "testsubject",
		},
		Logger: irma.Logger,
	})
	assert.Error(t, err)

	err = processConfiguration(&Configuration{
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     "localhost:1025",
			EmailFrom:       "test@example.com",
			DefaultLanguage: "en",
		},
		DeleteExpiredAccountFiles: map[string]string{
			"en": filepath.Join(testdataPath, "emailtemplate.html"),
		},
		Logger: irma.Logger,
	})
	assert.Error(t, err)
}

func SetupDatabase(t *testing.T) {
	test.RunScriptOnDB(t, "../cleanup.sql", true)
	test.RunScriptOnDB(t, "../schema.sql", false)
}

func TeardownDatabase(t *testing.T) {
	test.RunScriptOnDB(t, "../cleanup.sql", false)
}

/* TODO: what do I want to test:

revisit all tests containing: expireAccounts()

expireAccounts:
- is account unused for more than 1 year set to expire (delete_on)?
	- are these only accounts with one or more email addresses?
- is an account unused less than 1 year not affected

warnForUpcomingAccountDeletion
- does a user not get an mail (when delete_on > 15 days && < 30 days) if one of the mail addresses is not working?
-

to check: what happens with users currently in the db where delete_on is set for example? Do they miss out something, recieve a double mail etc?? -> need to know!
*/
