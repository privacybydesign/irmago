//go:build !local_tests
// +build !local_tests

package tasks

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strconv"
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

func countDeleteDates(t *testing.T, db *sql.DB) map[string]int {
	res, err := db.Query("SELECT delete_on FROM irma.users WHERE delete_on IS NOT NULL")
	require.NoError(t, err)

	dateMap := make(map[string]int)
	for res.Next() {
		var date int64
		require.NoError(t, res.Scan(&date))
		dateMap[strconv.FormatInt(date, 10)] += 1
	}
	require.NoError(t, res.Close())

	return dateMap
}

func createUser(t *testing.T, db *sql.DB, id int, username string, lastSeen int64, mails []string) {
	_, err := db.Exec("INSERT INTO irma.users (id, username, language, coredata, last_seen, pin_counter, pin_block_date) VALUES ($1,$2, '', '', $3, 0, 0)",
		id,
		username,
		lastSeen)
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

	require.NoError(t, runWithTimeout(th.cleanupEmails))

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

	require.NoError(t, runWithTimeout(th.cleanupTokens))

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

	require.NoError(t, runWithTimeout(th.cleanupAccounts))

	assert.Equal(t, 2, countRows(t, db, "users", ""))
}

func xTimesEntry(x int, template string) (result string) {
	for i := 0; i < x; i++ {
		nr := strconv.Itoa(i)
		result += fmt.Sprintf(template, nr, nr)
	}
	return
}

func TestExpireAccounts(t *testing.T) {
	testdataPath := test.FindTestdataFolder(t)
	SetupDatabase(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", test.PostgresTestUrl)
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.users(id, username, language, coredata, pin_counter, pin_block_date, last_seen) VALUES (15, 'A', '', '', 0, 0, $1-12*3600), "+
		xTimesEntry(12, "(%s, 'ExpiredUser%s', '', '', 0, 0, 0), ")+
		"(28, 'ExpiredUserWithoutMail', '', '', 0, 0, 0)", time.Now().Unix())
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO irma.emails (user_id, email, delete_on) VALUES (15, 'test@example.com', NULL), " +
		xTimesEntry(12, "(%s, 'test%s@example.com', NULL), ") +
		"(28, 'test@example.com', NULL)")
	require.NoError(t, err)

	th, err := newHandler(&Configuration{
		DBConnStr:   test.PostgresTestUrl,
		DeleteDelay: 30,
		ExpiryDelay: 1,
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

	require.NoError(t, runWithTimeout(th.expireAccounts))
	deleteOnMap := countDeleteDates(t, db)

	assert.Equal(t, 10, countRows(t, db, "users", "delete_on IS NOT NULL"))
	assert.Equal(t, 4, countRows(t, db, "users", "delete_on IS NULL"))

	time.Sleep(1 * time.Second)
	require.NoError(t, runWithTimeout(th.expireAccounts))

	for date, count := range deleteOnMap {
		assert.Equal(t, count, countRows(t, db, "users", "delete_on = "+date))
	}
	assert.Equal(t, 13, countRows(t, db, "users", "delete_on IS NOT NULL"))
	assert.Equal(t, 1, countRows(t, db, "users", "delete_on IS NULL"))
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

func TestEmailRevalidation(t *testing.T) {
	SetupDatabase(t)
	testdataPath := test.FindTestdataFolder(t)
	defer TeardownDatabase(t)

	db, err := sql.Open("pgx", test.PostgresTestUrl)
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

	createUser(t, db, 1, "TemporaryInvalid", time.Now().AddDate(-1, -1, -1).Unix(), []string{"user_1@temporaryinvalidaddress.com"})
	createUser(t, db, 2, "PermanentInvalid", time.Now().AddDate(-1, -1, -1).Unix(), []string{"user_2@permenantlyinvalidaddress.com"})

	require.NoError(t, runWithTimeout(th.expireAccounts))
	require.NoError(t, runWithTimeout(th.revalidateMails))

	// Is revalidate_on set for both email addresses?
	assert.Equal(t, 2, countRows(t, db, "emails", "revalidate_on IS NOT NULL"))

	// Correct the temporary invalid e-mail address to a valid one, simulating it becoming valid, and 'forward time'
	_, err = db.Exec("UPDATE irma.emails SET email = $1, revalidate_on = $2 WHERE id = $3", "user_1@github.com", time.Now().AddDate(0, 0, -1).Unix(), 1)
	require.NoError(t, err)

	// Forward time for the invalid address
	_, err = db.Exec("UPDATE irma.emails SET revalidate_on = $1 WHERE id = $2", time.Now().AddDate(0, 0, -1).Unix(), 2)
	require.NoError(t, err)

	// Next revalidation run: the invalid email address should be deleted now
	require.NoError(t, runWithTimeout(th.revalidateMails))

	assert.Equal(t, 1, countRows(t, db, "emails", ""))
}

func SetupDatabase(t *testing.T) {
	test.RunScriptOnDB(t, "../cleanup.sql", true)
	test.RunScriptOnDB(t, "../schema.sql", false)
}

func TeardownDatabase(t *testing.T) {
	test.RunScriptOnDB(t, "../cleanup.sql", false)
}
