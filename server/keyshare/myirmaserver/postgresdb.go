package myirmaserver

import (
	"database/sql"
	"time"

	"github.com/go-errors/errors"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"
)

type myirmaPostgresDB struct {
	db keyshare.DB
}

const EMAIL_TOKEN_VALIDITY = 60 // amount of time an email login token is valid (in minutes)

var ErrEmailNotFound = errors.New("Email address not found")

func NewPostgresDatabase(connstring string) (MyirmaDB, error) {
	db, err := sql.Open("pgx", connstring)
	if err != nil {
		return nil, err
	}
	return &myirmaPostgresDB{
		db: keyshare.DB{DB: db},
	}, nil
}

func (db *myirmaPostgresDB) UserID(username string) (int64, error) {
	var id int64
	return id, db.db.QueryUser("SELECT id FROM irma.users WHERE username = $1", []interface{}{&id}, username)
}

func (db *myirmaPostgresDB) VerifyEmailToken(token string) (int64, error) {
	var email string
	var id int64
	err := db.db.QueryScan(
		"SELECT user_id, email FROM irma.email_verification_tokens WHERE token = $1 AND expiry >= $2",
		[]interface{}{&id, &email},
		token, time.Now().Unix())
	if err == sql.ErrNoRows {
		return 0, errors.New("Token not found")
	}
	if err != nil {
		return 0, err
	}

	err = db.AddEmail(id, email)
	if err != nil {
		return 0, err
	}

	// Beyond this point, errors are no longer relevant for frontend, so only log
	aff, err := db.db.ExecCount("DELETE FROM irma.email_verification_tokens WHERE token = $1", token)
	if err != nil {
		_ = server.LogError(err)
		return id, nil
	}
	if aff != 1 {
		_ = server.LogError(errors.Errorf("Unexpected number of deleted records %d for token", aff))
		return id, nil
	}
	return id, nil
}

func (db *myirmaPostgresDB) RemoveUser(id int64, delay time.Duration) error {
	return db.db.ExecUser("UPDATE irma.users SET coredata = NULL, delete_on = $2 WHERE id = $1 AND coredata IS NOT NULL",
		id,
		time.Now().Add(delay).Unix())
}

func (db *myirmaPostgresDB) AddEmailLoginToken(email, token string) error {
	// Check if email address exists in database
	err := db.db.QueryScan("SELECT 1 FROM irma.emails WHERE email = $1 AND (delete_on >= $2 OR delete_on IS NULL) LIMIT 1",
		nil, email, time.Now().Unix())
	if err == sql.ErrNoRows {
		return ErrEmailNotFound
	}
	if err != nil {
		return err
	}

	// insert and verify
	aff, err := db.db.ExecCount("INSERT INTO irma.email_login_tokens (token, email, expiry) VALUES ($1, $2, $3)",
		token,
		email,
		time.Now().Add(EMAIL_TOKEN_VALIDITY*time.Minute).Unix())
	if err != nil {
		return err
	}
	if aff != 1 {
		return errors.Errorf("Unexpected number of affected rows %d on token insert", aff)
	}

	return nil
}

func (db *myirmaPostgresDB) LoginTokenCandidates(token string) ([]LoginCandidate, error) {
	var candidates []LoginCandidate
	err := db.db.QueryIterate(
		`SELECT username, last_seen FROM irma.users INNER JOIN irma.emails ON users.id = emails.user_id WHERE
		     (emails.delete_on >= $2 OR emails.delete_on is NULL) AND
		          emails.email = (SELECT email FROM irma.email_login_tokens WHERE token = $1 AND expiry >= $2);`,
		func(rows *sql.Rows) error {
			candidate := LoginCandidate{}
			err := rows.Scan(&candidate.Username, &candidate.LastActive)
			candidates = append(candidates, candidate)
			return err
		},
		token, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, keyshare.ErrUserNotFound
	}
	return candidates, nil
}

func (db *myirmaPostgresDB) TryUserLoginToken(token, username string) (bool, error) {
	err := db.db.QueryUser(
		`SELECT 1 FROM irma.users INNER JOIN irma.emails ON users.id = emails.user_id WHERE
		     username = $1 AND (emails.delete_on >= $3 OR emails.delete_on IS NULL) AND
		     email = (SELECT email FROM irma.email_login_tokens WHERE token = $2 AND expiry >= $3)`,
		nil, username, token, time.Now().Unix())
	if err != nil {
		return false, err
	}

	// Successfull deletion of the token can only occur once, so we use that to signal ok to login
	aff, err := db.db.ExecCount("DELETE FROM irma.email_login_tokens WHERE token = $1", token)
	if err != nil {
		return false, err
	}
	if aff != 1 {
		return false, nil
	}
	return true, nil
}

func (db *myirmaPostgresDB) UserInformation(id int64) (UserInformation, error) {
	var result UserInformation

	// fetch username
	err := db.db.QueryUser("SELECT username, language, (coredata IS NULL) AS delete_in_progress FROM irma.users WHERE id = $1",
		[]interface{}{&result.Username, &result.language, &result.DeleteInProgress},
		id)
	if err != nil {
		return UserInformation{}, err
	}

	// fetch email addresses
	err = db.db.QueryIterate(
		"SELECT email, (delete_on IS NOT NULL) AS delete_in_progress FROM irma.emails WHERE user_id = $1 AND (delete_on >= $2 OR delete_on IS NULL)",
		func(rows *sql.Rows) error {
			var email UserEmail
			err = rows.Scan(&email.Email, &email.DeleteInProgress)
			result.Emails = append(result.Emails, email)
			return err
		},
		id, time.Now().Unix())
	if err != nil {
		return UserInformation{}, err
	}
	return result, nil
}

func (db *myirmaPostgresDB) Logs(id int64, offset, amount int) ([]LogEntry, error) {
	var result []LogEntry
	err := db.db.QueryIterate(
		"SELECT time, event, param FROM irma.log_entry_records WHERE user_id = $1 ORDER BY time DESC OFFSET $2 LIMIT $3",
		func(rows *sql.Rows) error {
			var curEntry LogEntry
			err := rows.Scan(&curEntry.Timestamp, &curEntry.Event, &curEntry.Param)
			result = append(result, curEntry)
			return err
		},
		id, offset, amount)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (db *myirmaPostgresDB) AddEmail(id int64, email string) error {
	// Try to restore email in process of deletion
	aff, err := db.db.ExecCount("UPDATE irma.emails SET delete_on = NULL WHERE user_id = $1 AND email = $2", id, email)
	if err != nil {
		return err
	}
	if aff == 1 {
		return nil
	}

	// Fall back to adding new one
	_, err = db.db.Exec("INSERT INTO irma.emails (user_id, email) VALUES ($1, $2)", id, email)
	return err
}

func (db *myirmaPostgresDB) RemoveEmail(id int64, email string, delay time.Duration) error {
	aff, err := db.db.ExecCount("UPDATE irma.emails SET delete_on = $3 WHERE user_id = $1 AND email = $2 AND delete_on IS NULL",
		id,
		email,
		time.Now().Add(delay).Unix())
	if err != nil {
		return err
	}
	if aff != 1 {
		return errors.Errorf("Unexpected number of affected rows %d for email removal", aff)
	}
	return nil
}

func (db *myirmaPostgresDB) SetSeen(id int64) error {
	return db.db.ExecUser("UPDATE irma.users SET last_seen = $1 WHERE id = $2", time.Now().Unix(), id)
}
