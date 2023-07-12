package myirmaserver

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"
)

type postgresDB struct {
	db keyshare.DB
}

const emailTokenValidity = 60         // amount of time an email login token is valid (in minutes)
const emailTokenRateLimitDuration = 2 // amount of time before a new email can be requested (in minutes)

var (
	errEmailNotFound = errors.New("Email address not found")
	errTokenNotFound = errors.New("Token not found")
	errTooManyTokens = errors.New("Too many unhandled email tokens for given email address")
)

// newPostgresDB opens a new database connection using the given maximum connection bounds.
// For the maxOpenConns, maxIdleTime and maxOpenTime parameters, the value 0 means unlimited.
func newPostgresDB(connstring string, maxIdleConns, maxOpenConns int, maxIdleTime, maxOpenTime time.Duration) (db, error) {
	db, err := sql.Open("pgx", connstring)
	if err != nil {
		return nil, err
	}
	db.SetMaxIdleConns(maxIdleConns)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetConnMaxIdleTime(maxIdleTime)
	db.SetConnMaxLifetime(maxOpenTime)
	if err = db.Ping(); err != nil {
		return nil, errors.Errorf("failed to connect to database: %v", err)
	}
	return &postgresDB{
		db: keyshare.DB{DB: db},
	}, nil
}

func (db *postgresDB) userIDByUsername(ctx context.Context, username string) (int64, error) {
	var id int64
	return id, db.db.QueryUserContext(ctx, "SELECT id FROM irma.users WHERE username = $1", []interface{}{&id}, username)
}

func (db *postgresDB) verifyEmailToken(ctx context.Context, token string) (int64, error) {
	var email string
	var id int64
	err := db.db.QueryScanContext(
		ctx,
		"SELECT user_id, email FROM irma.email_verification_tokens WHERE token = $1 AND expiry >= $2",
		[]interface{}{&id, &email},
		token, time.Now().Unix())
	if err == sql.ErrNoRows {
		return 0, errTokenNotFound
	}
	if err != nil {
		return 0, err
	}

	err = db.addEmail(ctx, id, email)
	if err != nil {
		return 0, err
	}

	// Beyond this point, errors are no longer relevant for frontend, so only log
	aff, err := db.db.ExecCountContext(ctx, "DELETE FROM irma.email_verification_tokens WHERE token = $1", token)
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

func (db *postgresDB) scheduleUserRemoval(ctx context.Context, id int64, delay time.Duration) error {
	return db.db.ExecUserContext(ctx, "UPDATE irma.users SET coredata = NULL, delete_on = $2 WHERE id = $1 AND coredata IS NOT NULL",
		id,
		time.Now().Add(delay).Unix())
}

func (db *postgresDB) addLoginToken(ctx context.Context, email, token string) error {
	// Check if email address exists in database
	err := db.db.QueryScanContext(ctx, "SELECT 1 FROM irma.emails WHERE email = $1 AND (delete_on >= $2 OR delete_on IS NULL) LIMIT 1",
		nil, email, time.Now().Unix())
	if err == sql.ErrNoRows {
		return errEmailNotFound
	}
	if err != nil {
		return err
	}

	expiry := time.Now().Add(emailTokenValidity * time.Minute)
	maxPrevExpiry := expiry.Add(-1 * emailTokenRateLimitDuration * time.Minute)

	// Check whether rate limiting is necessary
	amount, err := db.db.ExecCountContext(ctx, "SELECT 1 FROM irma.email_login_tokens WHERE email = $1 AND expiry > $2",
		email,
		maxPrevExpiry.Unix())
	if err != nil {
		return err
	}
	if amount > 0 {
		return errTooManyTokens
	}

	// Insert and verify
	aff, err := db.db.ExecCountContext(ctx, "INSERT INTO irma.email_login_tokens (token, email, expiry) VALUES ($1, $2, $3)",
		token,
		email,
		expiry.Unix())
	if err != nil {
		return err
	}
	if aff != 1 {
		return errors.Errorf("Unexpected number of affected rows %d on token insert", aff)
	}

	return nil
}

func (db *postgresDB) loginUserCandidates(ctx context.Context, token string) ([]loginCandidate, error) {
	var candidates []loginCandidate
	err := db.db.QueryIterateContext(
		ctx,
		`SELECT username, last_seen FROM irma.users INNER JOIN irma.emails ON users.id = emails.user_id WHERE
		     (emails.delete_on >= $2 OR emails.delete_on is NULL) AND
		          emails.email = (SELECT email FROM irma.email_login_tokens WHERE token = $1 AND expiry >= $2);`,
		func(rows *sql.Rows) error {
			candidate := loginCandidate{}
			err := rows.Scan(&candidate.Username, &candidate.LastActive)
			candidates = append(candidates, candidate)
			return err
		},
		token, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, errTokenNotFound
	}
	return candidates, nil
}

func (db *postgresDB) verifyLoginToken(ctx context.Context, token, username string) (int64, error) {
	var id int64
	err := db.db.QueryScanContext(
		ctx,
		`SELECT users.id FROM irma.users INNER JOIN irma.emails ON users.id = emails.user_id WHERE
		     username = $1 AND (emails.delete_on >= $3 OR emails.delete_on IS NULL) AND
		     email = (SELECT email FROM irma.email_login_tokens WHERE token = $2 AND expiry >= $3)`,
		[]interface{}{&id}, username, token, time.Now().Unix())
	if err == sql.ErrNoRows {
		return 0, errTokenNotFound
	}
	if err != nil {
		return 0, err
	}

	aff, err := db.db.ExecCountContext(ctx, "DELETE FROM irma.email_login_tokens WHERE token = $1", token)
	if err != nil {
		return 0, err
	}
	if aff != 1 {
		return 0, errors.Errorf("Unexpected number of affected rows %d for token removal", aff)
	}
	return id, nil
}

func (db *postgresDB) user(ctx context.Context, id int64) (user, error) {
	var result user

	// fetch username
	err := db.db.QueryUserContext(ctx, "SELECT username, language, (coredata IS NULL) AS delete_in_progress FROM irma.users WHERE id = $1",
		[]interface{}{&result.Username, &result.language, &result.DeleteInProgress},
		id)
	if err != nil {
		return user{}, err
	}

	query := "SELECT email, (delete_on IS NOT NULL) AS delete_in_progress {{revalidate}} FROM irma.emails WHERE user_id = $1 AND (delete_on >= $2 OR delete_on IS NULL)"

	if db.db.EmailRevalidation(ctx) {
		query = strings.ReplaceAll(query, "{{revalidate}}", ", (revalidate_on IS NOT NULL) AS revalidate_in_progress")
	} else {
		query = strings.ReplaceAll(query, "{{revalidate}}", "")
	}

	// fetch email addresses
	err = db.db.QueryIterateContext(
		ctx,
		query,
		func(rows *sql.Rows) error {
			var email userEmail
			err = rows.Scan(&email.Email, &email.DeleteInProgress, &email.RevalidateInProgress)
			result.Emails = append(result.Emails, email)
			return err
		},
		id, time.Now().Unix())
	if err != nil {
		return user{}, err
	}
	return result, nil
}

func (db *postgresDB) logs(ctx context.Context, id int64, offset, amount int) ([]logEntry, error) {
	var result []logEntry
	err := db.db.QueryIterateContext(
		ctx,
		"SELECT time, event, param FROM irma.log_entry_records WHERE user_id = $1 ORDER BY time DESC OFFSET $2 LIMIT $3",
		func(rows *sql.Rows) error {
			var curEntry logEntry
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

func (db *postgresDB) addEmail(ctx context.Context, id int64, email string) error {
	// Try to restore email in process of deletion
	aff, err := db.db.ExecCountContext(ctx, "UPDATE irma.emails SET delete_on = NULL WHERE user_id = $1 AND email = $2", id, email)
	if err != nil {
		return err
	}
	if aff > 1 {
		return errors.Errorf("Unexpected number of affected rows %d for email adding", aff)
	}
	if aff == 1 {
		return nil
	}

	// Fall back to adding new one
	_, err = db.db.ExecContext(ctx, "INSERT INTO irma.emails (user_id, email) VALUES ($1, $2)", id, email)
	return err
}

func (db *postgresDB) scheduleEmailRemoval(ctx context.Context, id int64, email string, delay time.Duration) error {
	aff, err := db.db.ExecCountContext(ctx, "UPDATE irma.emails SET delete_on = $3 WHERE user_id = $1 AND email = $2 AND delete_on IS NULL",
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

func (db *postgresDB) setSeen(ctx context.Context, id int64) error {
	// If the user is scheduled for deletion (delete_on is not null), undo that by resetting
	// delete_on back to null, but only if the user did not explicitly delete her account herself
	// in the myIRMA website, in which case coredata is null.
	return db.db.ExecUserContext(
		ctx,
		`UPDATE irma.users
		 SET last_seen = $1,
		     delete_on = CASE
		         WHEN coredata IS NOT NULL THEN NULL
		         ELSE delete_on
		     END
		 WHERE id = $2`,
		time.Now().Unix(), id,
	)
}

func (db *postgresDB) hasEmailRevalidation(ctx context.Context) bool {
	return db.db.EmailRevalidation(ctx)
}

func (db *postgresDB) scheduleEmailRevalidation(ctx context.Context, id int64, email string, delay time.Duration) error {
	aff, err := db.db.ExecCountContext(ctx, "UPDATE irma.emails SET revalidate_on = $1 WHERE user_id = $2 AND email = $3 AND delete_on IS NULL",
		time.Now().Add(delay).Unix(),
		id,
		email)
	if err != nil {
		return err
	}
	if aff != 1 {
		return errors.Errorf("Unexpected number of affected rows %d for email revalidation", aff)
	}
	return nil
}

func (db *postgresDB) setPinBlockDate(ctx context.Context, id int64, delay time.Duration) error {
	aff, err := db.db.ExecCountContext(ctx, "UPDATE irma.users SET pin_block_date = $1 WHERE id = $2",
		time.Now().Add(delay).Unix(),
		id)
	if err != nil {
		return err
	}
	if aff != 1 {
		return errors.Errorf("Unexpected number of affected rows %d at setting pin_block_date", aff)
	}
	return nil
}
