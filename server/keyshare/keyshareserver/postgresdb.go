package keyshareserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/go-errors/errors"
	_ "github.com/jackc/pgx/stdlib"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server/keyshare"
)

// postgresDB provides a postgres-backed implementation of DB
// database access is done through the database/sql mechanisms, using
// pgx as database driver

type postgresDB struct {
	db keyshare.DB
}

// Number of tries allowed on pin before we start with exponential backoff
const maxPinTries = 3

// Max number of active tokens per email address within the emailTokenRateLimitDuration
const emailTokenRateLimit = 3

// Amount of time after which tokens become irrelevant for rate limiting (in minutes)
const emailTokenRateLimitDuration = 60

var errTooManyTokens = errors.New("Too many unhandled email tokens for given email address")

// Initial amount of time user is forced to back off when having multiple pin failures (in seconds).
// var so that tests may change it.
var backoffStart int64 = 60

// newPostgresDB opens a new database connection using the given maximum connection bounds.
// For the maxOpenConns, maxIdleTime and maxOpenTime parameters, the value 0 means unlimited.
func newPostgresDB(connstring string, maxIdleConns, maxOpenConns int, maxIdleTime, maxOpenTime time.Duration) (DB, error) {
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

func (db *postgresDB) AddUser(ctx context.Context, user *User) error {
	res, err := db.db.QueryContext(ctx, "INSERT INTO irma.users (username, language, coredata, last_seen, pin_counter, pin_block_date) VALUES ($1, $2, $3, $4, 0, 0) RETURNING id",
		user.Username,
		user.Language,
		user.Secrets,
		time.Now().Unix())
	if err != nil {
		return err
	}
	defer common.Close(res)
	if !res.Next() {
		if err = res.Err(); err != nil {
			return err
		}
		return errUserAlreadyExists
	}
	var id int64
	err = res.Scan(&id)
	if err != nil {
		return err
	}
	user.id = id
	return nil
}

func (db *postgresDB) user(ctx context.Context, username string) (*User, error) {
	var result User
	err := db.db.QueryUserContext(
		ctx,
		"SELECT id, username, language, coredata FROM irma.users WHERE username = $1 AND coredata IS NOT NULL",
		[]interface{}{&result.id, &result.Username, &result.Language, &result.Secrets},
		username,
	)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (db *postgresDB) updateUser(ctx context.Context, user *User) error {
	return db.db.ExecUserContext(
		ctx,
		"UPDATE irma.users SET username = $1, language = $2, coredata = $3 WHERE id=$4",
		user.Username,
		user.Language,
		user.Secrets,
		user.id,
	)
}

func (db *postgresDB) reservePinTry(ctx context.Context, user *User) (bool, int, int64, error) {
	// Check that account is not blocked already, and if not,
	//  update pinCounter and pinBlockDate
	uprows, err := db.db.QueryContext(ctx, `
		UPDATE irma.users
		SET pin_counter = pin_counter+1,
			pin_block_date = $1 + CASE WHEN pin_counter-$3 < 0 THEN 0
			                           ELSE $2*2^GREATEST(0, pin_counter-$3)
			                      END
		WHERE id=$4 AND pin_block_date<=$1 AND coredata IS NOT NULL
		RETURNING pin_counter, pin_block_date`,
		time.Now().Unix(),
		backoffStart,
		maxPinTries-1,
		user.id)
	if err != nil {
		return false, 0, 0, err
	}
	defer common.Close(uprows)

	var (
		allowed bool
		wait    int64
		tries   int
	)
	if !uprows.Next() {
		if err = uprows.Err(); err != nil {
			return false, 0, 0, err
		}
		// if no results, then account either does not exist (which would be weird here) or is blocked
		// so request wait timeout
		pinrows, err := db.db.QueryContext(ctx, "SELECT pin_block_date FROM irma.users WHERE id=$1 AND coredata IS NOT NULL", user.id)
		if err != nil {
			return false, 0, 0, err
		}
		defer common.Close(pinrows)
		if !pinrows.Next() {
			if err = pinrows.Err(); err != nil {
				return false, 0, 0, err
			}
			return false, 0, 0, keyshare.ErrUserNotFound
		}
		err = pinrows.Scan(&wait)
		if err != nil {
			return false, 0, 0, err
		}
	} else {
		// Pin check is allowed (implied since there is a result, so pinBlockDate <= now)
		//  calculate tries remaining and wait time
		allowed = true
		err = uprows.Scan(&tries, &wait)
		if err != nil {
			return false, 0, 0, err
		}
		tries = maxPinTries - tries
		if tries < 0 {
			tries = 0
		}
	}

	wait = wait - time.Now().Unix()
	if wait < 0 {
		wait = 0
	}
	return allowed, tries, wait, nil
}

func (db *postgresDB) resetPinTries(ctx context.Context, user *User) error {
	return db.db.ExecUserContext(
		ctx,
		"UPDATE irma.users SET pin_counter = 0, pin_block_date = 0 WHERE id = $1",
		user.id,
	)
}

func (db *postgresDB) setSeen(ctx context.Context, user *User) error {
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
		time.Now().Unix(), user.id,
	)
}

func (db *postgresDB) addLog(ctx context.Context, user *User, eventType eventType, param interface{}) error {
	var encodedParamString *string
	if param != nil {
		encodedParam, err := json.Marshal(param)
		if err != nil {
			return err
		}
		encodedParams := string(encodedParam)
		encodedParamString = &encodedParams
	}

	_, err := db.db.ExecContext(ctx, "INSERT INTO irma.log_entry_records (time, event, param, user_id) VALUES ($1, $2, $3, $4)",
		time.Now().Unix(),
		eventType,
		encodedParamString,
		user.id)
	return err
}

func (db *postgresDB) addEmailVerification(ctx context.Context, user *User, emailAddress, token string, validity int) error {
	expiry := time.Now().Add(time.Duration(validity) * time.Hour)
	maxPrevExpiry := expiry.Add(-1 * time.Duration(emailTokenRateLimitDuration) * time.Minute)

	// Check whether rate limiting is necessary
	amount, err := db.db.ExecCountContext(ctx, "SELECT 1 FROM irma.email_verification_tokens WHERE email = $1 AND expiry > $2",
		emailAddress,
		maxPrevExpiry.Unix())
	if err != nil {
		return err
	}
	if amount >= emailTokenRateLimit {
		return errTooManyTokens
	}

	_, err = db.db.ExecContext(ctx, "INSERT INTO irma.email_verification_tokens (token, email, user_id, expiry) VALUES ($1, $2, $3, $4)",
		token,
		emailAddress,
		user.id,
		expiry.Unix())
	return err
}
