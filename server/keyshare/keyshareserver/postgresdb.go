package keyshareserver

import (
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

const maxPinTries = 3         // Number of tries allowed on pin before we start with exponential backoff
const emailTokenValidity = 24 // amount of time user's email validation token is valid (in hours)

// Initial amount of time user is forced to back off when having multiple pin failures (in seconds).
// var so that tests may change it.
var backoffStart int64 = 60

func newPostgresDB(connstring string) (DB, error) {
	db, err := sql.Open("pgx", connstring)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, errors.Errorf("failed to connect to database: %v", err)
	}
	return &postgresDB{
		db: keyshare.DB{DB: db},
	}, nil
}

func (db *postgresDB) AddUser(user *User) error {
	res, err := db.db.Query("INSERT INTO irma.users (username, language, coredata, last_seen, pin_counter, pin_block_date) VALUES ($1, $2, $3, $4, 0, 0) RETURNING id",
		user.Username,
		user.Language,
		user.Secrets[:],
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

func (db *postgresDB) user(username string) (*User, error) {
	var result User
	var secrets []byte
	err := db.db.QueryUser(
		"SELECT id, username, language, coredata FROM irma.users WHERE username = $1 AND coredata IS NOT NULL",
		[]interface{}{&result.id, &result.Username, &result.Language, &secrets},
		username,
	)
	if err != nil {
		return nil, err
	}
	copy(result.Secrets[:], secrets)
	return &result, nil
}

func (db *postgresDB) updateUser(user *User) error {
	return db.db.ExecUser(
		"UPDATE irma.users SET username = $1, language = $2, coredata = $3 WHERE id=$4",
		user.Username,
		user.Language,
		user.Secrets[:],
		user.id,
	)
}

func (db *postgresDB) reservePinTry(user *User) (bool, int, int64, error) {
	// Check that account is not blocked already, and if not,
	//  update pinCounter and pinBlockDate
	uprows, err := db.db.Query(`
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
		pinrows, err := db.db.Query("SELECT pin_block_date FROM irma.users WHERE id=$1 AND coredata IS NOT NULL", user.id)
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

func (db *postgresDB) resetPinTries(user *User) error {
	return db.db.ExecUser(
		"UPDATE irma.users SET pin_counter = 0, pin_block_date = 0 WHERE id = $1",
		user.id,
	)
}

func (db *postgresDB) setSeen(user *User) error {
	// If the user is scheduled for deletion (delete_on is not null), undo that by resetting
	// delete_on back to null, but only if the user did not explicitly delete her account herself
	// in the myIRMA website, in which case coredata is null.
	return db.db.ExecUser(
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

func (db *postgresDB) addLog(user *User, eventType eventType, param interface{}) error {
	var encodedParamString *string
	if param != nil {
		encodedParam, err := json.Marshal(param)
		if err != nil {
			return err
		}
		encodedParams := string(encodedParam)
		encodedParamString = &encodedParams
	}

	_, err := db.db.Exec("INSERT INTO irma.log_entry_records (time, event, param, user_id) VALUES ($1, $2, $3, $4)",
		time.Now().Unix(),
		eventType,
		encodedParamString,
		user.id)
	return err
}

func (db *postgresDB) addEmailVerification(user *User, emailAddress, token string) error {
	_, err := db.db.Exec("INSERT INTO irma.email_verification_tokens (token, email, user_id, expiry) VALUES ($1, $2, $3, $4)",
		token,
		emailAddress,
		user.id,
		time.Now().Add(emailTokenValidity*time.Hour).Unix())
	return err
}
