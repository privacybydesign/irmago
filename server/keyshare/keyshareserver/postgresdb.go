package keyshareserver

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/jackc/pgx/stdlib"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server/keyshare"
)

// postgresDB provides a postgres-backed implementation of KeyshareDB
// database access is done through the database/sql mechanisms, using
// pgx as database driver

type keysharePostgresDatabase struct {
	db keyshare.DB
}

const MAX_PIN_TRIES = 3         // Number of tries allowed on pin before we start with exponential backoff
const EMAIL_TOKEN_VALIDITY = 24 // amount of time user's email validation token is valid (in hours)

// Initial amount of time user is forced to back off when having multiple pin failures (in seconds).
// var so that tests may change it.
var BACKOFF_START int64 = 30

func NewPostgresDatabase(connstring string) (KeyshareDB, error) {
	db, err := sql.Open("pgx", connstring)
	if err != nil {
		return nil, err
	}
	return &keysharePostgresDatabase{
		db: keyshare.DB{DB: db},
	}, nil
}

func (db *keysharePostgresDatabase) NewUser(user *KeyshareUser) error {
	res, err := db.db.Query("INSERT INTO irma.users (username, language, coredata, last_seen, pin_counter, pin_block_date) VALUES ($1, $2, $3, $4, 0, 0) RETURNING id",
		user.Username,
		user.Language,
		user.Coredata[:],
		time.Now().Unix())
	if err != nil {
		return err
	}
	defer common.Close(res)
	if !res.Next() {
		return ErrUserAlreadyExists
	}
	var id int64
	err = res.Scan(&id)
	if err != nil {
		return err
	}
	user.id = id
	return nil
}

func (db *keysharePostgresDatabase) User(username string) (*KeyshareUser, error) {
	var result KeyshareUser
	var ep []byte
	err := db.db.QueryUser(
		"SELECT id, username, language, coredata FROM irma.users WHERE username = $1 AND coredata IS NOT NULL",
		[]interface{}{&result.id, &result.Username, &result.Language, &ep},
		username,
	)
	if err != nil {
		return nil, err
	}
	if len(ep) != len(result.Coredata[:]) {
		return nil, ErrInvalidRecord
	}
	copy(result.Coredata[:], ep)
	return &result, nil
}

func (db *keysharePostgresDatabase) UpdateUser(user *KeyshareUser) error {
	return db.db.ExecUser(
		"UPDATE irma.users SET username=$1, language=$2, coredata=$3 WHERE id=$4",
		user.Username,
		user.Language,
		user.Coredata[:],
		user.id,
	)
}

func (db *keysharePostgresDatabase) ReservePincheck(user *KeyshareUser) (bool, int, int64, error) {
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
		BACKOFF_START,
		MAX_PIN_TRIES-1,
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
		// if no results, then account either does not exist (which would be weird here) or is blocked
		// so request wait timeout
		pinrows, err := db.db.Query("SELECT pin_block_date FROM irma.users WHERE id=$1 AND coredata IS NOT NULL", user.id)
		if err != nil {
			return false, 0, 0, err
		}
		defer common.Close(pinrows)
		if !pinrows.Next() {
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
		tries = MAX_PIN_TRIES - tries
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

func (db *keysharePostgresDatabase) ClearPincheck(user *KeyshareUser) error {
	return db.db.ExecUser(
		"UPDATE irma.users SET pin_counter=0, pin_block_date=0 WHERE id=$1",
		user.id,
	)
}

func (db *keysharePostgresDatabase) SetSeen(user *KeyshareUser) error {
	return db.db.ExecUser(
		"UPDATE irma.users SET last_seen = $1 WHERE id = $2",
		time.Now().Unix(),
		user.id,
	)
}

func (db *keysharePostgresDatabase) AddLog(user *KeyshareUser, eventType LogEntryType, param interface{}) error {
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

func (db *keysharePostgresDatabase) AddEmailVerification(user *KeyshareUser, emailAddress, token string) error {
	_, err := db.db.Exec("INSERT INTO irma.email_verification_tokens (token, email, user_id, expiry) VALUES ($1, $2, $3, $4)",
		token,
		emailAddress,
		user.id,
		time.Now().Add(EMAIL_TOKEN_VALIDITY*time.Hour).Unix())
	return err
}
