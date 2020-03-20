package keyshareserver

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "github.com/jackc/pgx/stdlib"
)

type keysharePostgresDatabase struct {
	db *sql.DB
}

type keysharePostgresUser struct {
	KeyshareUserData
	id int64
}

func (m *keysharePostgresUser) Data() *KeyshareUserData {
	return &m.KeyshareUserData
}

const MAX_PIN_TRIES = 3         // Number of tries allowed on pin before we start with exponential backoff
const BACKOFF_START = 30        // Initial ammount of time you are forced to back off when having multiple pin failures (in seconds)
const EMAIL_TOKEN_VALIDITY = 24 // Ammount of time your email validation token is valid (in hours)

func NewPostgresDatabase(connstring string) (KeyshareDB, error) {
	db, err := sql.Open("pgx", connstring)
	if err != nil {
		return nil, err
	}
	return &keysharePostgresDatabase{
		db: db,
	}, nil
}

func (db *keysharePostgresDatabase) NewUser(user KeyshareUserData) (KeyshareUser, error) {
	res, err := db.db.Query("INSERT INTO irma.users (username, language, coredata, lastSeen, pinCounter, pinBlockDate) VALUES ($1, $2, $3, $4, 0, 0) RETURNING id",
		user.Username,
		user.Language,
		user.Coredata[:],
		time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer res.Close()
	if !res.Next() {
		return nil, ErrUserAlreadyExists
	}
	var id int64
	err = res.Scan(&id)
	if err != nil {
		return nil, err
	}
	return &keysharePostgresUser{KeyshareUserData: user, id: id}, nil
}

func (db *keysharePostgresDatabase) User(username string) (KeyshareUser, error) {
	rows, err := db.db.Query("SELECT id, username, language, coredata FROM irma.users WHERE username = $1", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, ErrUserNotFound
	}
	var result keysharePostgresUser
	var ep []byte
	err = rows.Scan(&result.id, &result.Username, &result.Language, &ep)
	if err != nil {
		return nil, err
	}
	if len(ep) != len(result.Coredata[:]) {
		return nil, ErrInvalidRecord
	}
	copy(result.Coredata[:], ep)
	return &result, nil
}

func (db *keysharePostgresDatabase) UpdateUser(user KeyshareUser) error {
	userdata := user.(*keysharePostgresUser)
	res, err := db.db.Exec("UPDATE irma.users SET username=$1, language=$2, coredata=$3 WHERE id=$4",
		userdata.Username,
		userdata.Language,
		userdata.Coredata[:],
		userdata.id)
	if err != nil {
		return err
	}
	c, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if c == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (db *keysharePostgresDatabase) ReservePincheck(user KeyshareUser) (bool, int, int64, error) {
	// Extract data
	userdata := user.(*keysharePostgresUser)

	// Check that account is not blocked already, and if not,
	//  update pinCounter and pinBlockDate
	uprows, err := db.db.Query(`
		UPDATE irma.users
		SET pinCounter = pinCounter+1,
			pinBlockDate = $1+$2*2^GREATEST(0, pinCounter-$3)
		WHERE id=$4 AND pinBlockDate<=$5
		RETURNING pinCounter, pinBlockDate`,
		time.Now().Unix()-1-BACKOFF_START, // Grace time of 2 seconds on pinBlockDate set
		BACKOFF_START,
		MAX_PIN_TRIES-2,
		userdata.id,
		time.Now().Unix())
	if err != nil {
		return false, 0, 0, err
	}
	defer uprows.Close()

	// Check whether we have results
	if !uprows.Next() {
		// if no, then account either does not exist (which would be weird here) or is blocked
		// so request wait timeout
		pinrows, err := db.db.Query("SELECT pinBlockDate FROM irma.users WHERE id=$1", userdata.id)
		if err != nil {
			return false, 0, 0, err
		}
		defer pinrows.Close()
		if !pinrows.Next() {
			return false, 0, 0, ErrUserNotFound
		}
		var wait int64
		err = pinrows.Scan(&wait)
		if err != nil {
			return false, 0, 0, err
		}
		wait = wait - time.Now().Unix()
		if wait < 0 {
			wait = 0
		}
		return false, 0, wait, nil
	}

	// Pin check is allowed (implied since there is a result, so pinBlockDate <= now)
	//  calculate tries remaining and wait time
	var tries int
	var wait int64
	err = uprows.Scan(&tries, &wait)
	if err != nil {
		return false, 0, 0, err
	}
	tries = MAX_PIN_TRIES - tries
	if tries < 0 {
		tries = 0
	}
	wait = wait - time.Now().Unix()
	if wait < 0 {
		wait = 0
	}
	return true, tries, wait, nil
}

func (db *keysharePostgresDatabase) ClearPincheck(user KeyshareUser) error {
	userdata := user.(*keysharePostgresUser)
	res, err := db.db.Exec("UPDATE irma.users SET pinCounter=0, pinBlockDate=0 WHERE id=$1", userdata.id)
	if err != nil {
		return err
	}
	c, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if c == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (db *keysharePostgresDatabase) SetSeen(user KeyshareUser) error {
	userdata := user.(*keysharePostgresUser)
	res, err := db.db.Exec("UPDATE irma.users SET lastSeen = $1 WHERE id = $2", time.Now().Unix(), userdata.id)
	if err != nil {
		return err
	}
	c, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if c == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (db *keysharePostgresDatabase) AddLog(user KeyshareUser, eventType LogEntryType, param interface{}) error {
	userdata := user.(*keysharePostgresUser)

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
		userdata.id)
	return err
}

func (db *keysharePostgresDatabase) AddEmailVerification(user KeyshareUser, emailAddress, token string) error {
	userdata := user.(*keysharePostgresUser)

	_, err := db.db.Exec("INSERT INTO irma.email_verification_tokens (token, email, user_id, expiry) VALUES ($1, $2, $3, $4)",
		token,
		emailAddress,
		userdata.id,
		time.Now().Add(EMAIL_TOKEN_VALIDITY*time.Hour).Unix())
	return err
}
