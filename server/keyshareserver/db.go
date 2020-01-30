package keyshareserver

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/internal/keysharecore"

	_ "github.com/jackc/pgx/stdlib"
)

var (
	ErrUserAlreadyExists = errors.New("Cannot create user, username already taken")
	ErrUserNotFound      = errors.New("Could not find specified user")
	ErrInvalidData       = errors.New("Invalid user datastructure passed")
	ErrInvalidRecord     = errors.New("Invalid record in database")
)

type KeyshareDB interface {
	NewUser(user KeyshareUserData) error
	User(username string) (KeyshareUser, error)
	UpdateUser(user KeyshareUser) error

	// Reserve returns (allow, tries, wait, error)
	ReservePincheck(user KeyshareUser) (bool, int, int64, error)
	ClearPincheck(user KeyshareUser) error

	SetSeen(user KeyshareUser) error
}

type KeyshareUser interface {
	Data() *KeyshareUserData
}

type KeyshareUserData struct {
	Username string
	Coredata keysharecore.EncryptedKeysharePacket
}

type keyshareMemoryDB struct {
	lock  sync.Mutex
	users map[string]keysharecore.EncryptedKeysharePacket
}

type keyshareMemoryUser struct {
	KeyshareUserData
}

func (m *keyshareMemoryUser) Data() *KeyshareUserData {
	return &m.KeyshareUserData
}

func NewMemoryDatabase() KeyshareDB {
	return &keyshareMemoryDB{users: map[string]keysharecore.EncryptedKeysharePacket{}}
}

func (db *keyshareMemoryDB) User(username string) (KeyshareUser, error) {
	// Ensure access to database is single-threaded
	db.lock.Lock()
	defer db.lock.Unlock()

	// Check and fetch user data
	data, ok := db.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	return &keyshareMemoryUser{KeyshareUserData{Username: username, Coredata: data}}, nil
}

func (db *keyshareMemoryDB) NewUser(user KeyshareUserData) error {
	// Ensure access to database is single-threaded
	db.lock.Lock()
	defer db.lock.Unlock()

	// Check and insert user
	_, exists := db.users[user.Username]
	if exists {
		return ErrUserAlreadyExists
	}
	db.users[user.Username] = user.Coredata
	return nil
}

func (db *keyshareMemoryDB) UpdateUser(user KeyshareUser) error {
	userdata, ok := user.(*keyshareMemoryUser)
	if !ok {
		return ErrInvalidData
	}

	// Ensure access to database is single-threaded
	db.lock.Lock()
	defer db.lock.Unlock()

	// Check and update user.
	_, exists := db.users[userdata.Username]
	if !exists {
		return ErrUserNotFound
	}
	db.users[userdata.Username] = userdata.Coredata
	return nil
}

func (db *keyshareMemoryDB) ReservePincheck(user KeyshareUser) (bool, int, int64, error) {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return true, 1, 0, nil
}

func (db *keyshareMemoryDB) ClearPincheck(user KeyshareUser) error {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return nil
}

func (db *keyshareMemoryDB) SetSeen(user KeyshareUser) error {
	return nil
}

type keysharePostgresDatabase struct {
	db *sql.DB
}

type keysharePostgresUser struct {
	KeyshareUserData
	id int
}

func (m *keysharePostgresUser) Data() *KeyshareUserData {
	return &m.KeyshareUserData
}

const MAX_PIN_TRIES = 3
const BACKOFF_START = 30

func NewPostgresDatabase(connstring string) (KeyshareDB, error) {
	db, err := sql.Open("pgx", connstring)
	if err != nil {
		return nil, err
	}
	return &keysharePostgresDatabase{
		db: db,
	}, nil
}

func (db *keysharePostgresDatabase) NewUser(user KeyshareUserData) error {
	res, err := db.db.Exec("INSERT INTO irma.users (username, coredata, pinCounter, pinBlockDate) VALUES ($1, $2, 0, 0);", user.Username, user.Coredata[:])
	if err != nil {
		return err
	}
	c, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if c == 0 {
		return ErrUserAlreadyExists
	}
	return nil
}

func (db *keysharePostgresDatabase) User(username string) (KeyshareUser, error) {
	rows, err := db.db.Query("SELECT id, username, coredata FROM irma.users WHERE username = $1", username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, ErrUserNotFound
	}
	var result keysharePostgresUser
	var ep []byte
	err = rows.Scan(&result.id, &result.Username, &ep)
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
	userdata, ok := user.(*keysharePostgresUser)
	if !ok {
		return ErrInvalidData
	}
	res, err := db.db.Exec("UPDATE irma.users SET username=$1, coredata=$2 WHERE id=$3", userdata.Username, userdata.Coredata, userdata.id)
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
	userdata, ok := user.(*keysharePostgresUser)
	if !ok {
		return false, 0, 0, ErrInvalidData
	}

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
		return false, 0, wait - time.Now().Unix(), nil
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
	return true, tries, wait - time.Now().Unix(), nil
}

func (db *keysharePostgresDatabase) ClearPincheck(user KeyshareUser) error {
	userdata, ok := user.(*keysharePostgresUser)
	if !ok {
		return ErrInvalidData
	}
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
	userdata, ok := user.(*keysharePostgresUser)
	if !ok {
		return ErrInvalidData
	}
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
