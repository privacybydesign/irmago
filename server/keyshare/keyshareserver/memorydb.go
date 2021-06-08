package keyshareserver

import (
	"sync"

	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server/keyshare"
)

// memoryDB provides an easy-to-configure testing implementation of the
// keyshare server database. It does not provide full functionality, instead
// mocking some behaviour, as noted on the specific functions.

type memoryDB struct {
	sync.Mutex
	users map[string]keysharecore.User
}

func NewMemoryDB() DB {
	return &memoryDB{users: map[string]keysharecore.User{}}
}

func (db *memoryDB) user(username string) (*User, error) {
	// Ensure access to database is single-threaded
	db.Lock()
	defer db.Unlock()

	// Check and fetch user data
	data, ok := db.users[username]
	if !ok {
		return nil, keyshare.ErrUserNotFound
	}
	return &User{Username: username, UserData: data}, nil
}

func (db *memoryDB) AddUser(user *User) error {
	// Ensure access to database is single-threaded
	db.Lock()
	defer db.Unlock()

	// Check and insert user
	_, exists := db.users[user.Username]
	if exists {
		return errUserAlreadyExists
	}
	db.users[user.Username] = user.UserData
	return nil
}

func (db *memoryDB) updateUser(user *User) error {
	// Ensure access to database is single-threaded
	db.Lock()
	defer db.Unlock()

	// Check and update user.
	_, exists := db.users[user.Username]
	if !exists {
		return keyshare.ErrUserNotFound
	}
	db.users[user.Username] = user.UserData
	return nil
}

func (db *memoryDB) reservePinTry(user *User) (bool, int, int64, error) {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return true, 1, 0, nil
}

func (db *memoryDB) resetPinTries(user *User) error {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return nil
}

func (db *memoryDB) setSeen(user *User) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}

func (db *memoryDB) addLog(user *User, eventType eventType, param interface{}) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}

func (db *memoryDB) addEmailVerification(user *User, emailAddress, token string) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}
