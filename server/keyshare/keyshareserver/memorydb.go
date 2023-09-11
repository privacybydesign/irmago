package keyshareserver

import (
	"context"
	"sync"

	"github.com/privacybydesign/irmago/server/keyshare"
)

// memoryDB provides an easy-to-configure testing implementation of the
// keyshare server database. It does not provide full functionality, instead
// mocking some behaviour, as noted on the specific functions.

type memoryDB struct {
	sync.Mutex
	users map[string]UserSecrets
}

func NewMemoryDB() DB {
	return &memoryDB{users: map[string]UserSecrets{}}
}

func (db *memoryDB) user(_ context.Context, username string) (*User, error) {
	// Ensure access to database is single-threaded
	db.Lock()
	defer db.Unlock()

	// Check and fetch user data
	secrets, ok := db.users[username]
	if !ok {
		return nil, keyshare.ErrUserNotFound
	}
	return &User{Username: username, Secrets: UserSecrets(secrets)}, nil
}

func (db *memoryDB) AddUser(_ context.Context, user *User) error {
	// Ensure access to database is single-threaded
	db.Lock()
	defer db.Unlock()

	// Check and insert user
	_, exists := db.users[user.Username]
	if exists {
		return errUserAlreadyExists
	}
	db.users[user.Username] = user.Secrets
	return nil
}

func (db *memoryDB) updateUser(_ context.Context, user *User) error {
	// Ensure access to database is single-threaded
	db.Lock()
	defer db.Unlock()

	// Check and update user.
	_, exists := db.users[user.Username]
	if !exists {
		return keyshare.ErrUserNotFound
	}
	db.users[user.Username] = user.Secrets
	return nil
}

func (db *memoryDB) reservePinTry(_ context.Context, _ *User) (bool, int, int64, error) {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return true, 1, 0, nil
}

func (db *memoryDB) resetPinTries(_ context.Context, _ *User) error {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return nil
}

func (db *memoryDB) setSeen(_ context.Context, _ *User) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}

func (db *memoryDB) addLog(_ context.Context, _ *User, _ eventType, _ interface{}) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}

func (db *memoryDB) addEmailVerification(_ context.Context, _ *User, _, _ string, _ int) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}
