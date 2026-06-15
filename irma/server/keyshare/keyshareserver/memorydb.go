package keyshareserver

import (
	"context"
	"sync"

	"github.com/privacybydesign/irmago/irma/server/keyshare"
)

// memoryDB provides an easy-to-configure testing implementation of the
// keyshare server database. It does not provide full functionality, instead
// mocking some behaviour, as noted on the specific functions.

const memoryDBMaxPinTries = 3

type MemoryDB struct {
	sync.Mutex
	users       map[string]UserSecrets
	pinCounters map[string]int
}

func NewMemoryDB() *MemoryDB {
	return &MemoryDB{
		users:       map[string]UserSecrets{},
		pinCounters: map[string]int{},
	}
}

func (db *MemoryDB) user(_ context.Context, username string) (*User, error) {
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

func (db *MemoryDB) AddUser(_ context.Context, user *User) error {
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

func (db *MemoryDB) updateUser(_ context.Context, user *User) error {
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

func (db *MemoryDB) reservePinTry(_ context.Context, user *User) (bool, int, int64, error) {
	db.Lock()
	defer db.Unlock()

	db.pinCounters[user.Username]++
	counter := db.pinCounters[user.Username]

	if counter > memoryDBMaxPinTries {
		return false, 0, 1, nil
	}
	return true, memoryDBMaxPinTries - counter, 0, nil
}

func (db *MemoryDB) resetPinTries(_ context.Context, user *User) error {
	db.Lock()
	defer db.Unlock()

	delete(db.pinCounters, user.Username)
	return nil
}

func (db *MemoryDB) setSeen(_ context.Context, _ *User) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}

func (db *MemoryDB) addLog(_ context.Context, _ *User, _ eventType, _ interface{}) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}

func (db *MemoryDB) addEmailVerification(_ context.Context, _ *User, _, _ string, _ int) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}

// DumpUsers returns a copy of all users in the database.
func (db *MemoryDB) DumpUsers() []User {
	db.Lock()
	defer db.Unlock()
	users := make([]User, 0, len(db.users))
	for username, secrets := range db.users {
		s := make(UserSecrets, len(secrets))
		copy(s, secrets)
		users = append(users, User{Username: username, Secrets: s})
	}
	return users
}
