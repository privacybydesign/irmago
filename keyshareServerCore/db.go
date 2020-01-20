package keyshareServerCore

import (
	"errors"
	"sync"

	"github.com/privacybydesign/irmago/keyshareCore"
)

var (
	ErrUserAlreadyExists = errors.New("Cannot create user, username already taken")
	ErrUserNotFound      = errors.New("Could not find specified user")
)

type KeyshareDB interface {
	NewUser(user *KeyshareUser) error
	User(username string) (*KeyshareUser, error)
	UpdateUser(user *KeyshareUser) error

	// Reserve returns (allow, tries, wait, error)
	ReservePincheck(user *KeyshareUser) (bool, int, int, error)
	ClearPincheck(user *KeyshareUser) error
}

type KeyshareUser struct {
	Username string
	Coredata keyshareCore.EncryptedKeysharePacket
}

type keyshareMemoryDB struct {
	lock  sync.Mutex
	users map[string]keyshareCore.EncryptedKeysharePacket
}

func NewMemoryDatabase() KeyshareDB {
	return &keyshareMemoryDB{users: map[string]keyshareCore.EncryptedKeysharePacket{}}
}

func (db *keyshareMemoryDB) User(username string) (*KeyshareUser, error) {
	// Ensure access to database is single-threaded
	db.lock.Lock()
	defer db.lock.Unlock()

	// Check and fetch user data
	data, ok := db.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	return &KeyshareUser{Username: username, Coredata: data}, nil
}

func (db *keyshareMemoryDB) NewUser(user *KeyshareUser) error {
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

func (db *keyshareMemoryDB) UpdateUser(user *KeyshareUser) error {
	// Ensure access to database is single-threaded
	db.lock.Lock()
	defer db.lock.Unlock()

	// Check and update user.
	_, exists := db.users[user.Username]
	if !exists {
		return ErrUserNotFound
	}
	db.users[user.Username] = user.Coredata
	return nil
}

func (db *keyshareMemoryDB) ReservePincheck(user *KeyshareUser) (bool, int, int, error) {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return false, 1, 0, nil
}

func (db *keyshareMemoryDB) ClearPincheck(user *KeyshareUser) error {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return nil
}
