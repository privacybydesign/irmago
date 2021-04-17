package keyshareserver

import (
	"sync"

	"github.com/privacybydesign/irmago/internal/keysharecore"
)

// MemoryDB provides an easy-to-configure testing implementation of the
// keyshare server database. It does not provide full functionality, instead
// mocking some behaviour, as noted on the specific functions.

type keyshareMemoryDB struct {
	lock  sync.Mutex
	users map[string]keysharecore.EncryptedKeysharePacket
}

func NewMemoryDatabase() KeyshareDB {
	return &keyshareMemoryDB{users: map[string]keysharecore.EncryptedKeysharePacket{}}
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

func (db *keyshareMemoryDB) ReservePincheck(user *KeyshareUser) (bool, int, int64, error) {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return true, 1, 0, nil
}

func (db *keyshareMemoryDB) ClearPincheck(user *KeyshareUser) error {
	// Since this is a testing DB, implementing anything more than always allow creates hastle
	return nil
}

func (db *keyshareMemoryDB) SetSeen(user *KeyshareUser) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}

func (db *keyshareMemoryDB) AddLog(user *KeyshareUser, eventType LogEntryType, param interface{}) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}

func (db *keyshareMemoryDB) AddEmailVerification(user *KeyshareUser, emailAddress, token string) error {
	// We don't need to do anything here, as this information cannot be extracted locally
	return nil
}
