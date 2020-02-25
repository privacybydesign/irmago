package keyshareserver

import (
	"sync"

	"github.com/privacybydesign/irmago/internal/keysharecore"
)

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

func (db *keyshareMemoryDB) NewUser(user KeyshareUserData) (KeyshareUser, error) {
	// Ensure access to database is single-threaded
	db.lock.Lock()
	defer db.lock.Unlock()

	// Check and insert user
	_, exists := db.users[user.Username]
	if exists {
		return nil, ErrUserAlreadyExists
	}
	db.users[user.Username] = user.Coredata
	return &keyshareMemoryUser{KeyshareUserData: user}, nil
}

func (db *keyshareMemoryDB) UpdateUser(user KeyshareUser) error {
	userdata := user.(*keyshareMemoryUser)

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

func (db *keyshareMemoryDB) AddLog(user KeyshareUser, eventType LogEntryType, param interface{}) error {
	return nil
}

func (db *keyshareMemoryDB) AddEmailVerification(user KeyshareUser, emailAddress, token string) error {
	return nil
}
