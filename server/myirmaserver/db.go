package myirmaserver

import (
	"errors"
	"sync"
)

var (
	ErrUserAlreadyExists = errors.New("Cannot create user, username already taken")
	ErrUserNotFound      = errors.New("Could not find specified user")
	ErrInvalidRecord     = errors.New("Invalid record in database")
)

type MyirmaDB interface {
	GetUserID(username string) (int64, error)
}

type MemoryUserData struct {
	id int64
}

type MyirmaMemoryDB struct {
	lock     sync.Mutex
	UserData map[string]MemoryUserData
}

func NewMyirmaMemoryDB() MyirmaDB {
	return &MyirmaMemoryDB{
		UserData: map[string]MemoryUserData{},
	}
}

func (db *MyirmaMemoryDB) GetUserID(username string) (int64, error) {
	db.lock.Lock()
	defer db.lock.Unlock()
	data, ok := db.UserData[username]
	if !ok {
		return 0, ErrUserNotFound
	}
	return data.id, nil
}
