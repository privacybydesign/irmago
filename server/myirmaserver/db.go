package myirmaserver

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrUserNotFound = errors.New("Could not find specified user")
)

type MyirmaDB interface {
	GetUserID(username string) (int64, error)

	AddEmailLoginToken(email, token string) error
	LoginTokenGetCandidates(token string) ([]LoginCandidate, error)
	LoginTokenGetEmail(token string) (string, error)
	TryUserLoginToken(token, username string) (bool, error)
}

type LoginCandidate struct {
	Username   string `json:"username"`
	LastActive int64  `json:"last_active"`
}

type MemoryUserData struct {
	ID         int64
	Email      string
	LastActive time.Time
}

type MyirmaMemoryDB struct {
	lock     sync.Mutex
	UserData map[string]MemoryUserData

	LoginEmailTokens map[string]string
}

func NewMyirmaMemoryDB() MyirmaDB {
	return &MyirmaMemoryDB{
		UserData:         map[string]MemoryUserData{},
		LoginEmailTokens: map[string]string{},
	}
}

func (db *MyirmaMemoryDB) GetUserID(username string) (int64, error) {
	db.lock.Lock()
	defer db.lock.Unlock()
	data, ok := db.UserData[username]
	if !ok {
		return 0, ErrUserNotFound
	}
	return data.ID, nil
}

func (db *MyirmaMemoryDB) AddEmailLoginToken(email, token string) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	found := false
	for _, v := range db.UserData {
		if v.Email == email {
			found = true
			break
		}
	}

	if !found {
		return ErrUserNotFound
	}

	db.LoginEmailTokens[token] = email
	return nil
}

func (db *MyirmaMemoryDB) LoginTokenGetCandidates(token string) ([]LoginCandidate, error) {
	db.lock.Lock()
	defer db.lock.Unlock()

	email, ok := db.LoginEmailTokens[token]
	if !ok {
		return nil, ErrUserNotFound
	}

	result := []LoginCandidate{}
	for k, v := range db.UserData {
		if v.Email == email {
			result = append(result, LoginCandidate{Username: k, LastActive: v.LastActive.Unix()})
		}
	}
	return result, nil
}

func (db *MyirmaMemoryDB) LoginTokenGetEmail(token string) (string, error) {
	db.lock.Lock()
	defer db.lock.Unlock()

	v, ok := db.LoginEmailTokens[token]
	if !ok {
		return "", ErrUserNotFound
	}
	return v, nil
}

func (db *MyirmaMemoryDB) TryUserLoginToken(token, username string) (bool, error) {
	db.lock.Lock()
	defer db.lock.Unlock()

	email, ok := db.LoginEmailTokens[token]
	if !ok {
		return false, nil
	}

	user, ok := db.UserData[username]
	if !ok {
		return false, ErrUserNotFound
	}
	if user.Email == email {
		delete(db.LoginEmailTokens, token)
		return true, nil
	} else {
		return false, nil
	}
}
