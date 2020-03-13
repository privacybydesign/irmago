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
	RemoveUser(id int64) error

	AddEmailLoginToken(email, token string) error
	LoginTokenGetCandidates(token string) ([]LoginCandidate, error)
	LoginTokenGetEmail(token string) (string, error)
	TryUserLoginToken(token, username string) (bool, error)

	GetUserInformation(id int64) (UserInformation, error)
	AddEmail(id int64, email string) error
	RemoveEmail(id int64, email string) error
}

type UserInformation struct {
	Username string   `json:"username"`
	Emails   []string `json:"emails"`
}

type LoginCandidate struct {
	Username   string `json:"username"`
	LastActive int64  `json:"last_active"`
}

type MemoryUserData struct {
	ID         int64
	Email      []string
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

func (db *MyirmaMemoryDB) RemoveUser(id int64) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.UserData {
		if user.ID == id {
			delete(db.UserData, username)
			return nil
		}
	}
	return ErrUserNotFound
}

func (db *MyirmaMemoryDB) AddEmailLoginToken(email, token string) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	found := false
	for _, user := range db.UserData {
		for _, userEmail := range user.Email {
			if userEmail == email {
				found = true
				break
			}
		}
		if found {
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
	for name, user := range db.UserData {
		for _, userEmail := range user.Email {
			if userEmail == email {
				result = append(result, LoginCandidate{Username: name, LastActive: user.LastActive.Unix()})
				break
			}
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

	for _, userEmail := range user.Email {
		if userEmail == email {
			delete(db.LoginEmailTokens, token)
			return true, nil
		}
	}
	return false, nil
}

func (db *MyirmaMemoryDB) GetUserInformation(id int64) (UserInformation, error) {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.UserData {
		if user.ID == id {
			return UserInformation{
				Username: username,
				Emails:   user.Email,
			}, nil
		}
	}
	return UserInformation{}, ErrUserNotFound
}

func (db *MyirmaMemoryDB) AddEmail(id int64, email string) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.UserData {
		if user.ID == id {
			user.Email = append(user.Email, email)
			db.UserData[username] = user
			return nil
		}
	}
	return ErrUserNotFound
}

func (db *MyirmaMemoryDB) RemoveEmail(id int64, email string) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.UserData {
		if user.ID == id {
			for i, emailv := range user.Email {
				if emailv == email {
					copy(user.Email[i:], user.Email[i+1:])
					user.Email = user.Email[:len(user.Email)-1]
					db.UserData[username] = user
					return nil
				}
			}
			return nil
		}
	}

	return ErrUserNotFound
}
