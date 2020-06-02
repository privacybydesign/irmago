package myirmaserver

import (
	"sync"
	"time"
)

type MemoryUserData struct {
	ID         int64
	Email      []string
	LogEntries []LogEntry
	LastActive time.Time
}

type MyirmaMemoryDB struct {
	lock     sync.Mutex
	UserData map[string]MemoryUserData

	LoginEmailTokens  map[string]string
	VerifyEmailTokens map[string]int64
}

func NewMyirmaMemoryDB() MyirmaDB {
	return &MyirmaMemoryDB{
		UserData:          map[string]MemoryUserData{},
		LoginEmailTokens:  map[string]string{},
		VerifyEmailTokens: map[string]int64{},
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

func (db *MyirmaMemoryDB) VerifyEmailToken(token string) (int64, error) {
	db.lock.Lock()
	defer db.lock.Unlock()

	userID, ok := db.VerifyEmailTokens[token]
	if !ok {
		return 0, ErrUserNotFound
	}

	delete(db.VerifyEmailTokens, token)

	return userID, nil
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
			var emailList []UserEmail
			for _, e := range user.Email {
				emailList = append(emailList, UserEmail{
					Email:            e,
					DeleteInProgress: false,
				})
			}
			return UserInformation{
				Username:         username,
				Emails:           emailList,
				DeleteInProgress: false,
			}, nil
		}
	}
	return UserInformation{}, ErrUserNotFound
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func (db *MyirmaMemoryDB) GetLogs(id int64, offset, ammount int) ([]LogEntry, error) {
	db.lock.Lock()
	defer db.lock.Unlock()
	for _, user := range db.UserData {
		if user.ID == id {
			return user.LogEntries[min(len(user.LogEntries), offset):min(len(user.LogEntries), offset+ammount)], nil
		}
	}
	return nil, ErrUserNotFound
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

func (db *MyirmaMemoryDB) SetSeen(id int64) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.UserData {
		if user.ID == id {
			user.LastActive = time.Now()
			db.UserData[username] = user
			return nil
		}
	}
	return ErrUserNotFound
}
