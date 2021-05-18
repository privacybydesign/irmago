package myirmaserver

import (
	"sync"
	"time"

	"github.com/privacybydesign/irmago/server/keyshare"
)

type memoryUserData struct {
	id         int64
	email      []string
	logEntries []LogEntry
	lastActive time.Time
}

type myirmaMemoryDB struct {
	lock     sync.Mutex
	userData map[string]memoryUserData

	loginEmailTokens  map[string]string
	verifyEmailTokens map[string]int64
}

func NewMyirmaMemoryDB() MyirmaDB {
	return &myirmaMemoryDB{
		userData:          map[string]memoryUserData{},
		loginEmailTokens:  map[string]string{},
		verifyEmailTokens: map[string]int64{},
	}
}

func (db *myirmaMemoryDB) UserID(username string) (int64, error) {
	db.lock.Lock()
	defer db.lock.Unlock()
	data, ok := db.userData[username]
	if !ok {
		return 0, keyshare.ErrUserNotFound
	}
	return data.id, nil
}

func (db *myirmaMemoryDB) RemoveUser(id int64, _ time.Duration) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.userData {
		if user.id == id {
			delete(db.userData, username)
			return nil
		}
	}
	return keyshare.ErrUserNotFound
}

func (db *myirmaMemoryDB) VerifyEmailToken(token string) (int64, error) {
	db.lock.Lock()
	defer db.lock.Unlock()

	userID, ok := db.verifyEmailTokens[token]
	if !ok {
		return 0, keyshare.ErrUserNotFound
	}

	delete(db.verifyEmailTokens, token)

	return userID, nil
}

func (db *myirmaMemoryDB) AddEmailLoginToken(email, token string) error {
	db.lock.Lock()
	defer db.lock.Unlock()

	found := false
	for _, user := range db.userData {
		for _, userEmail := range user.email {
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
		return ErrEmailNotFound
	}

	db.loginEmailTokens[token] = email
	return nil
}

func (db *myirmaMemoryDB) LoginTokenCandidates(token string) ([]LoginCandidate, error) {
	db.lock.Lock()
	defer db.lock.Unlock()

	email, ok := db.loginEmailTokens[token]
	if !ok {
		return nil, keyshare.ErrUserNotFound
	}

	var result []LoginCandidate
	for name, user := range db.userData {
		for _, userEmail := range user.email {
			if userEmail == email {
				result = append(result, LoginCandidate{Username: name, LastActive: user.lastActive.Unix()})
				break
			}
		}
	}
	return result, nil
}

func (db *myirmaMemoryDB) TryUserLoginToken(token, username string) (int64, error) {
	db.lock.Lock()
	defer db.lock.Unlock()

	email, ok := db.loginEmailTokens[token]
	if !ok {
		return 0, keyshare.ErrUserNotFound
	}

	user, ok := db.userData[username]
	if !ok {
		return 0, keyshare.ErrUserNotFound
	}

	for _, userEmail := range user.email {
		if userEmail == email {
			delete(db.loginEmailTokens, token)
			return user.id, nil
		}
	}
	return 0, keyshare.ErrUserNotFound
}

func (db *myirmaMemoryDB) UserInformation(id int64) (UserInformation, error) {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.userData {
		if user.id == id {
			var emailList []UserEmail
			for _, e := range user.email {
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
	return UserInformation{}, keyshare.ErrUserNotFound
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func (db *myirmaMemoryDB) Logs(id int64, offset, amount int) ([]LogEntry, error) {
	db.lock.Lock()
	defer db.lock.Unlock()
	for _, user := range db.userData {
		if user.id == id {
			return user.logEntries[min(len(user.logEntries), offset):min(len(user.logEntries), offset+amount)], nil
		}
	}
	return nil, keyshare.ErrUserNotFound
}

func (db *myirmaMemoryDB) AddEmail(id int64, email string) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.userData {
		if user.id == id {
			user.email = append(user.email, email)
			db.userData[username] = user
			return nil
		}
	}
	return keyshare.ErrUserNotFound
}

func (db *myirmaMemoryDB) RemoveEmail(id int64, email string, _ time.Duration) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.userData {
		if user.id == id {
			for i, emailv := range user.email {
				if emailv == email {
					copy(user.email[i:], user.email[i+1:])
					user.email = user.email[:len(user.email)-1]
					db.userData[username] = user
					return nil
				}
			}
			return nil
		}
	}

	return keyshare.ErrUserNotFound
}

func (db *myirmaMemoryDB) SetSeen(id int64) error {
	db.lock.Lock()
	defer db.lock.Unlock()
	for username, user := range db.userData {
		if user.id == id {
			user.lastActive = time.Now()
			db.userData[username] = user
			return nil
		}
	}
	return keyshare.ErrUserNotFound
}
