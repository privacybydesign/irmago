package myirmaserver

import (
	"context"
	"sync"
	"time"

	"github.com/privacybydesign/irmago/server/keyshare"
)

type memoryUserData struct {
	id         int64
	email      []string
	logEntries []logEntry
	lastActive time.Time
}

type memoryDB struct {
	sync.Mutex
	userData map[string]memoryUserData

	loginEmailTokens  map[string]string
	verifyEmailTokens map[string]int64
}

func newMemoryDB() db {
	return &memoryDB{
		userData:          map[string]memoryUserData{},
		loginEmailTokens:  map[string]string{},
		verifyEmailTokens: map[string]int64{},
	}
}

func (db *memoryDB) userIDByUsername(_ context.Context, username string) (int64, error) {
	db.Lock()
	defer db.Unlock()
	data, ok := db.userData[username]
	if !ok {
		return 0, keyshare.ErrUserNotFound
	}
	return data.id, nil
}

func (db *memoryDB) scheduleUserRemoval(_ context.Context, id int64, _ time.Duration) error {
	db.Lock()
	defer db.Unlock()
	for username, user := range db.userData {
		if user.id == id {
			delete(db.userData, username)
			return nil
		}
	}
	return keyshare.ErrUserNotFound
}

func (db *memoryDB) verifyEmailToken(_ context.Context, token string) (int64, error) {
	db.Lock()
	defer db.Unlock()

	userID, ok := db.verifyEmailTokens[token]
	if !ok {
		// We return this particular error in this case for consistency with the postgres DB.
		// The calling function replaces this with a more informative error for the frontend.
		return 0, errTokenNotFound
	}

	delete(db.verifyEmailTokens, token)

	return userID, nil
}

func (db *memoryDB) addLoginToken(_ context.Context, email, token string) error {
	db.Lock()
	defer db.Unlock()

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
		return errEmailNotFound
	}

	db.loginEmailTokens[token] = email
	return nil
}

func (db *memoryDB) loginUserCandidates(_ context.Context, token string) ([]loginCandidate, error) {
	db.Lock()
	defer db.Unlock()

	email, ok := db.loginEmailTokens[token]
	if !ok {
		// We return this particular error in this case for consistency with the postgres DB.
		// The calling function replaces this with a more informative error for the frontend.
		return nil, errTokenNotFound
	}

	var result []loginCandidate
	for name, user := range db.userData {
		for _, userEmail := range user.email {
			if userEmail == email {
				result = append(result, loginCandidate{Username: name, LastActive: user.lastActive.Unix()})
				break
			}
		}
	}
	return result, nil
}

func (db *memoryDB) verifyLoginToken(_ context.Context, token, username string) (int64, error) {
	db.Lock()
	defer db.Unlock()

	email, ok := db.loginEmailTokens[token]
	if !ok {
		return 0, errTokenNotFound
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

func (db *memoryDB) user(_ context.Context, id int64) (user, error) {
	db.Lock()
	defer db.Unlock()
	for username, u := range db.userData {
		if u.id == id {
			var emailList []userEmail
			for _, e := range u.email {
				emailList = append(emailList, userEmail{
					Email:            e,
					DeleteInProgress: false,
				})
			}
			return user{
				Username:         username,
				Emails:           emailList,
				DeleteInProgress: false,
			}, nil
		}
	}
	return user{}, keyshare.ErrUserNotFound
}

func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func (db *memoryDB) logs(_ context.Context, id int64, offset, amount int) ([]logEntry, error) {
	db.Lock()
	defer db.Unlock()
	for _, user := range db.userData {
		if user.id == id {
			return user.logEntries[min(len(user.logEntries), offset):min(len(user.logEntries), offset+amount)], nil
		}
	}
	return nil, keyshare.ErrUserNotFound
}

func (db *memoryDB) addEmail(_ context.Context, id int64, email string) error {
	db.Lock()
	defer db.Unlock()
	for username, user := range db.userData {
		if user.id == id {
			user.email = append(user.email, email)
			db.userData[username] = user
			return nil
		}
	}
	return keyshare.ErrUserNotFound
}

func (db *memoryDB) scheduleEmailRemoval(_ context.Context, id int64, email string, _ time.Duration) error {
	db.Lock()
	defer db.Unlock()
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

func (db *memoryDB) setSeen(_ context.Context, id int64) error {
	db.Lock()
	defer db.Unlock()
	for username, user := range db.userData {
		if user.id == id {
			user.lastActive = time.Now()
			db.userData[username] = user
			return nil
		}
	}
	return keyshare.ErrUserNotFound
}

func (db *memoryDB) hasEmailRevalidation(_ context.Context) bool {
	return false
}

func (db *memoryDB) scheduleEmailRevalidation(_ context.Context, _ int64, _ string, _ time.Duration) error {
	return nil
}

func (db *memoryDB) setPinBlockDate(_ context.Context, _ int64, _ time.Duration) error {
	return nil
}
