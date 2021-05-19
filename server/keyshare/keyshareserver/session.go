package keyshareserver

import (
	"sync"
	"time"

	irma "github.com/privacybydesign/irmago"
)

type SessionData struct {
	LastKeyID    irma.PublicKeyIdentifier // last used key, used in signing the issuance message
	LastCommitID uint64
	expiry       time.Time
}

type sessionStore interface {
	add(username string, session *SessionData)
	get(username string) *SessionData
	flush()
}

type memorySessionStore struct {
	sync.Mutex

	data            map[string]*SessionData
	sessionLifetime time.Duration
}

func newMemorySessionStore(sessionLifetime time.Duration) sessionStore {
	return &memorySessionStore{
		sessionLifetime: sessionLifetime,
		data:            map[string]*SessionData{},
	}
}

func (s *memorySessionStore) add(username string, session *SessionData) {
	s.Lock()
	defer s.Unlock()
	session.expiry = time.Now().Add(s.sessionLifetime)
	s.data[username] = session
}

func (s *memorySessionStore) get(username string) *SessionData {
	s.Lock()
	defer s.Unlock()
	return s.data[username]
}

func (s *memorySessionStore) flush() {
	now := time.Now()
	s.Lock()
	defer s.Unlock()
	for k, v := range s.data {
		if now.After(v.expiry) {
			delete(s.data, k)
		}
	}
}
