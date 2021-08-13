package keyshareserver

import (
	"sync"
	"time"

	irma "github.com/privacybydesign/irmago"
)

type session struct {
	KeyID    irma.PublicKeyIdentifier // last used key, used in signing the issuance message
	CommitID uint64
	expiry   time.Time
}

type sessionStore interface {
	add(username string, session *session)
	get(username string) *session
	flush()
}

type memorySessionStore struct {
	sync.Mutex

	sessions        map[string]*session
	sessionLifetime time.Duration
}

func newMemorySessionStore(sessionLifetime time.Duration) sessionStore {
	return &memorySessionStore{
		sessionLifetime: sessionLifetime,
		sessions:        map[string]*session{},
	}
}

func (s *memorySessionStore) add(username string, session *session) {
	s.Lock()
	defer s.Unlock()
	session.expiry = time.Now().Add(s.sessionLifetime)
	s.sessions[username] = session
}

func (s *memorySessionStore) get(username string) *session {
	s.Lock()
	defer s.Unlock()
	return s.sessions[username]
}

func (s *memorySessionStore) flush() {
	now := time.Now()
	s.Lock()
	defer s.Unlock()
	for k, v := range s.sessions {
		if now.After(v.expiry) {
			delete(s.sessions, k)
		}
	}
}
