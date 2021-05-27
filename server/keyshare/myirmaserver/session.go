package myirmaserver

import (
	"sync"
	"time"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
)

type Session struct {
	sync.Mutex

	token  string
	userID *int64

	pendingError        *server.Error
	pendingErrorMessage string

	expiry time.Time
}

type SessionStore interface {
	create() *Session
	get(token string) *Session
	flush()
}

type MemorySessionStore struct {
	sync.Mutex

	data            map[string]*Session
	sessionLifetime time.Duration
}

func NewMemorySessionStore(sessionLifetime time.Duration) SessionStore {
	return &MemorySessionStore{
		sessionLifetime: sessionLifetime,
		data:            map[string]*Session{},
	}
}

func (s *MemorySessionStore) create() *Session {
	s.Lock()
	defer s.Unlock()
	token := common.NewSessionToken()
	s.data[token] = &Session{
		token:  token,
		expiry: time.Now().Add(s.sessionLifetime),
	}
	return s.data[token]
}

func (s *MemorySessionStore) get(token string) *Session {
	s.Lock()
	defer s.Unlock()
	return s.data[token]
}

func (s *MemorySessionStore) flush() {
	now := time.Now()
	s.Lock()
	defer s.Unlock()
	for k, v := range s.data {
		if now.After(v.expiry) {
			delete(s.data, k)
		}
	}
}
