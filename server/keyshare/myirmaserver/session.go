package myirmaserver

import (
	"sync"
	"time"

	"github.com/privacybydesign/irmago/internal/common"
)

type session struct {
	sync.Mutex

	token  string
	userID *int64

	loginSessionToken string
	emailSessionToken string

	expiry time.Time
}

type sessionStore interface {
	create() *session
	get(token string) *session
	flush()
}

type memorySessionStore struct {
	sync.Mutex

	data            map[string]*session
	sessionLifetime time.Duration
}

func newMemorySessionStore(sessionLifetime time.Duration) sessionStore {
	return &memorySessionStore{
		sessionLifetime: sessionLifetime,
		data:            map[string]*session{},
	}
}

func (s *memorySessionStore) create() *session {
	s.Lock()
	defer s.Unlock()
	token := common.NewSessionToken()
	s.data[token] = &session{
		token:  token,
		expiry: time.Now().Add(s.sessionLifetime),
	}
	return s.data[token]
}

func (s *memorySessionStore) get(token string) *session {
	s.Lock()
	defer s.Unlock()
	return s.data[token]
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
