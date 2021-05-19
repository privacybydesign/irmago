package myirmaserver

import (
	"sync"
	"time"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
)

type Sessiondata struct {
	sync.Mutex

	token  string
	userID *int64

	pendingError        *server.Error
	pendingErrorMessage string

	expiry time.Time
}

type SessionStore interface {
	create() *Sessiondata
	get(token string) *Sessiondata
	flush()
}

type MemorySessionStore struct {
	sync.Mutex

	data            map[string]*Sessiondata
	sessionLifetime time.Duration
}

func NewMemorySessionStore(sessionLifetime time.Duration) SessionStore {
	return &MemorySessionStore{
		sessionLifetime: sessionLifetime,
		data:            map[string]*Sessiondata{},
	}
}

func (s *MemorySessionStore) create() *Sessiondata {
	s.Lock()
	defer s.Unlock()
	token := common.NewSessionToken()
	s.data[token] = &Sessiondata{
		token:  token,
		expiry: time.Now().Add(s.sessionLifetime),
	}
	return s.data[token]
}

func (s *MemorySessionStore) get(token string) *Sessiondata {
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
