package myirmaserver

import (
	"sync"
	"time"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
)

var errUnknownSession = errors.New("unknown session")

type session struct {
	token  string
	userID *int64

	loginSessionToken irma.RequestorToken
	emailSessionToken irma.RequestorToken

	expiry time.Time
}

type sessionStore interface {
	add(ses session) error
	get(token string) (session, error)
	txUpdate(token string, handler func(ses *session) error) error
	flush()
}

type memorySessionStore struct {
	sync.Mutex
	data map[string]session
}

func newMemorySessionStore(sessionLifetime time.Duration) sessionStore {
	return &memorySessionStore{
		data: map[string]session{},
	}
}

func (s *memorySessionStore) add(ses session) error {
	s.Lock()
	defer s.Unlock()
	s.data[ses.token] = ses
	return nil
}

func (s *memorySessionStore) get(token string) (session, error) {
	s.Lock()
	defer s.Unlock()
	ses, ok := s.data[token]
	if !ok {
		return session{}, errUnknownSession
	}
	return ses, nil
}

func (s *memorySessionStore) txUpdate(token string, handler func(ses *session) error) error {
	s.Lock()
	defer s.Unlock()
	ses, ok := s.data[token]
	if !ok {
		return errUnknownSession
	}
	if err := handler(&ses); err != nil {
		return err
	}
	s.data[token] = ses
	return nil
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
