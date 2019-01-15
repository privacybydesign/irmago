package core

import (
	"math/rand"
	"sync"
	"time"

	"github.com/jasonlvhit/gocron"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"gopkg.in/antage/eventsource.v1"
)

type session struct {
	sync.Mutex

	action   irma.Action
	token    string
	version  *irma.ProtocolVersion
	rrequest irma.RequestorRequest
	request  irma.SessionRequest

	status     server.Status
	prevStatus server.Status
	evtSource  eventsource.EventSource

	lastActive time.Time
	result     *server.SessionResult

	kssProofs map[irma.SchemeManagerIdentifier]*gabi.ProofP
}

type sessionStore interface {
	get(token string) *session
	add(token string, session *session)
	update(session *session)
	deleteExpired()
}

type memorySessionStore struct {
	sync.RWMutex
	m map[string]*session
}

const (
	maxSessionLifetime = 5 * time.Minute // After this a session is cancelled
	sessionChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var (
	minProtocolVersion = irma.NewVersion(2, 4)
	maxProtocolVersion = irma.NewVersion(2, 4)

	sessions sessionStore = &memorySessionStore{
		m: make(map[string]*session),
	}
)

func init() {
	rand.Seed(time.Now().UnixNano())

	gocron.Every(10).Seconds().Do(func() {
		sessions.deleteExpired()
	})
	gocron.Start()
}

func (s *memorySessionStore) get(token string) *session {
	s.RLock()
	defer s.RUnlock()
	return s.m[token]
}

func (s *memorySessionStore) add(token string, session *session) {
	s.Lock()
	defer s.Unlock()
	s.m[token] = session
}

func (s *memorySessionStore) update(session *session) {
	session.onUpdate()
}

func (s memorySessionStore) deleteExpired() {
	// First check which sessions have expired
	// We don't need a write lock for this yet, so postpone that for actual deleting
	s.RLock()
	expired := make([]string, 0, len(s.m))
	for token, session := range s.m {
		session.Lock()

		timeout := maxSessionLifetime
		if session.status == server.StatusInitialized && session.rrequest.Base().ClientTimeout != 0 {
			timeout = time.Duration(session.rrequest.Base().ClientTimeout) * time.Second
		}

		if session.lastActive.Add(timeout).Before(time.Now()) {
			if !session.status.Finished() {
				conf.Logger.Infof("Session %s expired", token)
				session.markAlive()
				session.setStatus(server.StatusTimeout)
			} else {
				conf.Logger.Infof("Deleting %s", token)
				expired = append(expired, token)
			}
		}
		session.Unlock()
	}
	s.RUnlock()

	// Using a write lock, delete the expired sessions
	s.Lock()
	for _, token := range expired {
		session := s.m[token]
		if session.evtSource != nil {
			session.evtSource.Close()
		}
		delete(s.m, token)
	}
	s.Unlock()
}

var one *big.Int = big.NewInt(1)

func newSession(action irma.Action, request irma.RequestorRequest) *session {
	token := newSessionToken()
	s := &session{
		action:     action,
		rrequest:   request,
		request:    request.SessionRequest(),
		lastActive: time.Now(),
		token:      token,
		status:     server.StatusInitialized,
		prevStatus: server.StatusInitialized,
		result: &server.SessionResult{
			Token:  token,
			Type:   action,
			Status: server.StatusInitialized,
		},
	}

	conf.Logger.Debug("New session started: ", token)
	nonce, _ := gabi.RandomBigInt(gabi.DefaultSystemParameters[2048].Lstatzk)
	s.request.SetNonce(nonce)
	s.request.SetContext(one)
	sessions.add(token, s)

	return s
}

func newSessionToken() string {
	b := make([]byte, 20)
	for i := range b {
		b[i] = sessionChars[rand.Int63()%int64(len(sessionChars))]
	}
	return string(b)
}
