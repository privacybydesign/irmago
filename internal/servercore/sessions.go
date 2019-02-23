package servercore

import (
	"math/rand"
	"sync"
	"time"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"gopkg.in/antage/eventsource.v1"
)

type session struct {
	sync.Mutex

	action      irma.Action
	token       string
	clientToken string
	version     *irma.ProtocolVersion
	rrequest    irma.RequestorRequest
	request     irma.SessionRequest

	status     server.Status
	prevStatus server.Status
	evtSource  eventsource.EventSource

	lastActive time.Time
	result     *server.SessionResult

	kssProofs map[irma.SchemeManagerIdentifier]*gabi.ProofP

	conf     *server.Configuration
	sessions sessionStore
}

type sessionStore interface {
	get(token string) *session
	clientGet(token string) *session
	add(session *session)
	update(session *session)
	deleteExpired()
	stop()
}

type memorySessionStore struct {
	sync.RWMutex
	conf *server.Configuration

	requestor map[string]*session
	client    map[string]*session
}

const (
	maxSessionLifetime = 5 * time.Minute // After this a session is cancelled
	sessionChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var (
	minProtocolVersion = irma.NewVersion(2, 4)
	maxProtocolVersion = irma.NewVersion(2, 4)
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func (s *memorySessionStore) get(t string) *session {
	s.RLock()
	defer s.RUnlock()
	return s.requestor[t]
}

func (s *memorySessionStore) clientGet(t string) *session {
	s.RLock()
	defer s.RUnlock()
	return s.client[t]
}

func (s *memorySessionStore) add(session *session) {
	s.Lock()
	defer s.Unlock()
	s.requestor[session.token] = session
	s.client[session.clientToken] = session
}

func (s *memorySessionStore) update(session *session) {
	session.onUpdate()
}

func (s *memorySessionStore) stop() {
	s.Lock()
	defer s.Unlock()
	for _, session := range s.requestor {
		if session.evtSource != nil {
			session.evtSource.Close()
		}
	}
}

func (s *memorySessionStore) deleteExpired() {
	// First check which sessions have expired
	// We don't need a write lock for this yet, so postpone that for actual deleting
	s.RLock()
	expired := make([]string, 0, len(s.requestor))
	for token, session := range s.requestor {
		session.Lock()

		timeout := maxSessionLifetime
		if session.status == server.StatusInitialized && session.rrequest.Base().ClientTimeout != 0 {
			timeout = time.Duration(session.rrequest.Base().ClientTimeout) * time.Second
		}

		if session.lastActive.Add(timeout).Before(time.Now()) {
			if !session.status.Finished() {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.token}).Infof("Session expired")
				session.markAlive()
				session.setStatus(server.StatusTimeout)
			} else {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.token}).Infof("Deleting session")
				expired = append(expired, token)
			}
		}
		session.Unlock()
	}
	s.RUnlock()

	// Using a write lock, delete the expired sessions
	s.Lock()
	for _, token := range expired {
		session := s.requestor[token]
		if session.evtSource != nil {
			session.evtSource.Close()
		}
		delete(s.client, session.clientToken)
		delete(s.requestor, token)
	}
	s.Unlock()
}

var one *big.Int = big.NewInt(1)

func (s *Server) newSession(action irma.Action, request irma.RequestorRequest) *session {
	token := newSessionToken()
	clientToken := newSessionToken()

	ses := &session{
		action:      action,
		rrequest:    request,
		request:     request.SessionRequest(),
		lastActive:  time.Now(),
		token:       token,
		clientToken: clientToken,
		status:      server.StatusInitialized,
		prevStatus:  server.StatusInitialized,
		conf:        s.conf,
		sessions:    s.sessions,
		result: &server.SessionResult{
			Token:  token,
			Type:   action,
			Status: server.StatusInitialized,
		},
	}

	s.conf.Logger.WithFields(logrus.Fields{"session": ses.token}).Debug("New session started")
	nonce, _ := gabi.RandomBigInt(gabi.DefaultSystemParameters[2048].Lstatzk)
	ses.request.SetNonce(nonce)
	ses.request.SetContext(one)
	s.sessions.add(ses)

	return ses
}

func newSessionToken() string {
	b := make([]byte, 20)
	for i := range b {
		b[i] = sessionChars[rand.Int63()%int64(len(sessionChars))]
	}
	return string(b)
}
