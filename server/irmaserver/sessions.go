package irmaserver

import (
	"strings"
	"sync"
	"time"

	"github.com/alexandrevicenzi/go-sse"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"

	"github.com/sirupsen/logrus"
)

type session struct {
	sync.Mutex
	locked bool

	action             irma.Action
	requestorToken     irma.RequestorToken
	clientToken        irma.ClientToken
	frontendAuth       irma.FrontendAuthorization
	version            *irma.ProtocolVersion
	rrequest           irma.RequestorRequest
	request            irma.SessionRequest
	legacyCompatible   bool // if the request is convertible to pre-condiscon format
	implicitDisclosure irma.AttributeConDisCon

	options       irma.SessionOptions
	status        irma.ServerStatus
	prevStatus    irma.ServerStatus
	sse           *sse.Server
	responseCache responseCache

	clientAuth irma.ClientAuthorization
	lastActive time.Time
	result     *server.SessionResult

	kssProofs map[irma.SchemeManagerIdentifier]*gabi.ProofP

	conf     *server.Configuration
	sessions sessionStore
}

type responseCache struct {
	endpoint      string
	message       []byte
	response      []byte
	status        int
	sessionStatus irma.ServerStatus
}

type sessionStore interface {
	get(token irma.RequestorToken) *session
	clientGet(token irma.ClientToken) *session
	add(session *session)
	update(session *session)
	deleteExpired()
	stop()
}

type memorySessionStore struct {
	sync.RWMutex
	conf *server.Configuration

	requestor map[irma.RequestorToken]*session
	client    map[irma.ClientToken]*session
}

const (
	maxSessionLifetime = 5 * time.Minute // After this a session is cancelled
)

var (
	minProtocolVersion = irma.NewVersion(2, 4)
	maxProtocolVersion = irma.NewVersion(2, 7)
)

func (s *memorySessionStore) get(t irma.RequestorToken) *session {
	s.RLock()
	defer s.RUnlock()
	return s.requestor[t]
}

func (s *memorySessionStore) clientGet(t irma.ClientToken) *session {
	s.RLock()
	defer s.RUnlock()
	return s.client[t]
}

func (s *memorySessionStore) add(session *session) {
	s.Lock()
	defer s.Unlock()
	s.requestor[session.requestorToken] = session
	s.client[session.clientToken] = session
}

func (s *memorySessionStore) update(session *session) {
	session.onUpdate()
}

func (s *memorySessionStore) stop() {
	s.Lock()
	defer s.Unlock()
	for _, session := range s.requestor {
		if session.sse != nil {
			session.sse.CloseChannel("session/" + string(session.requestorToken))
			session.sse.CloseChannel("session/" + string(session.clientToken))
		}
	}
}

func (s *memorySessionStore) deleteExpired() {
	// First check which sessions have expired
	// We don't need a write lock for this yet, so postpone that for actual deleting
	s.RLock()
	toCheck := make(map[irma.RequestorToken]*session, len(s.requestor))
	for token, session := range s.requestor {
		toCheck[token] = session
	}
	s.RUnlock()

	expired := make([]irma.RequestorToken, 0, len(toCheck))
	for token, session := range toCheck {
		session.Lock()
		timeout := maxSessionLifetime
		if session.status == irma.ServerStatusInitialized && session.rrequest.Base().ClientTimeout != 0 {
			timeout = time.Duration(session.rrequest.Base().ClientTimeout) * time.Second
		}

		if session.lastActive.Add(timeout).Before(time.Now()) {
			if !session.status.Finished() {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.requestorToken}).Infof("Session expired")
				session.markAlive()
				session.setStatus(irma.ServerStatusTimeout)
			} else {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.requestorToken}).Infof("Deleting session")
				expired = append(expired, token)
			}
		}
		session.Unlock()
	}

	// Using a write lock, delete the expired sessions
	s.Lock()
	for _, token := range expired {
		session := s.requestor[token]
		if session.sse != nil {
			session.sse.CloseChannel("session/" + string(session.requestorToken))
			session.sse.CloseChannel("session/" + string(session.clientToken))
		}
		delete(s.client, session.clientToken)
		delete(s.requestor, token)
	}
	s.Unlock()
}

var one *big.Int = big.NewInt(1)

func (s *Server) newSession(action irma.Action, request irma.RequestorRequest) *session {
	clientToken := irma.ClientToken(common.NewSessionToken())
	requestorToken := irma.RequestorToken(common.NewSessionToken())
	frontendAuth := irma.FrontendAuthorization(common.NewSessionToken())

	base := request.SessionRequest().Base()
	if s.conf.AugmentClientReturnURL && base.AugmentReturnURL && base.ClientReturnURL != "" {
		if strings.Contains(base.ClientReturnURL, "?") {
			base.ClientReturnURL += "&token=" + string(requestorToken)
		} else {
			base.ClientReturnURL += "?token=" + string(requestorToken)
		}
	}

	ses := &session{
		action:   action,
		rrequest: request,
		request:  request.SessionRequest(),
		options: irma.SessionOptions{
			LDContext:     irma.LDContextSessionOptions,
			BindingMethod: irma.BindingMethodNone,
		},
		lastActive:     time.Now(),
		requestorToken: requestorToken,
		clientToken:    clientToken,
		frontendAuth:   frontendAuth,
		status:         irma.ServerStatusInitialized,
		prevStatus:     irma.ServerStatusInitialized,
		conf:           s.conf,
		sessions:       s.sessions,
		sse:            s.serverSentEvents,
		result: &server.SessionResult{
			LegacySession: request.SessionRequest().Base().Legacy(),
			Token:         requestorToken,
			Type:          action,
			Status:        irma.ServerStatusInitialized,
		},
	}

	s.conf.Logger.WithFields(logrus.Fields{"session": ses.requestorToken}).Debug("New session started")
	nonce, _ := gabi.GenerateNonce()
	base.Nonce = nonce
	base.Context = one
	s.sessions.add(ses)

	return ses
}
