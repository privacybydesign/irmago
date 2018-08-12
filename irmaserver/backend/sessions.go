package backend

import (
	"math/big"
	"math/rand"
	"sync"
	"time"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
)

type session struct {
	sync.Mutex

	action  irma.Action
	token   string
	version *irma.ProtocolVersion
	request irma.SessionRequest
	status  irmaserver.Status

	active time.Time

	proofStatus irma.ProofStatus
	disclosed   []*irma.DisclosedAttribute
	signature   *irma.SignedMessage

	kssProofs map[irma.SchemeManagerIdentifier]*gabi.ProofP
}

type sessionStore interface {
	get(token string) *session
	add(token string, session *session)
	deleteExpired()
}

type memorySessionStore struct {
	sync.RWMutex
	m map[string]*session
}

const (
	maxSessionLifetime = 5 * time.Minute  // After this a session is cancelled
	expiryTicker       = 10 * time.Second // Every so often we check if any session has expired
)

const sessionChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	minProtocolVersion = irma.NewVersion(2, 4)
	maxProtocolVersion = irma.NewVersion(2, 4)

	sessions sessionStore = &memorySessionStore{
		m: make(map[string]*session),
	}
)

func init() {
	go sessions.deleteExpired()
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

func (s memorySessionStore) deleteExpired() {
	// First check which sessions have expired
	// We don't need a write lock for this yet, so postpone that for actual deleting
	s.RLock()
	expired := make([]string, 0, len(s.m))
	for token, session := range s.m {
		if session.active.Add(5 * time.Minute).Before(time.Now()) {
			conf.Logger.Infof("Session %s expired, deleting", token)
			expired = append(expired, token)
		}
	}
	s.RUnlock()

	// Using a write lock, delete the expired sessions
	s.Lock()
	for _, token := range expired {
		delete(s.m, token)
	}
	s.Unlock()

	// Schedule next run
	time.AfterFunc(expiryTicker, func() {
		s.deleteExpired()
	})
}

var one *big.Int = big.NewInt(1)

func newSession(action irma.Action, request irma.SessionRequest) *session {
	s := &session{
		action:  action,
		request: request,
		status:  irmaserver.StatusInitialized,
		active:  time.Now(),
		token:   newSessionToken(),
	}
	nonce, _ := gabi.RandomBigInt(gabi.DefaultSystemParameters[2048].Lstatzk)
	request.SetNonce(nonce)
	request.SetContext(one)
	sessions.add(s.token, s)
	return s
}

func newSessionToken() string {
	b := make([]byte, 20)
	for i := range b {
		b[i] = sessionChars[rand.Int63()%int64(len(sessionChars))]
	}
	return string(b)
}

func chooseProtocolVersion(min, max *irma.ProtocolVersion) (*irma.ProtocolVersion, error) {
	if min.AboveVersion(minProtocolVersion) || max.BelowVersion(min) {
		return nil, errors.Errorf("Protocol version negotiation failed, min=%s max=%s", min.String(), max.String())
	}
	if max.AboveVersion(maxProtocolVersion) {
		return maxProtocolVersion, nil
	} else {
		return max, nil
	}
}
