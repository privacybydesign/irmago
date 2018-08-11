package backend

import (
	"math/big"
	"math/rand"
	"sync"

	"github.com/go-errors/errors"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/irmaserver"
)

type session struct {
	action  irma.Action
	token   string
	version *irma.ProtocolVersion
	request irma.SessionRequest
	status  irmaserver.Status

	proofStatus irma.ProofStatus
	disclosed   []*irma.DisclosedAttribute
	signature   *irma.SignedMessage

	kssProofs map[irma.SchemeManagerIdentifier]*gabi.ProofP
}

type sessionStore interface {
	get(token string) *session
	add(token string, session *session)
}

type memorySessionStore struct {
	sync.RWMutex
	m map[string]*session
}

const sessionChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	minProtocolVersion = irma.NewVersion(2, 4)
	maxProtocolVersion = irma.NewVersion(2, 4)

	sessions sessionStore = &memorySessionStore{
		m: make(map[string]*session),
	}
)

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

var one *big.Int = big.NewInt(1)

func newSession(action irma.Action, request irma.SessionRequest) *session {
	s := &session{
		action:  action,
		request: request,
		status:  irmaserver.StatusInitialized,
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
