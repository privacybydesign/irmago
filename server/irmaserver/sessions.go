package irmaserver

import (
	//TODO: use redigo instead of redis-go v8?
	"context"
	"encoding/json"
	"github.com/go-errors/errors"
	"strings"
	"sync"
	"time"

	"github.com/alexandrevicenzi/go-sse"
	"github.com/go-redis/redis/v8"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"

	"github.com/sirupsen/logrus"
)

type session struct {
	//sync.Mutex
	//locked bool
	//
	//action             irma.Action
	//requestorToken     irma.RequestorToken
	//clientToken        irma.ClientToken
	//frontendAuth       irma.FrontendAuthorization
	//version            *irma.ProtocolVersion
	//rrequest           irma.RequestorRequest
	//request            irma.SessionRequest
	//legacyCompatible   bool // if the request is convertible to pre-condiscon format
	//implicitDisclosure irma.AttributeConDisCon
	//next               *irma.Qr
	//
	//options        irma.SessionOptions
	//status         irma.ServerStatus
	//prevStatus     irma.ServerStatus
	//sse            *sse.Server
	//statusChannels []chan irma.ServerStatus
	//responseCache  responseCache
	//
	//clientAuth irma.ClientAuthorization
	//lastActive time.Time
	//result     *server.SessionResult
	//
	//kssProofs map[irma.SchemeManagerIdentifier]*gabi.ProofP
	//
	//conf     *server.Configuration
	//sessions sessionStore
	//TODO: check if we can get rid of this Mutex for Redis
	sync.Mutex `json:-`
	//TODO: note somewhere that state with redis will not support sse for the moment
	sse         *sse.Server
	locked      bool
	sessions    sessionStore
	conf        *server.Configuration
	request     irma.SessionRequest
	context     context.Context
	toBeUpdated bool

	frontendAuth       irma.FrontendAuthorization
	implicitDisclosure irma.AttributeConDisCon
	next               *irma.Qr

	sessionData
}

type sessionData struct {
	Action             irma.Action
	RequestorToken     irma.RequestorToken
	ClientToken        irma.ClientToken
	Version            *irma.ProtocolVersion `json:",omitempty"`
	Rrequest           irma.RequestorRequest
	LegacyCompatible   bool // if the request is convertible to pre-condiscon format
	ImplicitDisclosure irma.AttributeConDisCon
	Status             server.Status
	PrevStatus         server.Status
	ResponseCache      responseCache
	LastActive         time.Time
	Result             *server.SessionResult
	KssProofs          map[irma.SchemeManagerIdentifier]*gabi.ProofP
}

type responseCache struct {
	Endpoint      string
	Message       []byte
	Response      []byte
	Status        int
	SessionStatus server.Status
}

type sessionStore interface {
	get(token irma.RequestorToken) (*session, error)
	clientGet(token irma.ClientToken) (*session, error)
	add(session *session) error
	update(session *session) error
	stop()
}

type memorySessionStore struct {
	sync.RWMutex
	conf *server.Configuration

	requestor map[irma.RequestorToken]*session
	client    map[irma.ClientToken]*session
}

type redisSessionStore struct {
	client *redis.Client
	conf   *server.Configuration
}

type RedisError interface {
	Error() string
}

type UnknownSessionError interface {
	Error() string
}

const (
	maxSessionLifetime         = 5 * time.Minute // After this a session is cancelled
	requestorTokenLookupPrefix = "token:"
	clientTokenLookupPrefix    = "session:"
)

var (
	minProtocolVersion = irma.NewVersion(2, 4)
	maxProtocolVersion = irma.NewVersion(2, 8)

	minFrontendProtocolVersion = irma.NewVersion(1, 0)
	maxFrontendProtocolVersion = irma.NewVersion(1, 1)
)

func (s *memorySessionStore) get(t irma.RequestorToken) (*session, error) {
	s.RLock()
	defer s.RUnlock()
	return s.requestor[t], nil
}

func (s *memorySessionStore) clientGet(t irma.ClientToken) (*session, error) {
	s.RLock()
	defer s.RUnlock()
	return s.client[t], nil
}

func (s *memorySessionStore) add(session *session) error {
	s.Lock()
	defer s.Unlock()
	s.requestor[session.RequestorToken] = session
	s.client[session.ClientToken] = session
	return nil
}

func (s *memorySessionStore) update(_ *session) error {
	return nil
}

func (s *memorySessionStore) stop() {
	s.Lock()
	defer s.Unlock()
	for _, session := range s.requestor {
		if session.sse != nil {
			session.sse.CloseChannel("session/" + string(session.RequestorToken))
			session.sse.CloseChannel("session/" + string(session.ClientToken))
			session.sse.CloseChannel("frontendsession/" + string(session.ClientToken))
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
		if session.Status == server.StatusInitialized && session.Rrequest.Base().ClientTimeout != 0 {
			timeout = time.Duration(session.Rrequest.Base().ClientTimeout) * time.Second
		}

		if session.LastActive.Add(timeout).Before(time.Now()) {
			if !session.Status.Finished() {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Infof("Session expired")
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
			session.sse.CloseChannel("session/" + string(session.RequestorToken))
			session.sse.CloseChannel("session/" + string(session.ClientToken))
			session.sse.CloseChannel("frontendsession/" + string(session.ClientToken))
		}
		delete(s.client, session.ClientToken)
		delete(s.requestor, token)
	}
	s.Unlock()
}

// UnmarshalJSON unmarshals sessionData.
func (s *sessionData) UnmarshalJSON(data []byte) error {
	type rawSessionData sessionData

	var temp struct {
		Rrequest json.RawMessage `json:",omitempty"`
		rawSessionData
	}

	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}

	*s = sessionData(temp.rawSessionData)

	if len(temp.Rrequest) == 0 {
		s.Rrequest = nil
		return errors.Errorf("temp.Rrequest == nil: %d \n", temp.Rrequest)
	}

	// unmarshal Rrequest
	switch s.Action {
	case "issuing":
		s.Rrequest = &irma.IdentityProviderRequest{}
	case "disclosing":
		s.Rrequest = &irma.ServiceProviderRequest{}
	case "signing":
		s.Rrequest = &irma.SignatureRequestorRequest{}
	}

	return json.Unmarshal(temp.Rrequest, s.Rrequest)
}

func (s *redisSessionStore) get(t string) (*session, error) {
	//TODO: input validation string?
	val, err := s.client.Get(context.Background(), requestorTokenLookupPrefix+t).Result()
	if err == redis.Nil {
		return nil, nil
	} else if err != nil {
		return nil, logAsRedisError(err)
	}

	return s.clientGet(val)
}

func (s *redisSessionStore) clientGet(t string) (*session, error) {
	val, err := s.client.Get(context.Background(), clientTokenLookupPrefix+t).Result()
	if err == redis.Nil {
		return nil, nil
	} else if err != nil {
		return nil, logAsRedisError(err)
	}

	var session session
	session.conf = s.conf
	session.sessions = s
	if err := json.Unmarshal([]byte(val), &session.sessionData); err != nil {
		return nil, logAsRedisError(err)
	}
	session.request = session.Rrequest.SessionRequest()

	if session.LastActive.Add(maxSessionLifetime).Before(time.Now()) && !session.Status.Finished() {
		s.conf.Logger.WithFields(logrus.Fields{"session": session.Token}).Infof("Session expired")
		session.markAlive()
		session.setStatus(server.StatusTimeout)
		_ = s.update(&session) // Worst case the TTL and status aren't updated. We won't deal with this error
	}

	return &session, nil
}

func (s *redisSessionStore) add(session *session) error {
	timeout := 2 * maxSessionLifetime // logic similar to memory store
	if session.Status == server.StatusInitialized && session.Rrequest.Base().ClientTimeout != 0 {
		timeout = time.Duration(session.Rrequest.Base().ClientTimeout) * time.Second
	} else if session.Status.Finished() {
		timeout = maxSessionLifetime
	}

	sessionJSON, err := json.Marshal(session.sessionData)
	if err != nil {
		return logAsRedisError(err)
	}

	err = s.client.Set(session.context, requestorTokenLookupPrefix+session.sessionData.Token, session.sessionData.ClientToken, timeout).Err()
	if err != nil {
		return logAsRedisError(err)
	}
	err = s.client.Set(session.context, clientTokenLookupPrefix+session.sessionData.ClientToken, sessionJSON, timeout).Err()
	if err != nil {
		return logAsRedisError(err)
	}

	return nil
}

func (s *redisSessionStore) update(session *session) error {
	return s.add(session)
}

func (s *redisSessionStore) stop() {
	err := s.client.Close()
	if err != nil {
		_ = logAsRedisError(err)
	}
}

var one *big.Int = big.NewInt(1)

func (s *Server) newSession(action irma.Action, request irma.RequestorRequest, ctx context.Context) (*session, error) {
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

	sd := sessionData{
		Action:      action,
		Rrequest:    request,
		LastActive:  time.Now(),
		RequestorToken:       requestorToken,
		ClientToken: clientToken,
		Status:      server.StatusInitialized,
		PrevStatus:  server.StatusInitialized,
		Result: &server.SessionResult{
			LegacySession: request.SessionRequest().Base().Legacy(),
			Token:         requestorToken,
			Type:          action,
			Status:        irma.ServerStatusInitialized,
		},
	}
	ses := &session{
		sessionData: sd,
		sessions:    s.sessions,
		sse:         s.serverSentEvents,
		conf:        s.conf,
		request:     request.SessionRequest(),
		context:     ctx,

		options: irma.SessionOptions{
			LDContext:     irma.LDContextSessionOptions,
			PairingMethod: irma.PairingMethodNone,
		},
		frontendAuth:   frontendAuth,
	}

	s.conf.Logger.WithFields(logrus.Fields{"session": ses.RequestorToken}).Debug("New session started")
	nonce, _ := gabi.GenerateNonce()
	base.Nonce = nonce
	base.Context = one
	err := s.sessions.add(ses)
	if err != nil {
		return nil, err
	}

	return ses, nil
}

func logAsRedisError(err error) error {
	return server.LogError(RedisError(err))
}
