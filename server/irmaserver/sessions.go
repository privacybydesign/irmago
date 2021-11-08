package irmaserver

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-errors/errors"
	"strings"
	"sync"
	"time"

	"github.com/bsm/redislock"

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
	sync.Mutex
	sse            *sse.Server
	locked         bool
	lock           *redislock.Lock
	sessions       sessionStore
	conf           *server.Configuration
	request        irma.SessionRequest
	statusChannels []chan irma.ServerStatus

	sessionData
}

type sessionData struct {
	Action             irma.Action
	RequestorToken     irma.RequestorToken
	ClientToken        irma.ClientToken
	Version            *irma.ProtocolVersion `json:",omitempty"`
	Rrequest           irma.RequestorRequest
	LegacyCompatible   bool // if the request is convertible to pre-condiscon format
	Status             irma.ServerStatus
	PrevStatus         irma.ServerStatus
	ResponseCache      responseCache
	LastActive         time.Time
	Result             *server.SessionResult
	KssProofs          map[irma.SchemeManagerIdentifier]*gabi.ProofP
	Next               *irma.Qr
	FrontendAuth       irma.FrontendAuthorization
	ImplicitDisclosure irma.AttributeConDisCon
	Options            irma.SessionOptions
	ClientAuth         irma.ClientAuthorization
}

type responseCache struct {
	Endpoint      string
	Message       []byte
	Response      []byte
	Status        int
	SessionStatus irma.ServerStatus
}

type sessionStore interface {
	get(token irma.RequestorToken) (*session, error)
	clientGet(token irma.ClientToken) (*session, error)
	add(session *session) error
	update(session *session) error
	lock(session *session) error
	unlock(session *session) error
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
	locker *redislock.Client
	conf   *server.Configuration
}

type RedisError struct {
	err error
}

func (err *RedisError) Error() string {
	return fmt.Sprintf("redis error: %s", err.err)
}

type UnknownSessionError struct {
	requestorToken irma.RequestorToken
	clientToken    irma.ClientToken
}

func (err *UnknownSessionError) Error() string {
	if err.requestorToken != "" {
		return fmt.Sprintf("session result requested of unknown session %s", err.requestorToken)
	} else {
		return fmt.Sprintf("session result requested of unknown session with clientToken %s", err.clientToken)
	}
}

const (
	maxLockLifetime            = 500 * time.Millisecond // After this the Redis lock self-deletes, preventing a deadlock
	minLockRetryTime           = 30 * time.Millisecond
	maxLockRetryTime           = 2 * time.Second
	requestorTokenLookupPrefix = "token:"
	clientTokenLookupPrefix    = "session:"
	lockPrefix                 = "lock:"
)

var (
	minProtocolVersion = irma.NewVersion(2, 4)
	maxProtocolVersion = irma.NewVersion(2, 8)

	minFrontendProtocolVersion = irma.NewVersion(1, 0)
	maxFrontendProtocolVersion = irma.NewVersion(1, 1)

	lockingRetryOptions = &redislock.Options{RetryStrategy: redislock.ExponentialBackoff(minLockRetryTime, maxLockRetryTime)}
)

func (s *memorySessionStore) get(t irma.RequestorToken) (*session, error) {
	s.RLock()
	defer s.RUnlock()
	if s.requestor[t] != nil {
		return s.requestor[t], nil
	} else {
		return nil, server.LogError(&UnknownSessionError{t, ""})
	}
}

func (s *memorySessionStore) clientGet(t irma.ClientToken) (*session, error) {
	s.RLock()
	defer s.RUnlock()

	if s.client[t] != nil {
		return s.client[t], nil
	} else {
		return nil, server.LogError(&UnknownSessionError{"", t})
	}
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

func (s *memorySessionStore) lock(session *session) error {
	session.Lock()
	session.locked = true

	return nil
}

func (s *memorySessionStore) unlock(session *session) error {
	session.locked = false
	session.Unlock()

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

		timeout := s.conf.MaxSessionLifetime
		if session.Status == irma.ServerStatusInitialized && session.Rrequest.Base().ClientTimeout != 0 {
			timeout = time.Duration(session.Rrequest.Base().ClientTimeout) * time.Second
		}

		if session.LastActive.Add(timeout).Before(time.Now()) {
			if !session.Status.Finished() {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Infof("Session expired")
				session.markAlive()
				session.setStatus(irma.ServerStatusTimeout)
			} else {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Infof("Deleting session")
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

func (s *redisSessionStore) get(t irma.RequestorToken) (*session, error) {
	val, err := s.client.Get(context.Background(), requestorTokenLookupPrefix+string(t)).Result()
	if err == redis.Nil {
		return nil, server.LogError(&UnknownSessionError{t, ""})
	} else if err != nil {
		return nil, logAsRedisError(err)
	}

	clientToken, err := irma.ParseClientToken(val)
	if err != nil {
		return nil, logAsRedisError(err)
	}
	s.conf.Logger.WithFields(logrus.Fields{"session": t}).Debugf("clientToken [%s] found in Redis datastore", clientToken)

	return s.clientGet(clientToken)
}

func (s *redisSessionStore) clientGet(t irma.ClientToken) (*session, error) {
	val, err := s.client.Get(context.Background(), clientTokenLookupPrefix+string(t)).Result()
	if err == redis.Nil {
		return nil, server.LogError(&UnknownSessionError{"", t})
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

	if session.LastActive.Add(s.conf.MaxSessionLifetime).Before(time.Now()) && !session.Status.Finished() {
		s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Infof("Session expired")
		session.markAlive()
		session.setStatus(irma.ServerStatusTimeout)
	}

	s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Debugf("Session received from Redis datastores")
	return &session, nil
}

func (s *redisSessionStore) add(session *session) error {
	timeout := 2 * s.conf.MaxSessionLifetime // logic similar to memory store
	if session.Status == irma.ServerStatusInitialized && session.Rrequest.Base().ClientTimeout != 0 {
		timeout = time.Duration(session.Rrequest.Base().ClientTimeout) * time.Second
	} else if session.Status.Finished() {
		timeout = s.conf.MaxSessionLifetime
	}

	sessionJSON, err := json.Marshal(session.sessionData)
	if err != nil {
		return server.LogError(err)
	}

	err = s.client.Set(context.Background(), requestorTokenLookupPrefix+string(session.sessionData.RequestorToken), string(session.sessionData.ClientToken), timeout).Err()
	if err != nil {
		return logAsRedisError(err)
	}
	err = s.client.Set(context.Background(), clientTokenLookupPrefix+string(session.sessionData.ClientToken), sessionJSON, timeout).Err()
	if err != nil {
		return logAsRedisError(err)
	}

	s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Debugf("session added to Redis datastore")
	return nil
}

func (s *redisSessionStore) update(session *session) error {
	// Time passes between acquiring the lock and writing to Redis. Check before write action that lock is still valid.
	if session.lock == nil {
		return logAsRedisError(errors.Errorf("lock is not set for session with requestorToken [%s]", session.RequestorToken))
	} else if ttl, err := session.lock.TTL(context.Background()); err != nil {
		return logAsRedisError(err)
	} else if ttl == 0 {
		return logAsRedisError(errors.Errorf("no session lock available for session with requestorToken [%s]", session.RequestorToken))
	}
	return s.add(session)
}

func (s *redisSessionStore) lock(session *session) error {
	lock, err := s.locker.Obtain(context.Background(), lockPrefix+string(session.ClientToken), maxLockLifetime, lockingRetryOptions)
	if err == redislock.ErrNotObtained {
		// It is possible that the session is already locked. However, it should not happen often. If you get this warning often,
		// you should investigate why.
		return server.LogWarning(&RedisError{err})
	} else if err != nil {
		return logAsRedisError(err)
	}
	session.locked = true
	session.lock = lock
	s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Debugf("session locked successfully")

	return nil
}

func (s *redisSessionStore) unlock(session *session) error {
	session.locked = false
	err := session.lock.Release(context.Background())
	if err == redislock.ErrLockNotHeld {
		s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Info("lock could not be released as the lock was not held")
		return nil
	} else if err != nil {
		return logAsRedisError(err)
	}
	s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Debugf("session unlocked successfully")

	return nil
}

func (s *redisSessionStore) stop() {
	err := s.client.Close()
	if err != nil {
		_ = logAsRedisError(err)
	}
	s.conf.Logger.Info("Redis client closed successfully")
}

var one *big.Int = big.NewInt(1)

func (s *Server) newSession(action irma.Action, request irma.RequestorRequest, disclosed irma.AttributeConDisCon, FrontendAuth irma.FrontendAuthorization) (*session, error) {
	clientToken := irma.ClientToken(common.NewSessionToken())
	requestorToken := irma.RequestorToken(common.NewSessionToken())
	if len(FrontendAuth) == 0 {
		FrontendAuth = irma.FrontendAuthorization(common.NewSessionToken())
	}

	base := request.SessionRequest().Base()
	if s.conf.AugmentClientReturnURL && base.AugmentReturnURL && base.ClientReturnURL != "" {
		if strings.Contains(base.ClientReturnURL, "?") {
			base.ClientReturnURL += "&token=" + string(requestorToken)
		} else {
			base.ClientReturnURL += "?token=" + string(requestorToken)
		}
	}

	sd := sessionData{
		Action:         action,
		Rrequest:       request,
		LastActive:     time.Now(),
		RequestorToken: requestorToken,
		ClientToken:    clientToken,
		Status:         irma.ServerStatusInitialized,
		PrevStatus:     irma.ServerStatusInitialized,
		Result: &server.SessionResult{
			LegacySession: request.SessionRequest().Base().Legacy(),
			Token:         requestorToken,
			Type:          action,
			Status:        irma.ServerStatusInitialized,
		},
		Options: irma.SessionOptions{
			LDContext:     irma.LDContextSessionOptions,
			PairingMethod: irma.PairingMethodNone,
		},
		FrontendAuth:       FrontendAuth,
		ImplicitDisclosure: disclosed,
	}
	ses := &session{
		sessionData: sd,
		sessions:    s.sessions,
		sse:         s.serverSentEvents,
		conf:        s.conf,
		request:     request.SessionRequest(),
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
	return server.LogError(&RedisError{err})
}
