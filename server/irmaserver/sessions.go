package irmaserver

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-errors/errors"

	"github.com/go-redis/redis/v8"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"

	"github.com/sirupsen/logrus"
)

type sessionData struct {
	Action             irma.Action
	RequestorToken     irma.RequestorToken
	ClientToken        irma.ClientToken
	Version            *irma.ProtocolVersion `json:",omitempty"`
	Rrequest           irma.RequestorRequest
	LegacyCompatible   bool // if the request is convertible to pre-condiscon format
	Status             irma.ServerStatus
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
	add(*sessionData) error
	transaction(irma.RequestorToken, func(*sessionData) error) error
	clientTransaction(irma.ClientToken, func(*sessionData) error) error
	subscribeStatusChanges(irma.RequestorToken) (chan statusChange, error)
	stop()
}

type statusChange struct {
	irma.FrontendSessionStatus
	Timeout time.Duration
}

type memorySessionStore struct {
	sync.RWMutex
	conf           *server.Configuration
	requestor      map[irma.RequestorToken]*memorySessionData
	client         map[irma.ClientToken]*memorySessionData
	statusChannels map[irma.RequestorToken][]chan statusChange
}

type memorySessionData struct {
	sync.Mutex
	*sessionData
}

type redisSessionStore struct {
	client *server.RedisClient
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
)

var (
	// AcceptInsecureProtocolVersions determines whether the server accepts connections from apps using an insecure protocol version.
	// It is set to false by default, but can be set to true for backwards compatibility with older apps. This is not recommended.
	AcceptInsecureProtocolVersions = false

	minProtocolVersion       = irma.NewVersion(2, 4)
	minSecureProtocolVersion = irma.NewVersion(2, 8)
	maxProtocolVersion       = irma.NewVersion(2, 8)

	minFrontendProtocolVersion = irma.NewVersion(1, 0)
	maxFrontendProtocolVersion = irma.NewVersion(1, 1)
)

func (s *memorySessionStore) add(session *sessionData) error {
	s.Lock()
	defer s.Unlock()
	memSes := &memorySessionData{sessionData: session}
	s.requestor[session.RequestorToken] = memSes
	s.client[session.ClientToken] = memSes
	return nil
}

func (s *memorySessionStore) transaction(t irma.RequestorToken, handler func(session *sessionData) error) error {
	s.RLock()
	ses := s.requestor[t]
	s.RUnlock()

	if ses == nil {
		return server.LogError(&UnknownSessionError{t, ""})
	}

	ses.Lock()
	copy, err := copyObject(ses.sessionData)
	ses.Unlock()
	if err != nil {
		return err
	}
	sesCopy := copy.(*sessionData)

	if err := s.handleTransaction(sesCopy, handler); err != nil {
		return err
	}

	s.Lock()
	defer s.Unlock()
	s.requestor[t].sessionData = sesCopy
	return nil
}

func (s *memorySessionStore) clientTransaction(t irma.ClientToken, handler func(session *sessionData) error) error {
	s.RLock()
	ses := s.client[t]
	s.RUnlock()

	if ses == nil {
		return server.LogError(&UnknownSessionError{"", t})
	}

	ses.Lock()
	copy, err := copyObject(ses.sessionData)
	ses.Unlock()
	if err != nil {
		return err
	}
	sesCopy := copy.(*sessionData)

	if err := s.handleTransaction(sesCopy, handler); err != nil {
		return err
	}

	s.Lock()
	defer s.Unlock()
	s.client[t].sessionData = sesCopy
	return nil
}

func (s *memorySessionStore) handleTransaction(ses *sessionData, handler func(session *sessionData) error) error {
	prevStatus := ses.Status

	if !ses.Status.Finished() && ses.timeout(s.conf) <= 0 {
		s.conf.Logger.WithFields(logrus.Fields{"session": ses.RequestorToken}).Info("Session expired")
		ses.setStatus(irma.ServerStatusTimeout, s.conf)
	}

	if err := handler(ses); err != nil {
		return err
	}

	if prevStatus != ses.Status {
		for _, channel := range s.statusChannels[ses.RequestorToken] {
			channel <- statusChange{
				FrontendSessionStatus: irma.FrontendSessionStatus{
					Status:      ses.Status,
					NextSession: ses.Next,
				},
				Timeout: ses.timeout(s.conf),
			}
		}
	}
	return nil
}

func (s *memorySessionStore) subscribeStatusChanges(token irma.RequestorToken) (chan statusChange, error) {
	statusChan := make(chan statusChange, 4)
	s.Lock()
	defer s.Unlock()
	s.statusChannels[token] = append(s.statusChannels[token], statusChan)
	return statusChan, nil
}

func (s *memorySessionStore) stop() {
	s.Lock()
	defer s.Unlock()
	for _, session := range s.requestor {
		for _, channel := range s.statusChannels[session.RequestorToken] {
			close(channel)
		}
	}
}

func (s *memorySessionStore) deleteExpired() {
	// First check which sessions have expired
	// We don't need a write lock for this yet, so postpone that for actual deleting
	s.RLock()
	toCheck := make(map[irma.RequestorToken]struct{}, len(s.requestor))
	for token := range s.requestor {
		toCheck[token] = struct{}{}
	}
	s.RUnlock()

	expired := make([]irma.RequestorToken, 0, len(toCheck))
	for token := range toCheck {
		s.transaction(token, func(session *sessionData) error {
			if session.ttl(s.conf) <= 0 {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Info("Deleting session")
				expired = append(expired, token)
			}
			return nil
		})
	}

	// Using a write lock, delete the expired sessions
	s.Lock()
	for _, token := range expired {
		session := s.requestor[token]
		delete(s.client, session.ClientToken)
		delete(s.requestor, token)
	}
	s.Unlock()
}

func (s *redisSessionStore) add(session *sessionData) error {
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return server.LogError(err)
	}

	ttl := session.ttl(s.conf)
	conn := s.client.Conn(context.Background())
	if err := conn.Set(context.Background(), requestorTokenLookupPrefix+string(session.RequestorToken), string(session.ClientToken), ttl).Err(); err != nil {
		return logAsRedisError(err)
	}
	if err := conn.Set(context.Background(), clientTokenLookupPrefix+string(session.ClientToken), sessionJSON, ttl).Err(); err != nil {
		return logAsRedisError(err)
	}

	if s.client.FailoverMode {
		if err := s.client.Wait(context.Background(), 1, time.Second).Err(); err != nil {
			return logAsRedisError(err)
		}
	}

	s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Debug("session added or updated in Redis datastore")
	return nil
}

func (s *redisSessionStore) transaction(t irma.RequestorToken, handler func(session *sessionData) error) error {
	val, err := s.client.Get(context.Background(), requestorTokenLookupPrefix+string(t)).Result()
	if err == redis.Nil {
		return server.LogError(&UnknownSessionError{t, ""})
	} else if err != nil {
		return logAsRedisError(err)
	}

	clientToken, err := irma.ParseClientToken(val)
	if err != nil {
		return logAsRedisError(err)
	}
	s.conf.Logger.WithFields(logrus.Fields{"session": t, "clientToken": clientToken}).Debug("clientToken found in Redis datastore")

	return s.clientTransaction(clientToken, handler)
}

func (s *redisSessionStore) clientTransaction(t irma.ClientToken, handler func(session *sessionData) error) error {
	if err := s.client.Watch(context.Background(), func(tx *redis.Tx) error {
		getResult := tx.Get(context.Background(), clientTokenLookupPrefix+string(t))
		if getResult.Err() == redis.Nil {
			// Both session and error need to be returned. The session will already be locked and needs to
			// be passed along, so it can be unlocked later.
			return server.LogError(&UnknownSessionError{"", t})
		} else if getResult.Err() != nil {
			return logAsRedisError(getResult.Err())
		}

		session := &sessionData{}
		if err := json.Unmarshal([]byte(getResult.Val()), &session); err != nil {
			return logAsRedisError(err)
		}

		s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Debug("Session received from Redis datastore")

		// Hashing the current session data needs to take place before the timeout check to detect all changes!
		hashBefore := session.hash()

		// Timeout check
		if !session.Status.Finished() && session.timeout(s.conf) <= 0 {
			s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Info("Session expired")
			session.setStatus(irma.ServerStatusTimeout, s.conf)
		}

		if err := handler(session); err != nil {
			return err
		}

		// Check if the session has changed
		hashAfter := session.hash()
		if hashBefore == hashAfter {
			return nil
		}

		// If the session has changed, update it in Redis
		sessionJSON, err := json.Marshal(session)
		if err != nil {
			return server.LogError(err)
		}

		err = tx.Set(context.Background(), clientTokenLookupPrefix+string(t), sessionJSON, 0).Err()
		if err != nil {
			return logAsRedisError(err)
		}

		if s.client.FailoverMode {
			if err := tx.Wait(context.Background(), 1, time.Second).Err(); err != nil {
				return logAsRedisError(err)
			}
		}
		return nil
	}); err != nil {
		return logAsRedisError(err)
	}
	return nil
}

func (s *redisSessionStore) subscribeStatusChanges(token irma.RequestorToken) (chan statusChange, error) {
	return nil, errors.New("not implemented")
}

func (s *redisSessionStore) stop() {
	err := s.client.Close()
	if err != nil {
		_ = logAsRedisError(err)
	}
	s.conf.Logger.Info("Redis client closed successfully")
}

var one *big.Int = big.NewInt(1)

func (s *Server) newSession(action irma.Action, request irma.RequestorRequest, disclosed irma.AttributeConDisCon, FrontendAuth irma.FrontendAuthorization) (*sessionData, error) {
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

	ses := &sessionData{
		Action:         action,
		Rrequest:       request,
		LastActive:     time.Now(),
		RequestorToken: requestorToken,
		ClientToken:    clientToken,
		Status:         irma.ServerStatusInitialized,
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
