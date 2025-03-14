package irmaserver

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-errors/errors"

	"github.com/go-redis/redis/v8"
	"github.com/privacybydesign/gabi"
	irma "github.com/privacybydesign/irmago"
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
	add(context.Context, *sessionData) error
	transaction(context.Context, irma.RequestorToken, func(*sessionData) (bool, error)) error
	clientTransaction(context.Context, irma.ClientToken, func(*sessionData) (bool, error)) error
	subscribeUpdates(context.Context, irma.RequestorToken) (chan *sessionData, error)
	stop()
}

type memorySessionStore struct {
	sync.RWMutex
	conf           *server.Configuration
	requestor      map[irma.RequestorToken]*memorySessionData
	client         map[irma.ClientToken]*memorySessionData
	updateChannels map[irma.RequestorToken][]chan *sessionData
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

func (s *memorySessionStore) add(ctx context.Context, session *sessionData) error {
	s.Lock()
	defer s.Unlock()
	memSes := &memorySessionData{sessionData: session}
	s.requestor[session.RequestorToken] = memSes
	s.client[session.ClientToken] = memSes
	return nil
}

func (s *memorySessionStore) transaction(ctx context.Context, t irma.RequestorToken, handler func(session *sessionData) (bool, error)) error {
	s.RLock()
	memSes := s.requestor[t]
	s.RUnlock()

	if memSes == nil {
		return &UnknownSessionError{t, ""}
	}
	return s.handleTransaction(memSes, handler)
}

func (s *memorySessionStore) clientTransaction(ctx context.Context, t irma.ClientToken, handler func(session *sessionData) (bool, error)) error {
	s.RLock()
	memSes := s.client[t]
	s.RUnlock()

	if memSes == nil {
		return &UnknownSessionError{"", t}
	}
	return s.handleTransaction(memSes, handler)
}

func (s *memorySessionStore) handleTransaction(memSes *memorySessionData, handler func(session *sessionData) (bool, error)) error {
	// The session struct contains pointers to other structs, so we need to give the handler a deep copy to prevent side effects.
	sesBefore := memSes.sessionData
	ses := &sessionData{}
	memSes.Lock()
	err := copyObject(sesBefore, ses)
	memSes.Unlock()
	if err != nil {
		return err
	}

	if !ses.Status.Finished() && ses.timeout(s.conf) <= 0 {
		ses.setStatus(irma.ServerStatusTimeout, s.conf)
	}

	if update, err := handler(ses); !update || err != nil {
		return err
	}

	s.conf.Logger.
		WithFields(logrus.Fields{"session": ses.RequestorToken, "status": ses.Status}).
		Info("Session updated")

	// Make a deep copy of the session data, so we can update it in memory without side effects.
	sesAfter := &sessionData{}
	if err := copyObject(ses, sesAfter); err != nil {
		return err
	}

	// Check if the session has changed by another routine, and if not, update it in memory.
	memSes.Lock()
	defer memSes.Unlock()
	if sesBefore != memSes.sessionData {
		return errors.New("session changed by another routine")
	}
	memSes.sessionData = sesAfter

	go func() {
		for _, channel := range s.updateChannels[ses.RequestorToken] {
			channel <- ses
		}
	}()
	return nil
}

func (s *memorySessionStore) subscribeUpdates(ctx context.Context, token irma.RequestorToken) (chan *sessionData, error) {
	statusChan := make(chan *sessionData)
	s.Lock()
	defer s.Unlock()
	s.updateChannels[token] = append(s.updateChannels[token], statusChan)
	return statusChan, nil
}

func (s *memorySessionStore) stop() {
	s.Lock()
	defer s.Unlock()
	for _, session := range s.requestor {
		for _, channel := range s.updateChannels[session.RequestorToken] {
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
		if err := s.transaction(context.Background(), token, func(session *sessionData) (bool, error) {
			if session.ttl(s.conf) <= 0 {
				s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Info("Deleting expired session")
				expired = append(expired, token)
			}
			return false, nil
		}); err != nil {
			s.conf.Logger.WithFields(logrus.Fields{"session": token}).WithError(err).Error("Error while deleting expired session")
		}
	}

	// Using a write lock, delete the expired sessions
	s.Lock()
	defer s.Unlock()
	for _, token := range expired {
		session := s.requestor[token]
		delete(s.client, session.ClientToken)
		delete(s.requestor, token)
		for _, channel := range s.updateChannels[token] {
			close(channel)
		}
		delete(s.updateChannels, token)
	}
}

func (s *redisSessionStore) add(ctx context.Context, session *sessionData) error {
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return &RedisError{err}
	}

	ttl := session.ttl(s.conf)
	if ttl <= 0 {
		return &RedisError{errors.New("session ttl is in the past")}
	}
	if _, err := s.client.TxPipelined(ctx, func(p redis.Pipeliner) error {
		if err := p.Set(
			ctx,
			s.client.KeyPrefix+requestorTokenLookupPrefix+string(session.RequestorToken),
			string(session.ClientToken),
			ttl,
		).Err(); err != nil {
			return err
		}
		return p.Set(
			ctx,
			s.client.KeyPrefix+clientTokenLookupPrefix+string(session.ClientToken),
			sessionJSON,
			ttl,
		).Err()
	}); err != nil {
		return &RedisError{err}
	}

	s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Debug("Session added in Redis datastore")
	return nil
}

func (s *redisSessionStore) transaction(ctx context.Context, t irma.RequestorToken, handler func(session *sessionData) (bool, error)) error {
	val, err := s.client.Get(ctx, s.client.KeyPrefix+requestorTokenLookupPrefix+string(t)).Result()
	if err == redis.Nil {
		return &UnknownSessionError{t, ""}
	} else if err != nil {
		return &RedisError{err}
	}

	clientToken, err := irma.ParseClientToken(val)
	if err != nil {
		return &RedisError{err}
	}
	s.conf.Logger.WithFields(logrus.Fields{"session": t, "clientToken": clientToken}).Debug("clientToken found in Redis datastore")

	return s.clientTransaction(ctx, clientToken, handler)
}

func (s *redisSessionStore) clientTransaction(ctx context.Context, t irma.ClientToken, handler func(session *sessionData) (bool, error)) error {
	err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		getResult := tx.Get(ctx, s.client.KeyPrefix+clientTokenLookupPrefix+string(t))
		if getResult.Err() == redis.Nil {
			return &UnknownSessionError{"", t}
		} else if getResult.Err() != nil {
			return getResult.Err()
		}

		session := &sessionData{}
		if err := json.Unmarshal([]byte(getResult.Val()), &session); err != nil {
			return err
		}

		s.conf.Logger.WithFields(logrus.Fields{"session": session.RequestorToken}).Debug("Session received from Redis datastore")

		// Timeout check
		if !session.Status.Finished() && session.timeout(s.conf) <= 0 {
			session.setStatus(irma.ServerStatusTimeout, s.conf)
		}

		if update, err := handler(session); !update || err != nil {
			return err
		}

		s.conf.Logger.
			WithFields(logrus.Fields{"session": session.RequestorToken, "status": session.Status}).
			Info("Session updated")

		// If the session has changed, update it in Redis
		sessionJSON, err := json.Marshal(session)
		if err != nil {
			return err
		}

		ttl := session.ttl(s.conf)
		if ttl <= 0 {
			return errors.New("session ttl is in the past")
		}

		_, err = tx.TxPipelined(ctx, func(p redis.Pipeliner) error {
			if err := p.Set(ctx, s.client.KeyPrefix+clientTokenLookupPrefix+string(t), sessionJSON, ttl).Err(); err != nil {
				return err
			}
			return p.Expire(ctx, s.client.KeyPrefix+requestorTokenLookupPrefix+string(session.RequestorToken), ttl).Err()
		})
		return err
	})
	if _, ok := err.(*UnknownSessionError); ok {
		return err
	} else if err != nil {
		return &RedisError{err}
	}
	return nil
}

func (s *redisSessionStore) subscribeUpdates(ctx context.Context, token irma.RequestorToken) (chan *sessionData, error) {
	return nil, errors.New("not implemented")
}

func (s *redisSessionStore) stop() {
	err := s.client.Close()
	if err != nil {
		s.conf.Logger.WithError(err).Error("Error closing Redis client")
	}
	s.conf.Logger.Info("Redis client closed successfully")
}
