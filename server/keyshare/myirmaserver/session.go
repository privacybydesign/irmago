package myirmaserver

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/go-errors/errors"
	"github.com/go-redis/redis/v8"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

const sessionLookupPrefix = "myirmaserver/session/"

var (
	errRedis          = errors.New("redis error")
	errUnknownSession = errors.New("unknown session")
)

type session struct {
	Token  string `json:"token"`
	UserID *int64 `json:"user_id,omitempty"`

	LoginSessionToken irma.RequestorToken `json:"login_session_token,omitempty"`
	EmailSessionToken irma.RequestorToken `json:"email_session_token,omitempty"`

	Expiry time.Time `json:"expiry"`
}

type sessionStore interface {
	add(ctx context.Context, ses session) error
	update(ctx context.Context, token string, handler func(ses *session) error) error
	flush()
}

type memorySessionStore struct {
	sync.Mutex
	data map[string]session
}

type redisSessionStore struct {
	client *server.RedisClient
	logger *logrus.Logger
}

func newMemorySessionStore() sessionStore {
	return &memorySessionStore{
		data: map[string]session{},
	}
}

func (s *memorySessionStore) add(_ context.Context, ses session) error {
	s.Lock()
	defer s.Unlock()
	s.data[ses.Token] = ses
	return nil
}

func (s *memorySessionStore) update(_ context.Context, token string, handler func(ses *session) error) error {
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
		if now.After(v.Expiry) {
			delete(s.data, k)
		}
	}
}

func (s *redisSessionStore) add(ctx context.Context, ses session) error {
	bytes, err := json.Marshal(ses)
	if err != nil {
		return err
	}

	ttl := time.Until(ses.Expiry).Seconds()
	if err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		if err := tx.Set(
			ctx,
			s.client.KeyPrefix+sessionLookupPrefix+ses.Token,
			string(bytes),
			time.Duration(ttl)*time.Second,
		).Err(); err != nil {
			return err
		}
		if s.client.FailoverMode {
			if err := tx.Wait(ctx, 1, time.Second).Err(); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		s.logger.WithError(err).Error("failed to add session")
		return errRedis
	}
	return nil
}

func (s *redisSessionStore) update(ctx context.Context, token string, handler func(ses *session) error) error {
	key := s.client.KeyPrefix + sessionLookupPrefix + token

	err := s.client.Watch(ctx, func(tx *redis.Tx) error {
		bytes, err := tx.Get(ctx, key).Bytes()
		if err == redis.Nil {
			return errUnknownSession
		} else if err != nil {
			return err
		}

		session := &session{}
		if err := json.Unmarshal(bytes, session); err != nil {
			return err
		}

		if err := handler(session); err != nil {
			return err
		}

		updatedBytes, err := json.Marshal(session)
		if err != nil {
			return err
		}

		if err := tx.Set(ctx, key, string(updatedBytes), time.Until(session.Expiry)).Err(); err != nil {
			return err
		}

		if s.client.FailoverMode {
			if err := tx.Wait(ctx, 1, time.Second).Err(); err != nil {
				return err
			}
		}
		return nil
	})
	if err == errUnknownSession {
		return err
	} else if err != nil {
		s.logger.WithError(err).Error("failed to update session")
		return errRedis
	}
	return nil
}

func (s *redisSessionStore) flush() {
	// Redis keys expire automatically.
}
