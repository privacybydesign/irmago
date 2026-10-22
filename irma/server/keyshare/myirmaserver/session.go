package myirmaserver

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/go-errors/errors"
	"github.com/go-redis/redis/v8"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server"
	"github.com/sirupsen/logrus"
)

const sessionLookupPrefix = "myirmaserver/session/"

var (
	errRedis          = errors.New("redis error")
	errUnknownSession = errors.New("unknown session")

	// errConcurrentSessionUpdate is returned when a session transaction had to be retried
	// after the handler already ran, but the session was changed by someone else in the
	// meantime: the handler cannot be re-run, so the write is abandoned.
	errConcurrentSessionUpdate = errors.New("session was updated concurrently")
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

	ttl := time.Until(ses.Expiry)
	if ttl <= 0 {
		return errors.New("session expiry time is in the past")
	}
	// The write is unconditional, so it can simply be run again when the connection it ran
	// on went away.
	if err := s.client.RetryOnBrokenConn(ctx, func() error {
		return s.client.Set(
			ctx,
			s.client.KeyPrefix+sessionLookupPrefix+ses.Token,
			string(bytes),
			ttl,
		).Err()
	}); err != nil {
		s.logger.WithError(err).Error("failed to add session")
		return errRedis
	}
	return nil
}

func (s *redisSessionStore) update(ctx context.Context, token string, handler func(ses *session) error) error {
	key := s.client.KeyPrefix + sessionLookupPrefix + token

	write := func(tx *server.RedisTx, sessionJSON []byte, ttl time.Duration) error {
		_, err := tx.TxPipelined(ctx, func(p redis.Pipeliner) error {
			return p.Set(ctx, key, sessionJSON, ttl).Err()
		})
		return err
	}

	err := s.client.WatchWithRetry(ctx, []string{key}, func(tx *server.RedisTx) error {
		before, err := tx.Get(ctx, key).Bytes()
		if err == redis.Nil {
			return errUnknownSession
		} else if err != nil {
			return err
		}

		session := &session{}
		if err := json.Unmarshal(before, session); err != nil {
			return err
		}

		// Everything above is a plain read that a retry can safely redo. The handler is not:
		// it writes to a shared HTTP response recorder, sets cookies, and may collect an IRMA
		// session result from the IRMA server.
		tx.NoRetry()
		if err := handler(session); err != nil {
			return err
		}

		after, err := json.Marshal(session)
		if err != nil {
			return err
		}

		ttl := time.Until(session.Expiry)
		if ttl <= 0 {
			return errors.New("session expiry time is in the past")
		}

		// The handler is done and its outcome is fully captured in after, so a write that
		// fails on a broken connection can be redone without running the handler again. Only
		// the session the handler based itself on may be overwritten, which is the same
		// condition the WATCH on this key enforces for the write below.
		tx.RetryWith(func(tx *server.RedisTx) error {
			current, err := tx.Get(ctx, key).Bytes()
			if err == redis.Nil {
				return errUnknownSession
			} else if err != nil {
				return err
			}
			switch {
			case bytes.Equal(current, before):
				return write(tx, after, ttl)
			case bytes.Equal(current, after):
				// The connection broke after Redis had already applied the write.
				return nil
			default:
				return errConcurrentSessionUpdate
			}
		})
		return write(tx, after, ttl)
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
