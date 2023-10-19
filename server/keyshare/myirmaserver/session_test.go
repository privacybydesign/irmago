package myirmaserver

import (
	"context"
	"testing"
	"time"

	// "github.com/alicebob/miniredis/v2"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"
)

func TestMemorySessionStore(t *testing.T) {
	testSessions(t, newMemorySessionStore(), time.Sleep)
}

func TestRedisSessionStore(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	mr.Start()
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Host() + ":" + mr.Port()})
	testSessions(t, &redisSessionStore{client: &server.RedisClient{Client: client}, logger: server.Logger}, mr.FastForward)
}

func testSessions(t *testing.T, store sessionStore, sleepFn func(time.Duration)) {
	s := session{
		Token:  "token",
		Expiry: time.Now().Add(1 * time.Second),
	}
	err := store.add(context.Background(), s)
	assert.NoError(t, err)

	session2, err := getSession(store, s.Token)
	assert.NoError(t, err)
	assert.Equal(t, s.Expiry.Unix(), session2.Expiry.Unix())
	s.Expiry = session2.Expiry // Time is not exactly equal, so set it to the same value
	assert.Equal(t, s, session2)

	emailSessionToken := irma.RequestorToken("emailtoken")
	err = store.update(context.Background(), s.Token, func(ses *session) error {
		ses.EmailSessionToken = emailSessionToken
		return nil
	})
	assert.NoError(t, err)

	session3, err := getSession(store, s.Token)
	assert.NoError(t, err)
	assert.Equal(t, session3.EmailSessionToken, emailSessionToken)

	_, err = getSession(store, "DOESNOTEXIST")
	assert.ErrorIs(t, err, errUnknownSession)

	store.flush()

	session4, err := getSession(store, s.Token)
	assert.NoError(t, err)
	assert.Equal(t, session4.Token, s.Token)

	sleepFn(2 * time.Second)

	store.flush()

	_, err = getSession(store, s.Token)
	assert.ErrorIs(t, err, errUnknownSession)
}

func getSession(store sessionStore, token string) (session, error) {
	var ses session
	return ses, store.update(context.Background(), token, func(s *session) error {
		ses = *s
		return nil
	})
}
