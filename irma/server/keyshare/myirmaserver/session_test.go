package myirmaserver

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemorySessionStore(t *testing.T) {
	testSessions(t, newMemorySessionStore(), time.Sleep)
}

func TestRedisSessionStore(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Host() + ":" + mr.Port()})
	defer client.Close()
	testSessions(t, &redisSessionStore{client: &server.RedisClient{Client: client}, logger: server.Logger}, mr.FastForward)
}

func TestRedisSessionStoreUpdateWatchesSessionKey(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	require.NoError(t, mr.Start())
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Host() + ":" + mr.Port()})
	defer client.Close()
	store := &redisSessionStore{client: &server.RedisClient{Client: client}, logger: server.Logger}

	userID := int64(1)
	ses := session{
		Token:  "token",
		UserID: &userID,
		Expiry: time.Now().Add(time.Minute),
	}
	require.NoError(t, store.add(context.Background(), ses))

	readDone := make(chan struct{})
	continueWrite := make(chan struct{})
	errChan := make(chan error, 1)
	go func() {
		errChan <- store.update(context.Background(), ses.Token, func(s *session) error {
			close(readDone)
			<-continueWrite
			updatedUserID := int64(2)
			s.UserID = &updatedUserID
			return nil
		})
	}()

	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("transaction did not read the session")
	}

	externalUserID := int64(3)
	ses.UserID = &externalUserID
	sessionJSON, err := json.Marshal(ses)
	require.NoError(t, err)
	key := store.client.KeyPrefix + sessionLookupPrefix + ses.Token
	require.NoError(t, client.Set(context.Background(), key, sessionJSON, time.Minute).Err())

	close(continueWrite)
	select {
	case err := <-errChan:
		require.ErrorIs(t, err, errRedis)
	case <-time.After(time.Second):
		t.Fatal("transaction did not finish")
	}

	sessionJSON, err = client.Get(context.Background(), key).Bytes()
	require.NoError(t, err)
	var storedSession session
	require.NoError(t, json.Unmarshal(sessionJSON, &storedSession))
	require.NotNil(t, storedSession.UserID)
	require.Equal(t, externalUserID, *storedSession.UserID)
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
