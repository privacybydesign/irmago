package irmaserver

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var logger = logrus.New()

func init() {
	irma.SetLogger(logger)
	logger.Level = logrus.FatalLevel
}

func sessionsConf(t *testing.T) *server.Configuration {
	return &server.Configuration{
		Logger:      logger,
		SchemesPath: filepath.Join(test.FindTestdataFolder(t), "irma_configuration"),
	}
}

func TestSessionHandlerInvokedOnCancel(t *testing.T) {
	s, err := New(sessionsConf(t))
	require.NoError(t, err)
	defer s.Stop()

	request := irma.NewDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"))

	handlerDone := make(chan struct{})
	_, token, _, err := s.StartSession(request, func(result *server.SessionResult) {
		close(handlerDone)
	}, "")
	require.NoError(t, err)

	// Give the handler goroutine time to subscribe to status updates
	// before cancelling, so it doesn't miss the status change.
	time.Sleep(100 * time.Millisecond)

	require.NoError(t, s.CancelSession(token))

	select {
	case <-handlerDone:
		// success
	case <-time.After(5 * time.Second):
		t.Fatal("session handler was not invoked within timeout")
	}
}

func TestSessionHandlerInvokedOnTimeout(t *testing.T) {
	s, err := New(sessionsConf(t))
	require.NoError(t, err)
	defer s.Stop()

	request := &irma.ServiceProviderRequest{
		RequestorBaseRequest: irma.RequestorBaseRequest{
			ClientTimeout: 1,
		},
		Request: irma.NewDisclosureRequest(irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")),
	}

	var handlerInvoked bool
	_, _, _, err = s.StartSession(request, func(result *server.SessionResult) {
		handlerInvoked = true
	}, "")
	require.NoError(t, err)

	time.Sleep(2 * time.Second)
	s.sessions.(*memorySessionStore).deleteExpired()
	time.Sleep(100 * time.Millisecond) // give session handler time to run

	require.True(t, handlerInvoked)
}

// TestMemoryStoreExpiryDoesNotPanic is a regression test for the
// "panic: send on closed channel" that occurred when an expired session was
// deleted while a status update for that session was still being delivered to
// its subscribers (see issue #406). It concurrently subscribes to session
// updates, fires status updates (which notify subscribers) and deletes the
// expired sessions (which closes the subscription channels). With the previous
// implementation, the unsynchronized fire-and-forget notification goroutine
// could send on a channel that deleteExpired had already closed, panicking and
// crashing the server. Run with -race to also catch the data race on the
// updateChannels map.
func TestMemoryStoreExpiryDoesNotPanic(t *testing.T) {
	s, err := New(sessionsConf(t))
	require.NoError(t, err)
	defer s.Stop()

	store := s.sessions.(*memorySessionStore)

	const rounds = 25
	const sessionsPerRound = 20

	for range rounds {
		ctx, cancel := context.WithCancel(context.Background())

		// Setup phase (sequential): create expired sessions and subscribe to
		// their updates without reading, emulating subscribers that have gone
		// away while an update is in flight. Each session gets a freshly parsed
		// request so the concurrent phase below does not race on shared request
		// state during (de)serialization.
		tokens := make([]irma.RequestorToken, 0, sessionsPerRound)
		for range sessionsPerRound {
			req, err := server.ParseSessionRequest(`{"request":{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"MtILupG0g0J23GNR1YtupQ==","devMode":true,"disclose":[[[{"type":"test.test.email.email","value":"example@example.com"}]]]}}`)
			require.NoError(t, err)
			session, err := s.newSession(context.Background(), irma.ActionDisclosing, req, nil, "", "")
			require.NoError(t, err)
			token := session.RequestorToken

			// Mark the session as expired so deleteExpired will remove it and
			// close its subscription channels.
			memSes := store.requestor[token]
			memSes.Lock()
			memSes.Status = irma.ServerStatusDone
			memSes.LastActive = time.Now().Add(-time.Hour)
			memSes.Unlock()

			_, err = store.subscribeUpdates(ctx, token)
			require.NoError(t, err)
			tokens = append(tokens, token)
		}

		// Race phase: fire a status update for every session (which notifies its
		// subscribers) while concurrently deleting the expired sessions (which
		// closes the subscription channels).
		var wg sync.WaitGroup
		for _, token := range tokens {
			wg.Add(1)
			go func(token irma.RequestorToken) {
				defer wg.Done()
				_ = store.transaction(context.Background(), token, func(ses *sessionData) (bool, error) {
					ses.setStatus(irma.ServerStatusCancelled, store.conf)
					return true, nil
				})
			}(token)
		}
		wg.Go(func() {
			store.deleteExpired()
		})

		wg.Wait()
		// Delete anything that survived the race above.
		store.deleteExpired()
		cancel()
	}

	// Give the per-subscription cleanup goroutines time to run, then verify that
	// all subscription channels have been cleaned up.
	time.Sleep(100 * time.Millisecond)
	store.RLock()
	require.Empty(t, store.updateChannels)
	store.RUnlock()
}

func TestMemoryStoreNoDeadlock(t *testing.T) {
	s, err := New(sessionsConf(t))
	require.NoError(t, err)
	defer s.Stop()

	req, err := server.ParseSessionRequest(`{"request":{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"MtILupG0g0J23GNR1YtupQ==","devMode":true,"disclose":[[[{"type":"test.test.email.email","value":"example@example.com"}]]]}}`)
	require.NoError(t, err)
	session, err := s.newSession(context.Background(), irma.ActionDisclosing, req, nil, "", "")
	require.NoError(t, err)

	memSessions, ok := s.sessions.(*memorySessionStore)
	require.True(t, ok)
	memSession := memSessions.requestor[session.RequestorToken]

	memSession.Lock()
	var deletingCompleted, addingCompleted atomic.Bool
	// Make sure the deleting continues on completion such that the test itself will not hang.
	defer func() {
		memSession.Unlock()
		time.Sleep(100 * time.Millisecond)
		require.True(t, deletingCompleted.Load())
	}()

	go func() {
		s.sessions.(*memorySessionStore).deleteExpired()
		deletingCompleted.Store(true)
	}()

	// Make sure the goroutine above is running
	time.Sleep(100 * time.Millisecond)

	// Make a new session; this involves adding it to the memory session store.
	go func() {
		_, _ = s.newSession(context.Background(), irma.ActionDisclosing, req, nil, "", "")
		addingCompleted.Store(true)
	}()

	// Check whether the IRMA server doesn't hang
	time.Sleep(100 * time.Millisecond)
	require.True(t, addingCompleted.Load())
	require.False(t, deletingCompleted.Load())
}
