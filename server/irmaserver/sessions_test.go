package irmaserver

import (
	"context"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestMemoryStoreNoDeadlock(t *testing.T) {
	logger := logrus.New()
	logger.Level = logrus.FatalLevel
	s, err := New(&server.Configuration{Logger: logger})
	require.NoError(t, err)
	defer s.Stop()

	req, err := server.ParseSessionRequest(`{"request":{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"MtILupG0g0J23GNR1YtupQ==","devMode":true,"disclose":[[[{"type":"test.test.email.email","value":"example@example.com"}]]]}}`)
	require.NoError(t, err)
	session, err := s.newSession(irma.ActionDisclosing, req, context.Background())
	require.NoError(t, err)

	session.Lock()
	deletingCompleted := false
	addingCompleted := false
	// Make sure the deleting continues on completion such that the test itself will not hang.
	defer func() {
		session.Unlock()
		time.Sleep(100 * time.Millisecond)
		require.True(t, deletingCompleted)
	}()

	go func() {
		s.sessions.(*memorySessionStore).deleteExpired()
		deletingCompleted = true
	}()

	// Make sure the goroutine above is running
	time.Sleep(100 * time.Millisecond)

	// Make a new session; this involves adding it to the memory session store.
	go func() {
		_, _ = s.newSession(irma.ActionDisclosing, req, context.Background())
		addingCompleted = true
	}()

	// Check whether the IRMA server doesn't hang
	time.Sleep(100 * time.Millisecond)
	require.True(t, addingCompleted)
	require.False(t, deletingCompleted)
}
