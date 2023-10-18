package irmaserver

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
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

	var handlerInvoked bool
	_, token, _, err := s.StartSession(request, func(result *server.SessionResult) {
		handlerInvoked = true
	})
	require.NoError(t, err)

	require.NoError(t, s.CancelSession(token))
	time.Sleep(100 * time.Millisecond) // give session handler time to run
	require.True(t, handlerInvoked)
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
	})
	require.NoError(t, err)

	time.Sleep(2 * time.Second)
	s.sessions.(*memorySessionStore).deleteExpired()
	time.Sleep(100 * time.Millisecond) // give session handler time to run

	require.True(t, handlerInvoked)
}

func TestMemoryStoreNoDeadlock(t *testing.T) {
	s, err := New(sessionsConf(t))
	require.NoError(t, err)
	defer s.Stop()

	req, err := server.ParseSessionRequest(`{"request":{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"MtILupG0g0J23GNR1YtupQ==","devMode":true,"disclose":[[[{"type":"test.test.email.email","value":"example@example.com"}]]]}}`)
	require.NoError(t, err)
	session, err := s.newSession(context.Background(), irma.ActionDisclosing, req, nil, "")
	require.NoError(t, err)

	memSessions, ok := s.sessions.(*memorySessionStore)
	require.True(t, ok)
	memSession := memSessions.requestor[session.RequestorToken]

	memSession.Lock()
	deletingCompleted := false
	addingCompleted := false
	// Make sure the deleting continues on completion such that the test itself will not hang.
	defer func() {
		memSession.Unlock()
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
		_, _ = s.newSession(context.Background(), irma.ActionDisclosing, req, nil, "")
		addingCompleted = true
	}()

	// Check whether the IRMA server doesn't hang
	time.Sleep(100 * time.Millisecond)
	require.True(t, addingCompleted)
	require.False(t, deletingCompleted)
}
