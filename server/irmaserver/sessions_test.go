package irmaserver

import (
	"testing"
	"time"

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

func TestSessionHandlerInvokedOnTimeout(t *testing.T) {
	s, err := New(&server.Configuration{Logger: logger})
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
	s.sessions.deleteExpired()
	time.Sleep(100 * time.Millisecond) // give session handler time to run

	require.True(t, handlerInvoked)
}

func TestMemoryStoreNoDeadlock(t *testing.T) {
	s, err := New(&server.Configuration{Logger: logger})
	require.NoError(t, err)
	defer s.Stop()

	req, err := server.ParseSessionRequest(`{"request":{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"MtILupG0g0J23GNR1YtupQ==","devMode":true,"disclose":[[[{"type":"test.test.email.email","value":"example@example.com"}]]]}}`)
	require.NoError(t, err)
	session := s.newSession(irma.ActionDisclosing, req)

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
		s.sessions.deleteExpired()
		deletingCompleted = true
	}()

	// Make sure the goroutine above is running
	time.Sleep(100 * time.Millisecond)

	// Make a new session; this involves adding it to the memory session store.
	go func() {
		_ = s.newSession(irma.ActionDisclosing, req)
		addingCompleted = true
	}()

	// Check whether the IRMA server doesn't hang
	time.Sleep(100 * time.Millisecond)
	require.True(t, addingCompleted)
	require.False(t, deletingCompleted)
}
