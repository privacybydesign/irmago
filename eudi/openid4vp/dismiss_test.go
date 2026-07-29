package openid4vp

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/require"
)

// startParkedSession drives a session up to the point where it is waiting for the
// user's answer — the state a dismissal has to be able to break out of — and
// returns the callback it is waiting on. An empty DCQL query keeps the plan build
// trivial; these tests are about the session lifecycle, not candidate matching.
func startParkedSession(t *testing.T) (*Client, *spyHandler, chan error, PermissionHandler) {
	t.Helper()
	client := newTestClient()
	handler := newSpyHandler()

	done := make(chan error, 1)
	go func() {
		done <- client.handleAuthorizationRequest(
			&AuthorizationRequest{},
			&clientmodels.TrustedParty{Name: "Test verifier"},
			handler,
		)
	}()

	return client, handler, done, handler.awaitRequest(t)
}

func awaitPerformReturn(t *testing.T, done chan error) {
	t.Helper()
	require.NoError(t, awaitOn(t, done, "the session goroutine to unwind"))
}

// Regression: Dismiss only logged, so the session goroutine stayed parked in
// awaitPermission and currentSession stayed set for the rest of the process.
func TestDismiss_UnwindsSessionAndClearsCurrentSession(t *testing.T) {
	client, handler, done, _ := startParkedSession(t)
	require.NotNil(t, client.currentSession.Load(), "session should be current while parked")

	client.Dismiss()
	awaitPerformReturn(t, done)

	require.Nil(t, client.currentSession.Load(), "Dismiss must clear the current session")
	require.EqualValues(t, 1, handler.cancels.Load(), "dismissal reported exactly once")
	require.EqualValues(t, 0, handler.successes.Load())
}

// The bug as it showed up in the wallet: after the dismissal, every completed
// IRMA session anywhere in the app re-asked the dead session for permission,
// dispatching a fresh requestPermission state each time.
func TestRefreshPendingPermissionRequest_SilentAfterDismiss(t *testing.T) {
	client, handler, done, _ := startParkedSession(t)
	require.EqualValues(t, 1, handler.requests.Load())

	client.Dismiss()
	awaitPerformReturn(t, done)

	for range 5 {
		client.RefreshPendingPermissionRequest()
	}

	require.EqualValues(t, 1, handler.requests.Load(),
		"a dismissed session must not be asked for permission again")
}

// The reason the refresh exists at all: issuance-during-disclosure obtains a
// missing credential, and the plan has to be rebuilt and re-shown. That must keep
// working while the user has not answered yet.
func TestRefreshPendingPermissionRequest_ReAsksWhileAwaiting(t *testing.T) {
	client, handler, done, _ := startParkedSession(t)
	require.EqualValues(t, 1, handler.requests.Load())

	client.RefreshPendingPermissionRequest()
	handler.awaitRequest(t)
	require.EqualValues(t, 2, handler.requests.Load(), "an awaiting session is re-asked")

	client.Dismiss()
	awaitPerformReturn(t, done)
}

// A refresh leaves the superseded permission screen's callback alive in the UI.
// The first answer to arrive wins whichever screen it came from, and the loser is
// dropped — if it were queued instead, it would be waiting in the channel as the
// answer to the session's next question.
func TestAnswer_FirstOneWins(t *testing.T) {
	client, handler, done, first := startParkedSession(t)

	client.RefreshPendingPermissionRequest()
	second := handler.awaitRequest(t)

	second(false, nil) // user dismisses the plan they can see
	first(true, nil)   // stale callback from the screen the refresh replaced

	awaitPerformReturn(t, done)
	require.EqualValues(t, 1, handler.cancels.Load(), "the answer the user gave is the one that counts")
	require.EqualValues(t, 0, handler.successes.Load())
}

// A session that has been answered but has not finished unwinding yet — it is
// POSTing the authorization response — must not be re-asked either. Reproduced
// directly, since the phase is a narrow window in a live session.
func TestRefreshPendingPermissionRequest_SilentWhenNotAwaiting(t *testing.T) {
	handler := newSpyHandler()
	session := &openid4vpSession{
		request:     &AuthorizationRequest{},
		requestor:   &clientmodels.TrustedParty{Name: "Test verifier"},
		handler:     handler,
		dcqlHandler: dcql.NewDcqlHandler(nil),
		answers:     make(chan *permissionResponse, 1),
	}

	client := newTestClient()
	client.currentSession.Store(session)

	client.RefreshPendingPermissionRequest()

	require.EqualValues(t, 0, handler.requests.Load(),
		"a session that is not awaiting an answer must not be re-asked")
	require.False(t, session.answer(nil),
		"an answer with nobody parked to receive it must not be queued")
}

func TestNoSessionInFlight_DismissAndRefreshAreNoOps(t *testing.T) {
	client := &Client{}
	require.NotPanics(t, client.Dismiss)
	require.NotPanics(t, client.RefreshPendingPermissionRequest)
}

// Only one caller may report the dismissal, or the wallet gets a second terminal
// state event for a session it has already finished and evicted.
func TestDismiss_IsIdempotent(t *testing.T) {
	client, handler, done, _ := startParkedSession(t)

	client.Dismiss()
	client.Dismiss()
	awaitPerformReturn(t, done)
	client.Dismiss()

	require.EqualValues(t, 1, handler.cancels.Load())
}
