package openid4vp

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/require"
)

// parkSession drives a session up to the point where it is waiting for the user's
// answer — the state a dismissal has to be able to break out of — and returns the
// callback it is waiting on. An empty DCQL query keeps the plan build trivial;
// these tests are about the session lifecycle, not candidate matching. Sessions on
// the same client may overlap, like disclosures arriving while one is parked do.
func parkSession(t *testing.T, client *Client, verifier string) (*openid4vpSession, *spyHandler, chan error, PermissionHandler) {
	t.Helper()
	handler := newSpyHandler()
	session := client.newSession(handler)

	done := make(chan error, 1)
	go func() {
		done <- client.handleAuthorizationRequest(
			session,
			&AuthorizationRequest{},
			&clientmodels.TrustedParty{Name: verifier},
			"", // audience: nothing is disclosed on the paths these tests drive
		)
	}()

	return session, handler, done, handler.awaitRequest(t)
}

func startParkedSession(t *testing.T) (*Client, *openid4vpSession, *spyHandler, chan error, PermissionHandler) {
	t.Helper()
	client := newTestClient()
	session, handler, done, callback := parkSession(t, client, "Test verifier")
	return client, session, handler, done, callback
}

func awaitPerformReturn(t *testing.T, done chan error) {
	t.Helper()
	require.NoError(t, awaitOn(t, done, "the session goroutine to unwind"))
}

func liveSessions(client *Client) int {
	client.mu.Lock()
	defer client.mu.Unlock()
	return len(client.sessions)
}

// Regression: Dismiss only logged, so the session goroutine stayed parked in
// awaitPermission and the session stayed registered for the rest of the process.
func TestDismiss_UnwindsSessionAndDeregistersIt(t *testing.T) {
	client, session, handler, done, _ := startParkedSession(t)
	require.Equal(t, 1, liveSessions(client), "session should be registered while parked")

	session.Dismiss()
	awaitPerformReturn(t, done)

	require.Equal(t, 0, liveSessions(client), "an unwound session must be deregistered")
	require.EqualValues(t, 1, handler.cancels.Load(), "dismissal reported exactly once")
	require.EqualValues(t, 0, handler.successes.Load())
}

// Regression: the client kept a single currentSession pointer and handed itself out
// as every session's dismisser, so with two sessions in flight, dismissing the older
// one answered the newer one instead — the session the user did not touch reported
// Cancelled, and the one they did dismiss stayed parked in awaitPermission forever,
// unreachable even by a second dismissal.
func TestOverlappingSessions_DismissCancelsOnlyItsOwnSession(t *testing.T) {
	client := newTestClient()
	session1, handler1, done1, _ := parkSession(t, client, "verifier 1")
	session2, handler2, done2, _ := parkSession(t, client, "verifier 2")

	// The user dismisses session 1's screen.
	session1.Dismiss()
	awaitPerformReturn(t, done1)
	require.EqualValues(t, 1, handler1.cancels.Load(), "the dismissed session got the cancellation")
	require.EqualValues(t, 0, handler2.cancels.Load(), "the untouched session got nothing")

	// Session 2 is still parked, still registered, and still answerable.
	require.True(t, session2.awaiting.Load(), "the untouched session keeps awaiting its own answer")
	require.Equal(t, 1, liveSessions(client))

	session2.Dismiss()
	awaitPerformReturn(t, done2)
	require.EqualValues(t, 1, handler2.cancels.Load())
	require.Equal(t, 0, liveSessions(client))
}

// The dismisser NewSession hands out is live before the authorization request has
// been fetched and verified. A dismissal landing in that window used to be a silent
// no-op — nobody was parked yet — leaving the session to ask for permission on a
// screen the user had already closed. It is latched instead: the session unwinds as
// cancelled without ever asking the UI.
func TestDismiss_DuringNetworkWindow_CancelsWithoutAsking(t *testing.T) {
	client := newTestClient()
	handler := newSpyHandler()
	session := client.newSession(handler)

	// The dismissal arrives while the session would be fetching the request.
	session.Dismiss()

	done := make(chan error, 1)
	go func() {
		done <- client.handleAuthorizationRequest(
			session,
			&AuthorizationRequest{},
			&clientmodels.TrustedParty{Name: "Test verifier"},
			"", // audience: nothing is disclosed on the paths these tests drive
		)
	}()

	awaitPerformReturn(t, done)
	require.EqualValues(t, 1, handler.cancels.Load(), "an early dismissal still cancels the session")
	require.EqualValues(t, 0, handler.requests.Load(), "a dismissed session must not ask for permission")
}

// The bug as it showed up in the wallet: after the dismissal, every completed
// IRMA session anywhere in the app re-asked the dead session for permission,
// dispatching a fresh requestPermission state each time.
func TestRefreshPendingPermissionRequest_SilentAfterDismiss(t *testing.T) {
	client, session, handler, done, _ := startParkedSession(t)
	require.EqualValues(t, 1, handler.requests.Load())

	session.Dismiss()
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
	client, session, handler, done, _ := startParkedSession(t)
	require.EqualValues(t, 1, handler.requests.Load())

	client.RefreshPendingPermissionRequest()
	handler.awaitRequest(t)
	require.EqualValues(t, 2, handler.requests.Load(), "an awaiting session is re-asked")

	session.Dismiss()
	awaitPerformReturn(t, done)
}

// With two sessions awaiting, the single currentSession pointer meant only the
// newest one ever got its plan rebuilt for issuance-during-disclosure. The refresh
// now reaches every awaiting session.
func TestRefreshPendingPermissionRequest_ReAsksEveryAwaitingSession(t *testing.T) {
	client := newTestClient()
	session1, handler1, done1, _ := parkSession(t, client, "verifier 1")
	session2, handler2, done2, _ := parkSession(t, client, "verifier 2")

	client.RefreshPendingPermissionRequest()
	handler1.awaitRequest(t)
	handler2.awaitRequest(t)
	require.EqualValues(t, 2, handler1.requests.Load(), "the older awaiting session is re-asked too")
	require.EqualValues(t, 2, handler2.requests.Load())

	session1.Dismiss()
	session2.Dismiss()
	awaitPerformReturn(t, done1)
	awaitPerformReturn(t, done2)
}

// A refresh leaves the superseded permission screen's callback alive in the UI.
// The first answer to arrive wins whichever screen it came from, and the loser is
// dropped — if it were queued instead, it would be waiting in the channel as the
// answer to the session's next question.
func TestAnswer_FirstOneWins(t *testing.T) {
	client, _, handler, done, first := startParkedSession(t)

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
	client.register(session)

	client.RefreshPendingPermissionRequest()

	require.EqualValues(t, 0, handler.requests.Load(),
		"a session that is not awaiting an answer must not be re-asked")
	require.False(t, session.answer(nil),
		"an answer with nobody parked to receive it must not be queued")
}

func TestNoSessionInFlight_RefreshIsANoOp(t *testing.T) {
	client := &Client{}
	require.NotPanics(t, client.RefreshPendingPermissionRequest)
}

// Only one caller may report the dismissal, or the wallet gets a second terminal
// state event for a session it has already finished and evicted.
func TestDismiss_IsIdempotent(t *testing.T) {
	_, session, handler, done, _ := startParkedSession(t)

	session.Dismiss()
	session.Dismiss()
	awaitPerformReturn(t, done)
	session.Dismiss()

	require.EqualValues(t, 1, handler.cancels.Load())
}

// A dismissal after the user's own answer must not clip the session: the response
// POST is already the user's decision playing out. The latch only matters while
// nobody has answered yet.
func TestDismiss_AfterAnswer_DoesNotCancel(t *testing.T) {
	_, session, handler, done, callback := startParkedSession(t)

	callback(false, nil) // the user's own "no" wins
	session.Dismiss()    // the screen's dismissal backstop fires afterwards

	awaitPerformReturn(t, done)
	require.EqualValues(t, 1, handler.cancels.Load(), "one cancellation, from the user's own answer")

	// The latch must not have queued a second verdict.
	select {
	case response := <-session.answers:
		t.Fatalf("unexpected queued answer: %v", response)
	case <-time.After(50 * time.Millisecond):
	}
}
