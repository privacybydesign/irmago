package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// dispatchSpy records the status of every state dispatched to the UI.
type dispatchSpy struct {
	statuses []clientmodels.SessionStatus
}

func (s *dispatchSpy) UpdateSession(state clientmodels.SessionState) {
	s.statuses = append(s.statuses, state.Status)
}

// newFinishTestSession wires up the least a session needs to finish: a manager to
// be evicted from and a handler to dispatch to.
func newFinishTestSession() (*session, *dispatchSpy) {
	spy := &dispatchSpy{}
	client := &Client{sessionManager: sessionManager{
		Sessions:       map[int]*session{},
		SessionHandler: spy,
	}}
	client.sessionManager.Client = client
	return client.sessionManager.NewSession(1), spy
}

// A protocol's own Cancelled after HandleUserInteraction's dismissal backstop
// reports the state the UI already has; the UI should see one Dismissed.
func TestFinish_DropsRepeatOfSameState(t *testing.T) {
	session, spy := newFinishTestSession()

	session.State.Status = clientmodels.Status_Dismissed
	session.finish()
	session.State.Status = clientmodels.Status_Dismissed
	session.finish()

	require.Equal(t, []clientmodels.SessionStatus{clientmodels.Status_Dismissed}, spy.statuses)
	_, registered := session.client.sessionManager.GetSession(1)
	require.False(t, registered, "finish must evict the session")
}

// The backstop is a guess about what the protocol will do. OpenID4VCI's Dismiss
// only logs, so issuance runs on past the guess and stores the credential — the
// user has to be told that, not left on the dismissal.
func TestFinish_DispatchesLaterDifferentState(t *testing.T) {
	session, spy := newFinishTestSession()

	session.State.Status = clientmodels.Status_Dismissed
	session.finish()
	session.State.Status = clientmodels.Status_Success
	session.finish()

	require.Equal(t, []clientmodels.SessionStatus{
		clientmodels.Status_Dismissed,
		clientmodels.Status_Success,
	}, spy.statuses)
}
