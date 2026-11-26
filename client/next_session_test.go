package client

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A chained IRMA session first succeeds with its follow-up pending; the app
// starts the follow-up or drops it.
func TestNextSessionPending(t *testing.T) {
	setup := func(t *testing.T) (*session, *dispatchSpy, *int) {
		s, spy := newFinishTestSession()
		started := 0
		(&irmaSessionAdapter{session: s}).SuccessWithNextSession("{}", irmaclient.NewPendingSession(func() { started++ }))
		require.Equal(t, clientmodels.Status_Success, s.State.Status)
		require.True(t, s.State.NextSessionPending)
		require.Equal(t, []clientmodels.SessionStatus{clientmodels.Status_Success}, spy.statuses)
		_, open := s.client.sessionManager.GetSession(1)
		require.True(t, open, "the session stays open for the follow-up")
		return s, spy, &started
	}
	interact := func(s *session, kind clientmodels.UserInteractionType) error {
		return s.client.HandleUserInteraction(clientmodels.SessionUserInteraction{SessionId: 1, Type: kind})
	}

	t.Run("continue starts the follow-up once", func(t *testing.T) {
		s, _, started := setup(t)
		require.NoError(t, interact(s, clientmodels.UI_ContinueNextSession))
		assert.Equal(t, 1, *started)
		assert.False(t, s.State.NextSessionPending)
		require.Error(t, interact(s, clientmodels.UI_ContinueNextSession), "nothing is waiting any more")
		assert.Equal(t, 1, *started)
	})

	t.Run("dismiss drops the follow-up and the session ends as it was: succeeded", func(t *testing.T) {
		s, spy, started := setup(t)
		s.dismisser = dismisserFunc(func() { t.Fatal("the finished session itself is not dismissed") })
		require.NoError(t, interact(s, clientmodels.UI_DismissSession))
		assert.Zero(t, *started)
		assert.False(t, s.State.NextSessionPending)
		assert.Equal(t, []clientmodels.SessionStatus{clientmodels.Status_Success, clientmodels.Status_Success}, spy.statuses,
			"a last success without anything pending")
		_, open := s.client.sessionManager.GetSession(1)
		assert.False(t, open)
	})
}
