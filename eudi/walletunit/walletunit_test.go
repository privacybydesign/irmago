package walletunit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/walletprovider"
	"github.com/privacybydesign/irmago/walletprovider/fake"
	"github.com/privacybydesign/irmago/walletprovider/providertest"
	"github.com/stretchr/testify/require"
)

const pin = "12345"

func newFake(t *testing.T) walletprovider.WalletProvider {
	t.Helper()
	p, err := fake.New(fake.Options{})(providertest.NewHost())
	require.NoError(t, err)
	return p
}

// pins answers successive PIN prompts from a list, recording the remaining
// attempts each prompt was shown with.
type pins struct {
	answers []string
	shown   []*int
	blocked []time.Duration
}

func (p *pins) RequestPin(remaining *int) (string, bool) {
	p.shown = append(p.shown, remaining)
	if len(p.answers) == 0 {
		return "", false
	}
	next := p.answers[0]
	p.answers = p.answers[1:]
	return next, true
}

func (p *pins) PinBlocked(d time.Duration) {
	p.blocked = append(p.blocked, d)
}

var scope = walletprovider.Scope{Purpose: walletprovider.PurposeDisclosureKB}

func TestUnlockRetriesAfterWrongPin(t *testing.T) {
	p := newFake(t)
	require.NoError(t, p.Activate(context.Background(), pin))

	answers := &pins{answers: []string{"00000", pin}}
	s := NewSession(p, answers)
	defer s.Close()
	_, err := s.Unlocked(context.Background(), scope, false)
	require.NoError(t, err)

	require.Len(t, answers.shown, 2)
	require.Nil(t, answers.shown[0])
	require.Equal(t, 2, *answers.shown[1])
}

func TestUnlockAsksOncePerPurpose(t *testing.T) {
	p := newFake(t)
	require.NoError(t, p.Activate(context.Background(), pin))

	answers := &pins{answers: []string{pin, pin}}
	s := NewSession(p, answers)
	defer s.Close()
	for range 3 {
		_, err := s.Unlocked(context.Background(), scope, false)
		require.NoError(t, err)
	}
	require.Len(t, answers.shown, 1)
}

func TestCloseEndsTheUnlock(t *testing.T) {
	p := newFake(t)
	require.NoError(t, p.Activate(context.Background(), pin))

	s := NewSession(p, &pins{answers: []string{pin}})
	u, err := s.Unlocked(context.Background(), walletprovider.Scope{Purpose: walletprovider.PurposeIssuancePoP}, false)
	require.NoError(t, err)
	s.Close()
	_, err = u.GenerateKeys(context.Background(), 1)
	require.ErrorIs(t, err, walletprovider.ErrUnlockExpired)
}

func TestUnlockReportsCancellation(t *testing.T) {
	p := newFake(t)
	require.NoError(t, p.Activate(context.Background(), pin))

	_, err := NewSession(p, &pins{}).Unlocked(context.Background(), scope, false)
	require.ErrorIs(t, err, ErrCancelled)
}

func TestUnlockReportsBlocked(t *testing.T) {
	p := newFake(t)
	require.NoError(t, p.Activate(context.Background(), pin))

	answers := &pins{answers: []string{"00000", "00000", "00000"}}
	_, err := NewSession(p, answers).Unlocked(context.Background(), scope, false)
	_, blocked := errors.AsType[*walletprovider.PinBlockedError](err)
	require.True(t, blocked, "got %v", err)
	require.Len(t, answers.blocked, 1, "the user is told")
}

func TestUnlockWithoutActivationFails(t *testing.T) {
	_, err := NewSession(newFake(t), &pins{answers: []string{pin}}).Unlocked(context.Background(), scope, false)
	require.ErrorIs(t, err, walletprovider.ErrNotActivated)
}

func TestUnlockActivatesWithEnteredPin(t *testing.T) {
	p := newFake(t)

	answers := &pins{answers: []string{pin}}
	s := NewSession(p, answers)
	_, err := s.Unlocked(context.Background(), scope, true)
	require.NoError(t, err)
	s.Close()
	require.Len(t, answers.shown, 1)

	state, err := p.State(context.Background())
	require.NoError(t, err)
	require.Equal(t, walletprovider.StateActive, state)

	// Activated with the PIN that was entered.
	u, err := p.Unlock(context.Background(), pin, scope)
	require.NoError(t, err)
	u.Close()
}

func TestSessionTravelsInContext(t *testing.T) {
	require.Nil(t, SessionFrom(context.Background()))
	s := NewSession(newFake(t), &pins{})
	require.Same(t, s, SessionFrom(WithSession(context.Background(), s)))
}

// closingPins closes the session from inside the prompt, as dismissing the
// session from its PIN screen does, and then enters the right PIN.
type closingPins struct {
	session *Session
}

func (p *closingPins) RequestPin(*int) (string, bool) {
	p.session.Close()
	return pin, true
}

func (p *closingPins) PinBlocked(time.Duration) {}

func TestCloseDuringThePromptEndsTheUnlock(t *testing.T) {
	p := newFake(t)
	require.NoError(t, p.Activate(context.Background(), pin))

	prompter := &closingPins{}
	s := NewSession(p, prompter)
	prompter.session = s

	_, err := s.Unlocked(context.Background(), scope, false)
	require.ErrorIs(t, err, ErrCancelled)
	_, err = s.Unlocked(context.Background(), scope, false)
	require.ErrorIs(t, err, ErrCancelled, "a closed session unlocks nothing")
}
