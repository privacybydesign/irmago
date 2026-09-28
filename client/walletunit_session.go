package client

import (
	"context"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/walletunit"
)

// context returns the context an OpenID4VC session runs in. With a wallet
// provider it carries a wallet unit session that asks for the PIN on this
// session's screen, which the key services behind the protocols unlock
// through; the protocols themselves never see it. The wallet unit session is
// closed when the session finishes.
func (s *session) context() context.Context {
	ctx := context.Background()
	if s.client.walletProvider == nil {
		return ctx
	}
	s.walletUnit = walletunit.NewSession(s.client.walletProvider, &sessionPinPrompter{session: s})
	return walletunit.WithSession(ctx, s.walletUnit)
}

// sessionPinPrompter asks for the wallet unit's PIN with the same request-PIN
// session state an IRMA session shows for the keyshare server: the app shows
// its one PIN screen and answers with UI_EnteredPin.
//
// When the user declines, or the PIN is blocked, the prompter ends the session
// towards the app itself; the failure the protocol then reports is not shown
// (see session.endedByWalletUnit).
type sessionPinPrompter struct {
	session *session
}

func (p *sessionPinPrompter) RequestPin(remainingAttempts *int) (string, bool) {
	s := p.session
	answers := make(chan clientmodels.PinInteractionPayload, 1)
	answer := func(proceed bool, pin string) {
		select {
		case answers <- clientmodels.PinInteractionPayload{Proceed: proceed, Pin: pin}:
		default:
		}
	}

	s.State.Status = clientmodels.Status_RequestPin
	s.State.RemainingPinAttempts = remainingAttempts
	s.State.PinBlockedTimeSeconds = nil
	s.pinHandler = answer
	s.cancelPinRequest = func() { answer(false, "") }
	s.dispatchState()

	a := <-answers
	s.cancelPinRequest = nil
	if !a.Proceed {
		s.endedByWalletUnit = true
		s.State.Status = clientmodels.Status_Dismissed
		s.finish()
		return "", false
	}
	return a.Pin, true
}

func (p *sessionPinPrompter) PinBlocked(duration time.Duration) {
	s := p.session
	seconds := int(duration.Round(time.Second) / time.Second)
	s.endedByWalletUnit = true
	s.State.Status = clientmodels.Status_RequestPin
	s.State.PinBlockedTimeSeconds = &seconds
	s.pinHandler = func(bool, string) {}
	s.dispatchState()
}
