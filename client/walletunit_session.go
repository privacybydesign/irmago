package client

import (
	"context"
	"errors"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/walletunit"
	"github.com/privacybydesign/irmago/walletprovider"
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

// ErrNoWalletProvider is returned by operations of a wallet provider the
// wallet does not have.
var ErrNoWalletProvider = errors.New("the wallet has no wallet provider")

// WalletProviderTransactions returns the wallet provider transaction log,
// newest first: at most max entries, and only those before the given time
// unless it is zero. Reading it takes the PIN; a wrong or blocked PIN is
// returned as *walletprovider.PinIncorrectError or
// *walletprovider.PinBlockedError.
func (client *Client) WalletProviderTransactions(pin string, before time.Time, max int) ([]clientmodels.WalletProviderTransaction, error) {
	if client.walletProvider == nil {
		return nil, ErrNoWalletProvider
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	u, err := client.walletProvider.Unlock(ctx, pin, walletprovider.Scope{Purpose: walletprovider.PurposeTransactionLog})
	if err != nil {
		return nil, err
	}
	defer u.Close()
	txs, err := u.Transactions(ctx, before, max)
	if err != nil {
		return nil, err
	}
	out := make([]clientmodels.WalletProviderTransaction, len(txs))
	for i, tx := range txs {
		out[i] = clientmodels.WalletProviderTransaction{
			ID:             tx.ID,
			Time:           tx.Time,
			Operation:      string(tx.Operation),
			Purpose:        string(tx.Purpose),
			Counterparty:   tx.Counterparty,
			CredentialType: tx.CredentialType,
			Succeeded:      tx.Succeeded,
		}
	}
	return out, nil
}
