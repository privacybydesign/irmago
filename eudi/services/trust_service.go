package services

import (
	"context"

	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
)

// TrustService is the single home for trust-level evaluation: the wallet's one
// place where a party's identity evidence is turned into a rung on the trust
// ladder, for both protocols and both roles.
//
// Two channels feed it, independently, and a party lands on whichever rung is
// higher. The certificate channel puts a party that authenticated with a
// Yivi-anchored certificate at high. The recognized-list channel puts a party
// granted on a list the wallet recognizes at medium. Neither can pull the other
// down: a scheme-certified party stays high with every list unreachable.
//
// Evaluation is fail-soft by construction: nothing on this path returns an
// error, so a trust level can never fail a session.
type TrustService struct {
	checker *lote.Checker
}

// NewTrustService returns the wallet's trust evaluator. A nil checker runs it
// dark — certificate channel only, no verdict ever carrying a listing — which
// is what a wallet with no recognized lists configured does.
func NewTrustService(checker *lote.Checker) *TrustService {
	return &TrustService{checker: checker}
}

// Snapshot pins the state a single session evaluates against, so a list refresh
// landing halfway through cannot change that session's verdicts.
//
// The context is the session's. Nothing here reads it: pinning is a read of
// state the checker already holds, never a fetch, so there is nothing for a
// cancellation to cut short and a cancelled context still yields a usable view.
func (s *TrustService) Snapshot(_ context.Context) trust.View {
	if s.checker == nil {
		return trust.NewView(nil)
	}
	return trust.NewView(s.checker.Snapshot())
}

// RefreshLists downloads the recognized lists and adopts the ones that hold up.
// It is the only path that touches the network, and it is deliberately not on
// the evaluation path: a session reads whatever the wallet already holds.
//
// The error reports which sources failed, for the caller's log. A failed
// refresh is not an error condition for the wallet — the lists it already holds
// stay in force, and a party it can no longer confirm caps at low.
func (s *TrustService) RefreshLists(ctx context.Context) error {
	if s.checker == nil {
		return nil
	}
	return s.checker.Refresh(ctx)
}
