package services

import (
	"context"

	"github.com/privacybydesign/irmago/eudi/lote"
	"github.com/privacybydesign/irmago/eudi/trust"
)

// TrustService is the single home for trust-level evaluation: the wallet's one
// place where a party's identity evidence is turned into a rung on the trust
// ladder, for both protocols and both roles.
//
// Two channels feed it. The certificate channel puts a party whose chain
// validated against the Yivi anchors on high. The recognized-list channel puts
// a party granted on a list the wallet recognizes on medium. They are
// independent, and the rung is the stronger of the two.
//
// Evaluation is fail-soft by construction: nothing on this path returns an
// error, so a trust level can never fail a session.
type TrustService struct {
	// checker is the recognized-list channel. Nil leaves the certificate
	// channel on its own.
	checker *lote.Checker
}

// NewTrustService returns the wallet's trust evaluator, reading the
// recognized-list channel from checker. A nil checker runs the certificate
// channel alone, which is what a wallet that recognizes no list does.
func NewTrustService(checker *lote.Checker) *TrustService {
	return &TrustService{checker: checker}
}

// Snapshot pins the state a single session evaluates against, so a list refresh
// landing halfway through cannot change that session's verdicts.
//
// The context is the session's: resolving the recognized lists can mean
// fetching one, and that fetch is bounded by it.
func (s *TrustService) Snapshot(ctx context.Context) trust.View {
	if s.checker == nil {
		return trust.NewView(nil)
	}
	return trust.NewView(s.checker.Snapshot(ctx))
}
