package services

import (
	"context"

	"github.com/privacybydesign/irmago/eudi/trust"
)

// TrustService is the single home for trust-level evaluation: the wallet's one
// place where a party's identity evidence is turned into a rung on the trust
// ladder, for both protocols and both roles.
//
// It runs dark for now — the certificate channel is the only one wired up, so a
// party that authenticated with a Yivi-anchored certificate reaches high and
// everything else reaches low, and no verdict carries a listing. The
// recognized-list channel (the Yivi-published LoTE) plugs in here in a later
// slice and adds the medium and marked-high rungs; the constructor grows a
// checker parameter at that point.
//
// Evaluation is fail-soft by construction: nothing on this path returns an
// error, so a trust level can never fail a session.
type TrustService struct{}

// NewTrustService returns the wallet's trust evaluator.
func NewTrustService() *TrustService {
	return &TrustService{}
}

// Snapshot pins the state a single session evaluates against, so a list refresh
// landing halfway through cannot change that session's verdicts. Dark mode has
// no list state to pin yet, but sessions take their view here from the start so
// the pinning point is not a later retrofit.
//
// The context is the session's; the recognized-list channel will use it to
// bound the read of the pinned list state.
func (s *TrustService) Snapshot(_ context.Context) trust.View {
	return trust.CertificateView{}
}
