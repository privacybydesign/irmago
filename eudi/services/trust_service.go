package services

import (
	"context"
	"crypto/x509"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
)

// TrustService is the single home for trust-level evaluation: the wallet's one
// place where a party's identity evidence is turned into a rung on the trust
// ladder, for both protocols and both roles.
//
// Two channels feed it, independently, and a party lands on whichever rung is
// higher. The certificate channel confers the level of the anchor a party's
// chain validates to — high under the Yivi roots, medium under an anchored
// third-party CA, nothing under a root the wallet does not anchor. The
// recognized-list channel confers the level of the list that grants the party
// — high on Yivi's own LoTE. Neither can pull the other down: a
// Yivi-certified party stays high with every list unreachable.
//
// Evaluation is fail-soft by construction: nothing on this path returns an
// error, so a trust level can never fail a session.
type TrustService struct {
	checker       *lote.Checker
	issuerCerts   trust.CertificateClassifier
	verifierCerts trust.CertificateClassifier
}

// NewTrustService returns the wallet's trust evaluator. The classifiers are
// the per-role certificate channels — the wallet's issuer and verifier trust
// models. A nil checker runs the list channel dark (no verdict ever carrying
// a listing), which is what a wallet with no recognized lists configured
// does; a nil classifier runs that role's certificate channel dark, which
// only a wallet without trust models (in practice: a test) does.
func NewTrustService(checker *lote.Checker, issuerCerts, verifierCerts trust.CertificateClassifier) *TrustService {
	return &TrustService{checker: checker, issuerCerts: issuerCerts, verifierCerts: verifierCerts}
}

// Snapshot pins the state a single session evaluates against, so a list refresh
// landing halfway through cannot change that session's verdicts.
//
// The context is the session's. Nothing here reads it: pinning is a read of
// state the checker already holds, never a fetch, so there is nothing for a
// cancellation to cut short and a cancelled context still yields a usable view.
func (s *TrustService) Snapshot(_ context.Context) trust.View {
	var lists trust.ListSnapshot
	if s.checker != nil {
		lists = s.checker.Snapshot()
	}
	return trust.NewView(lists, s.issuerCerts, s.verifierCerts)
}

// BatchIssuerEvidence is what the wallet recorded at issuance about the issuer
// of a stored credential batch, in the terms the trust ladder ranks parties by.
//
// It is read on every listing rather than turned into a stored level, so the
// rung a credential shows follows the recognized lists as they change: an issuer
// delisted since issuance demotes on the next read, a newly listed one promotes.
// A batch stored before the certificate was kept carries none, and ranks through
// the list channel alone.
func BatchIssuerEvidence(batch *models.CredentialBatch) trust.Evidence {
	evidence := trust.Evidence{Identifiers: []string{batch.CredentialIssuer}}
	if len(batch.IssuerCertificate) == 0 {
		return evidence
	}
	certificate, err := x509.ParseCertificate(batch.IssuerCertificate)
	if err != nil {
		// Unparseable evidence is absent evidence: the party keeps whatever the
		// list channel says about it rather than the read failing.
		eudi.Logger.Warnf("trust: stored issuer certificate for batch %q does not parse: %v", batch.Hash, err)
		return evidence
	}
	evidence.Certificate = certificate
	return evidence
}

// RefreshLists downloads the recognized lists and adopts the ones that hold up.
// It is the only path that touches the network, and it is deliberately not on
// the evaluation path: a session reads whatever the wallet already holds.
//
// changed counts the lists that came back saying something different about the
// parties on them, which is what tells the caller whether anything the app has
// already rendered went stale. A re-issue with the same entries counts zero.
//
// The error reports which sources failed, for the caller's log. A failed
// refresh is not an error condition for the wallet — the lists it already holds
// stay in force, and a party it can no longer confirm caps at low.
func (s *TrustService) RefreshLists(ctx context.Context) (int, error) {
	if s.checker == nil {
		return 0, nil
	}
	return s.checker.Refresh(ctx)
}
