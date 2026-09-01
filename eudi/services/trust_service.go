package services

import (
	"context"
	"crypto/x509"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/privacybydesign/irmago/eudi/trust/lote"
)

// TrustService is the single home for trust-level evaluation, for both protocols
// and both roles.
//
// Two channels feed it independently and a party lands on whichever rung is
// higher: the certificate channel confers the level of the anchor its chain
// validates to, the recognized-list channel the level of the list that grants it.
// Neither can pull the other down.
//
// Evaluation is fail-soft by construction: nothing on this path returns an error,
// so a trust level can never fail a session.
type TrustService struct {
	checker       *lote.Checker
	issuerCerts   trust.CertificateClassifier
	verifierCerts trust.CertificateClassifier
}

// NewTrustService returns the wallet's trust evaluator. The classifiers are the
// per-role certificate channels, i.e. the issuer and verifier trust models. A nil
// checker runs the list channel dark, which is what a wallet with no recognized
// lists does; a nil classifier runs that role's certificate channel dark.
func NewTrustService(checker *lote.Checker, issuerCerts, verifierCerts trust.CertificateClassifier) *TrustService {
	return &TrustService{checker: checker, issuerCerts: issuerCerts, verifierCerts: verifierCerts}
}

// Snapshot pins the state a single session evaluates against, so a list refresh
// landing halfway through cannot change its verdicts. It takes no context:
// pinning reads state the checker already holds, never fetches.
func (s *TrustService) Snapshot() trust.View {
	var lists trust.ListSnapshot
	if s.checker != nil {
		lists = s.checker.Snapshot()
	}
	return trust.NewView(lists, s.issuerCerts, s.verifierCerts)
}

// BatchIssuerEvidence is what the wallet recorded at issuance about the issuer of
// a stored credential batch, in the terms the trust ladder ranks parties by. It
// is read on every listing rather than stored as a level, so a credential's rung
// follows the lists as they change. A batch stored before the certificate was
// kept carries none and ranks through the list channel alone.
func BatchIssuerEvidence(batch *models.CredentialBatch) trust.Evidence {
	// Both names the issuer went by, most specific first, mirroring what
	// session.issuerVerdict matched on at issuance. A list may key on either.
	identifiers := []string{batch.IssuerIdentifier}
	if batch.CredentialIssuerIdentifier != batch.IssuerIdentifier {
		identifiers = append(identifiers, batch.CredentialIssuerIdentifier)
	}

	evidence := trust.Evidence{Identifiers: identifiers}
	if len(batch.IssuerCertificate) == 0 {
		return evidence
	}
	certificate, err := x509.ParseCertificate(batch.IssuerCertificate)
	if err != nil {
		// Unparseable evidence is absent evidence, not a failed read.
		eudi.Logger.Warnf("trust: stored issuer certificate for batch %q does not parse: %v", batch.Hash, err)
		return evidence
	}
	evidence.Certificate = certificate
	return evidence
}

// RefreshLists downloads the recognized lists and adopts the ones that hold up.
// It is the only path that touches the network, and not on the evaluation path.
//
// changed reports whether any list came back saying something different about the
// parties on it, which tells the caller whether what the app rendered went stale.
// A re-issue with the same entries does not count.
//
// The error names the sources that failed, for the caller's log: the lists the
// wallet already holds stay in force, and a party it can no longer confirm caps
// at low.
func (s *TrustService) RefreshLists(ctx context.Context) (bool, error) {
	if s.checker == nil {
		return false, nil
	}
	return s.checker.Refresh(ctx)
}
