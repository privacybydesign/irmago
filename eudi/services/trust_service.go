package services

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

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
// The recognized lists also feed the certificate channel: an anchor list
// delivers CAs, which SyncListAnchors installs into the trust models next to the
// compiled-in ones. That is the one place the two channels touch, and it goes
// one way — lists add anchors, anchors never add lists.
//
// Evaluation is fail-soft by construction: nothing on this path returns an error,
// so a trust level can never fail a session.
type TrustService struct {
	checker       *lote.Checker
	issuerCerts   trust.CertificateClassifier
	verifierCerts trust.CertificateClassifier

	anchorsMu sync.Mutex
	installer AnchorInstaller
	// installed fingerprints the anchor set last handed to the installer, so a
	// refresh that changed nothing about the anchors reloads nothing.
	installed string
}

// AnchorInstaller is where list-delivered trust anchors go: the wallet's
// eudi.Configuration, whose issuer and verifier pools take them next to the
// compiled-in ones. It has no way to take a trust-list anchor.
type AnchorInstaller interface {
	SetListTrustAnchors(issuers, verifiers []eudi.ExtraTrustAnchor) error
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
// parties on it — or delivered a different set of anchors, which changes the rung
// of every stored credential under them — which tells the caller whether what the
// app rendered went stale. A re-issue with the same entries does not count.
//
// The error names the sources that failed, for the caller's log: the lists the
// wallet already holds stay in force, and a party it can no longer confirm caps
// at low.
func (s *TrustService) RefreshLists(ctx context.Context) (bool, error) {
	if s.checker == nil {
		return false, nil
	}
	changed, err := s.checker.Refresh(ctx)
	anchorsChanged, syncErr := s.SyncListAnchors()
	return changed || anchorsChanged, errors.Join(err, syncErr)
}

// InstallListAnchorsInto names where list-delivered anchors go, and installs
// whatever the checker holds right now — the persisted anchor lists, at start-up.
// Until it is called the anchor lists are read but install nothing.
func (s *TrustService) InstallListAnchorsInto(installer AnchorInstaller) error {
	s.anchorsMu.Lock()
	s.installer = installer
	s.installed = ""
	s.anchorsMu.Unlock()
	_, err := s.SyncListAnchors()
	return err
}

// SyncListAnchors installs the anchors the current anchor lists deliver into the
// trust models, when they differ from what was installed last. It reports whether
// they did. Without a checker or an installer it is a no-op.
func (s *TrustService) SyncListAnchors() (bool, error) {
	if s.checker == nil {
		return false, nil
	}

	s.anchorsMu.Lock()
	defer s.anchorsMu.Unlock()
	if s.installer == nil {
		return false, nil
	}

	anchors := s.checker.Anchors()
	fingerprint := fingerprintAnchors(anchors)
	if fingerprint == s.installed {
		return false, nil
	}

	var issuers, verifiers []eudi.ExtraTrustAnchor
	for _, anchor := range anchors {
		extra := eudi.ExtraTrustAnchor{
			PEM:                   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Certificate.Raw}),
			Confers:               anchor.Confers,
			CRLDistributionPoints: anchor.CRLDistributionPoints,
		}
		switch anchor.Role {
		case trust.RoleIssuer:
			issuers = append(issuers, extra)
		case trust.RoleVerifier:
			verifiers = append(verifiers, extra)
		}
	}
	if err := s.installer.SetListTrustAnchors(issuers, verifiers); err != nil {
		return false, fmt.Errorf("install list-delivered trust anchors: %w", err)
	}
	s.installed = fingerprint
	return true, nil
}

// fingerprintAnchors reduces an anchor set to a string two sets can be compared
// by: role, certificate, level and distribution points, order-independent.
func fingerprintAnchors(anchors []lote.Anchor) string {
	lines := make([]string, 0, len(anchors))
	for _, anchor := range anchors {
		digest := sha256.Sum256(anchor.Certificate.Raw)
		points := slices.Clone(anchor.CRLDistributionPoints)
		slices.Sort(points)
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s",
			anchor.Role, hex.EncodeToString(digest[:]), anchor.Confers, strings.Join(points, ",")))
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}
