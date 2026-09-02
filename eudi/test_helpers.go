package eudi

import (
	"crypto/x509"
	"path/filepath"

	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// NewTestTrustModel creates a TrustModel for testing with the given PKI components.
func NewTestTrustModel(basePath string, rootPool, intermediatePool *x509.CertPool, revocationLists []*x509.RevocationList) *TrustModel {
	fstorage := filesystem.NewFileSystemStorage([32]byte{}, filepath.Join(basePath, "testdata"))
	tm := &TrustModel{
		storageContainer: fstorage.Issuers(),
		logger:           Logger,
	}
	state := newTrustState()
	if rootPool != nil {
		state.trustedRootCertificates = rootPool
	}
	if intermediatePool != nil {
		state.trustedIntermediateCertificates = intermediatePool
	}
	state.revocationLists = revocationLists
	tm.current.Store(state)
	return tm
}

// MarkAnchorsInstalled records the roots of the current state as locally
// installed anchors, so what chains to them ranks high on the trust ladder as
// chains installed in storage do. For tests that build a model by hand.
func (tm *TrustModel) MarkAnchorsInstalled(roots ...*x509.Certificate) {
	tm.replaceState(func(s *trustState) { s.installedAnchors = append(s.installedAnchors, roots...) })
}

// ClearTrustedRootCertificates replaces the root cert pool (for testing missing roots).
func (tm *TrustModel) ClearTrustedRootCertificates() {
	tm.replaceState(func(s *trustState) { s.trustedRootCertificates = x509.NewCertPool() })
}

// ClearTrustedIntermediateCertificates replaces the intermediate cert pool (for testing missing intermediates).
func (tm *TrustModel) ClearTrustedIntermediateCertificates() {
	tm.replaceState(func(s *trustState) { s.trustedIntermediateCertificates = x509.NewCertPool() })
}

// replaceState publishes a modified copy of the current state.
func (tm *TrustModel) replaceState(modify func(*trustState)) {
	current := tm.state()
	next := &trustState{
		trustedRootCertificates:           current.trustedRootCertificates.Clone(),
		trustedIntermediateCertificates:   current.trustedIntermediateCertificates.Clone(),
		allCerts:                          current.allCerts,
		revocationLists:                   current.revocationLists,
		revocationListsDistributionPoints: current.revocationListsDistributionPoints,
		installedAnchors:                  current.installedAnchors,
	}
	modify(next)
	tm.current.Store(next)
}
