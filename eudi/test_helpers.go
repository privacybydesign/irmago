package eudi

import (
	"crypto/x509"
	"path/filepath"

	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
)

// NewTestTrustModel creates a TrustModel for testing with the given PKI components.
func NewTestTrustModel(basePath string, rootPool, intermediatePool *x509.CertPool, revocationLists []*x509.RevocationList) *TrustModel {
	fstorage := filesystem.NewFileSystemStorage([32]byte{}, filepath.Join(basePath, "testdata"))
	tm := &TrustModel{storageContainer: fstorage.Issuers()}

	s := newTrustState()
	if rootPool != nil {
		s.roots = rootPool
	}
	if intermediatePool != nil {
		s.intermediates = intermediatePool
	}
	s.revocationLists = revocationLists
	tm.current.Store(s)
	return tm
}

// ClearTrustedRootCertificates replaces the root cert pool (for testing missing roots).
func (tm *TrustModel) ClearTrustedRootCertificates() {
	s := tm.state().clone()
	s.roots = x509.NewCertPool()
	tm.current.Store(s)
}

// ClearTrustedIntermediateCertificates replaces the intermediate cert pool (for testing missing intermediates).
func (tm *TrustModel) ClearTrustedIntermediateCertificates() {
	s := tm.state().clone()
	s.intermediates = x509.NewCertPool()
	tm.current.Store(s)
}
