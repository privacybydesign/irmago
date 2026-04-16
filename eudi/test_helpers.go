package eudi

import (
	"crypto/x509"
	"path/filepath"

	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/internal/mocks"
)

// NewTestTrustModel creates a TrustModel for testing with the given PKI components.
func NewTestTrustModel(basePath string, rootPool, intermediatePool *x509.CertPool, revocationLists []*x509.RevocationList) *TrustModel {
	fstorage := filesystem.NewFileSystemStorage(&mocks.MockEncryptionMiddleware{}, filepath.Join(basePath, "testdata"))
	return &TrustModel{
		storageContainer:                fstorage.Issuers(),
		trustedRootCertificates:         rootPool,
		trustedIntermediateCertificates: intermediatePool,
		revocationLists:                 revocationLists,
	}
}

// ClearTrustedRootCertificates replaces the root cert pool (for testing missing roots).
func (tm *TrustModel) ClearTrustedRootCertificates() {
	tm.trustedRootCertificates = x509.NewCertPool()
}

// ClearTrustedIntermediateCertificates replaces the intermediate cert pool (for testing missing intermediates).
func (tm *TrustModel) ClearTrustedIntermediateCertificates() {
	tm.trustedIntermediateCertificates = x509.NewCertPool()
}
