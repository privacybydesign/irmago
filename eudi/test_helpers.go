package eudi

import (
	"crypto/x509"
)

// NewTestTrustModel creates a TrustModel for testing with the given PKI components.
func NewTestTrustModel(rootPool, intermediatePool *x509.CertPool, revocationLists []*x509.RevocationList) *TrustModel {
	return &TrustModel{
		basePath:                        "testdata",
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
