package trust

import (
	"crypto/x509"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

func TestCertificateView_CertificateEvidenceRanksHigh(t *testing.T) {
	ev := Evidence{
		Certificate: &x509.Certificate{},
		Identifiers: []string{"x509_san_dns:verifier.example.com"},
	}

	for role, verdict := range map[string]Verdict{
		"verifier": CertificateView{}.Verifier(ev),
		"issuer":   CertificateView{}.Issuer(ev),
	} {
		require.Equal(t, clientmodels.TrustLevel_High, verdict.Level, role)
		require.Nil(t, verdict.Listing, "%s: the certificate channel grants no listing", role)
	}
}

func TestCertificateView_WithoutCertificateRanksLow(t *testing.T) {
	ev := Evidence{Identifiers: []string{"did:web:verifier.example.com"}}

	for role, verdict := range map[string]Verdict{
		"verifier": CertificateView{}.Verifier(ev),
		"issuer":   CertificateView{}.Issuer(ev),
	} {
		require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level, role)
		require.Nil(t, verdict.Listing, role)
	}
}

func TestCertificateView_EmptyEvidenceRanksLow(t *testing.T) {
	// A party the wallet knows nothing about still gets a verdict rather than
	// an error: no evaluation path may fail a session.
	require.Equal(t, clientmodels.TrustLevel_Low, CertificateView{}.Verifier(Evidence{}).Level)
	require.Equal(t, clientmodels.TrustLevel_Low, CertificateView{}.Issuer(Evidence{}).Level)
}
