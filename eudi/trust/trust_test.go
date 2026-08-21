package trust

import (
	"crypto/x509"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// stubClassifier confers one fixed level on every certificate.
type stubClassifier clientmodels.TrustLevel

func (s stubClassifier) Classify(*x509.Certificate) clientmodels.TrustLevel {
	return clientmodels.TrustLevel(s)
}

func TestCertificateChannel_ConfersTheAnchorsLevel(t *testing.T) {
	ev := Evidence{Certificate: &x509.Certificate{}}
	view := NewView(nil,
		stubClassifier(clientmodels.TrustLevel_Medium),
		stubClassifier(clientmodels.TrustLevel_High))

	issuer := view.Issuer(ev)
	require.Equal(t, clientmodels.TrustLevel_Medium, issuer.Level)
	require.Equal(t, clientmodels.TrustLevel_Medium, issuer.CertificateLevel)

	verifier := view.Verifier(ev)
	require.Equal(t, clientmodels.TrustLevel_High, verifier.Level)
	require.Equal(t, clientmodels.TrustLevel_High, verifier.CertificateLevel)

	require.Nil(t, issuer.Listing, "the certificate channel grants no listing")
	require.Nil(t, verifier.Listing, "the certificate channel grants no listing")
}

func TestCertificateChannel_UnclassifiableCertificateIsAbsentEvidence(t *testing.T) {
	// A certificate chaining to no anchor is a self-asserted key: no rung, and a
	// verdict recording that the channel contributed nothing.
	view := NewView(nil,
		stubClassifier(clientmodels.TrustLevel_Unevaluated),
		stubClassifier(clientmodels.TrustLevel_Unevaluated))

	verdict := view.Verifier(Evidence{Certificate: &x509.Certificate{}})

	require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level)
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, verdict.CertificateLevel)
}

func TestCertificateChannel_WithoutCertificateRanksLow(t *testing.T) {
	view := NewView(nil,
		stubClassifier(clientmodels.TrustLevel_High),
		stubClassifier(clientmodels.TrustLevel_High))

	verdict := view.Verifier(Evidence{Identifiers: []string{"did:web:verifier.example.com"}})

	require.Equal(t, clientmodels.TrustLevel_Low, verdict.Level,
		"a classifier is never consulted for a party that presented no certificate")
	require.Equal(t, clientmodels.TrustLevel_Unevaluated, verdict.CertificateLevel)
}

func TestNewView_EmptyEvidenceRanksLow(t *testing.T) {
	// A party the wallet knows nothing about still gets a verdict: no evaluation
	// path may fail a session.
	view := NewView(nil, nil, nil)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Verifier(Evidence{}).Level)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Issuer(Evidence{}).Level)
}
