package lote

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/jades"
	"github.com/stretchr/testify/require"
)

// Sign and VerifySigned are a pair. Most of the suite exercises this implicitly
// through SignList; this states it directly.
func TestSign_ProducesADocumentTheWalletsOwnVerifierAccepts(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList(testListId, 1)

	signed, err := Sign(Document{LoTE: list}, []*x509.Certificate{signer.Cert}, signer.PrivKey, time.Now())
	require.NoError(t, err)

	verified, err := VerifySigned(signed, signer.X509VerificationContext())
	require.NoError(t, err)
	require.Equal(t, testListId, verified.SchemeInformation.SchemeName["en"])
}

// Clause 6.8.0 binds the certificate to the scheme it signs for, and signing time
// is the only place a mismatch can be caught.
func TestSign_RejectsACertificateWhoseOrganizationIsNotTheSchemeOperator(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList(testListId, 1)
	list.SchemeInformation.SchemeOperatorName = MultiLang{"en": "Someone Else BV"}

	_, err := Sign(Document{LoTE: list}, []*x509.Certificate{signer.Cert}, signer.PrivKey, time.Now())

	require.ErrorContains(t, err, "clause 6.8.0")
	require.ErrorContains(t, err, "organization")
}

func TestSign_RejectsACertificateWhoseCountryIsNotTheSchemeTerritory(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList(testListId, 1)
	list.SchemeInformation.SchemeTerritory = "BE"

	_, err := Sign(Document{LoTE: list}, []*x509.Certificate{signer.Cert}, signer.PrivKey, time.Now())

	require.ErrorContains(t, err, "clause 6.8.0")
	require.ErrorContains(t, err, "country")
}

func TestSign_RejectsACertificateWithoutDigitalSignatureKeyUsage(t *testing.T) {
	signer := NewTestLoteSigner(t)
	// Strip the key usage the wallet checks explicitly.
	signer.Cert.KeyUsage = 0

	_, err := Sign(Document{LoTE: NewTestList(testListId, 1)}, []*x509.Certificate{signer.Cert},
		signer.PrivKey, time.Now())

	require.ErrorContains(t, err, "digitalSignature")
}

// Clause 6.6.5, with both bounds taken from the document rather than a tolerance.
func TestSign_RefusesToSignADocumentDatedInTheFuture(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList(testListId, 1)
	list.SchemeInformation.ListIssueDateTime = time.Now().Add(time.Hour)

	_, err := Sign(Document{LoTE: list}, []*x509.Certificate{signer.Cert}, signer.PrivKey, time.Now())

	require.ErrorContains(t, err, "clause 6.6.5")
	require.ErrorContains(t, err, "dated in the future")
}

// Publishing an already-expired document is publishing nothing, so the operator
// should learn at the point of signing.
func TestSign_RefusesToSignAnAlreadyExpiredDocument(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList(testListId, 1)
	list.SchemeInformation.ListIssueDateTime = time.Now().Add(-48 * time.Hour)
	list.SchemeInformation.NextUpdate = time.Now().Add(-time.Hour)

	_, err := Sign(Document{LoTE: list}, []*x509.Certificate{signer.Cert}, signer.PrivKey, time.Now())

	require.ErrorContains(t, err, "clause 6.6.5")
	require.ErrorContains(t, err, "already expired")
}

// Signing a little before the issue date is a clock, not a lie.
func TestSign_ToleratesClockSkewAgainstTheIssueDate(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList(testListId, 1)
	list.SchemeInformation.ListIssueDateTime = time.Now().Add(ClockSkew / 2)

	_, err := Sign(Document{LoTE: list}, []*x509.Certificate{signer.Cert}, signer.PrivKey, time.Now())

	require.NoError(t, err)
}

// Document conformance belongs to ValidateDocument and to `yivi eudi lote build`; a
// rule checked twice drifts in one of the two places.
func TestSign_DoesNotCheckDocumentConformance(t *testing.T) {
	signer := NewTestLoteSigner(t)
	list := NewTestList(testListId, 1)
	// Clause 6.3.6 prescribes `CC:name`. `lote build` rejects this; Sign does not.
	list.SchemeInformation.SchemeName = MultiLang{"en": "not-prefixed-with-a-territory"}

	_, err := Sign(Document{LoTE: list}, []*x509.Certificate{signer.Cert}, signer.PrivKey, time.Now())

	require.NoError(t, err)
}

func TestSignatureAlgorithmFor_FollowsTheCurve(t *testing.T) {
	signer := NewTestLoteSigner(t)

	alg, err := jades.SignatureAlgorithmFor(signer.PrivKey)

	require.NoError(t, err)
	require.Equal(t, "ES256", alg.String())
}
