package sdjwtvc

import (
	"crypto/x509"
	"testing"

	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// The holder's identity gate for an x5c issuer, with and without the anchoring
// requirement. The test credential is signed under the staging issuer
// certificate; the verification context here anchors a different chain, so the
// issuer chains to nothing the context knows.

func unanchoringContext() SdJwtVcVerificationContext {
	return CreateDefaultVerificationContext(testdata.IssuerCertChain_irma_app_Bytes)
}

func Test_HolderVerificationProcessor_UnanchoredIssuer_RefusedByDefault(t *testing.T) {
	credential := createTestSdJwtVc(t, newWorkingSdJwtVcTestConfig())
	holderVerifier := NewHolderVerificationProcessor(unanchoringContext())

	_, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(credential))
	require.ErrorContains(t, err, "failed to verify certificate")
}

func Test_HolderVerificationProcessor_UnanchoredIssuer_AcceptedWhenTheLadderDecides(t *testing.T) {
	credential := createTestSdJwtVc(t, newWorkingSdJwtVcTestConfig())
	context := unanchoringContext()
	context.AcceptUnanchoredIssuers = true
	holderVerifier := NewHolderVerificationProcessor(context)

	verified, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(credential))
	require.NoError(t, err)
	require.NotNil(t, verified.IssuerCertificate, "the certificate is reported for the trust ladder to rank")

	chain, err := utils.ParsePemCertificateChain(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	require.NoError(t, err)
	require.True(t, chain[0].Equal(verified.IssuerCertificate))
}

// Revocation stays a gate whatever the anchoring policy: the CA withdrawing a
// certificate is an act of distrust, not the absence of trust.
func Test_HolderVerificationProcessor_UnanchoredIssuer_RevokedIsStillRefused(t *testing.T) {
	credential := createTestSdJwtVc(t, newWorkingSdJwtVcTestConfig())
	chain, err := utils.ParsePemCertificateChain(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes)
	require.NoError(t, err)
	issuerCert := chain[0]

	context := unanchoringContext()
	context.AcceptUnanchoredIssuers = true
	context.X509VerificationContext = &eudi_jwt.StaticVerificationContext{
		VerifyOpts: context.X509VerificationContext.GetVerificationOptionsTemplate(),
		RevocationLists: []*x509.RevocationList{{
			Issuer:                    issuerCert.Issuer,
			AuthorityKeyId:            issuerCert.AuthorityKeyId,
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: issuerCert.SerialNumber}},
		}},
	}
	holderVerifier := NewHolderVerificationProcessor(context)

	_, err = holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(credential))
	require.ErrorContains(t, err, "issuer certificate is refused")
	require.ErrorContains(t, err, "certificate is revoked")
}

// An anchored issuer reports its certificate too, under either policy.
func Test_HolderVerificationProcessor_AnchoredIssuer_ReportsItsCertificate(t *testing.T) {
	credential := createTestSdJwtVc(t, newWorkingSdJwtVcTestConfig())
	holderVerifier := NewHolderVerificationProcessor(CreateDefaultVerificationContext(testdata.SdJwtVc_IssuerCert_openid4vc_staging_yivi_app_Bytes))

	verified, err := holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(credential))
	require.NoError(t, err)
	require.NotNil(t, verified.IssuerCertificate)
}
