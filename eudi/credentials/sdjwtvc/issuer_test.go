package sdjwtvc

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func Test_BuildSdJwtVc_ValidX509_Success(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().
		WithExpiresAt(time.Now().Unix()).
		WithVerifiableCredentialType("test.test.email").
		WithIssuerUrl("https://irma.app").
		WithIssuerCertificateChain(irmaAppCert)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_ValidIssuerUrl_Success(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().
		WithExpiresAt(time.Now().Unix()).
		WithVerifiableCredentialType("test.test.email").
		WithIssuerUrl("https://irma.app").
		WithIssuerCertificateChain(irmaAppCert)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_InvalidIssuerUrl_BuildFailure(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().
		WithExpiresAt(time.Now().Unix()).
		WithVerifiableCredentialType("test.test.email").
		WithIssuerUrl("http://irma.app").
		WithIssuerCertificateChain(irmaAppCert)

	requireBuildFailure(t, builder)
}

func Test_BuildSdJwtVc_WithDisclosures_Success(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().
		WithExpiresAt(time.Now().Unix()).
		WithHashingAlgorithm(HashAlg_Sha256).
		WithVerifiableCredentialType("test.test.email").
		WithDisclosures(disclosures).
		WithIssuerUrl("https://irma.app").
		WithIssuerCertificateChain(irmaAppCert)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_DisclosuresWithoutHashingAlg_Failure(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	})
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().
		WithExpiresAt(time.Now().Unix()).
		WithVerifiableCredentialType("test.test.email").
		WithDisclosures(disclosures).
		WithIssuerCertificateChain(irmaAppCert)

	requireBuildFailure(t, builder)
}

func Test_BuildSdJwtVc_NoVct_BuildFailure(t *testing.T) {
	builder := NewSdJwtVcBuilder().
		WithExpiresAt(time.Now().Unix())
	requireBuildFailure(t, builder)
}

func requireBuildFailure(t *testing.T, builder *SdJwtVcBuilder) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	_, err := builder.Build(jwtCreator)
	require.Error(t, err)
}

func requireValidSdJwtVc(t *testing.T, builder *SdJwtVcBuilder) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdjwtvc, err := builder.Build(jwtCreator)
	require.NoError(t, err)
	context := CreateTestVerificationContext()
	_, err = ParseAndVerifySdJwtVc(context, sdjwtvc)
	require.NoError(t, err)
}
