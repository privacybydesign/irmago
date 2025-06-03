package sdjwtvc

import (
	"testing"

	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func Test_BuildSdJwtVc_ValidX509_Success(t *testing.T) {
	irmaAppCert, err := ParseCertificateChain(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType("pbdf.sidn-pbdf.email").
		WithIssuerUrl("https://irma.app").
		WithIssuerCertificateChain(irmaAppCert)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_BareMinimum_Success(t *testing.T) {
	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType("pbdf.sidn-pbdf.email").
		WithIssuerUrl("https://example.app")
	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_ValidIssuerUrl_Success(t *testing.T) {
	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType("pbdf.sidn-pbdf.email").
		WithIssuerUrl("https://openid4vc.staging.yivi.app")

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_InvalidIssuerUrl_BuildFailure(t *testing.T) {
	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType("pbdf.sidn-pbdf.email").
		WithIssuerUrl("http://openid4vc.staging.yivi.app")

	requireBuildFailure(t, builder)
}

func Test_BuildSdJwtVc_InvalidIssuerUrl_AllowNonHttps_Success(t *testing.T) {
	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType("pbdf.sidn-pbdf.email").
		WithIssuerUrl("http://openid4vc.staging.yivi.app").
		WithAllowNonHttpsIssuerUrl(true)

	requireValidSdJwtVcWithNonHttpsIssuer(t, builder)
}

func Test_BuildSdJwtVc_WithDisclosures_Success(t *testing.T) {
	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"name":     "Yivi",
		"location": "Utrecht",
	})
	requireNoErr(t, err)

	builder := NewSdJwtVcBuilder().
		WithHashingAlgorithm(HashAlg_Sha256).
		WithVerifiableCredentialType("pbdf.sidn-pbdf.email").
		WithDisclosures(disclosures).
		WithIssuerUrl("https://openid4vc.staging.yivi.app")

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_DisclosuresWithoutHashingAlg_Failure(t *testing.T) {
	disclosures, err := MultipleNewDisclosureContents(map[string]string{
		"name":     "Yivi",
		"location": "Utrecht",
	})
	requireNoErr(t, err)

	builder := NewSdJwtVcBuilder().
		WithVerifiableCredentialType("pbdf.sidn-pbdf.email").
		WithDisclosures(disclosures)

	requireBuildFailure(t, builder)
}

func Test_BuildSdJwtVc_NoVct_BuildFailure(t *testing.T) {
	builder := NewSdJwtVcBuilder()
	requireBuildFailure(t, builder)
}

func requireBuildFailure(t *testing.T, builder *SdJwtVcBuilder) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	_, err := builder.Build(jwtCreator)
	requireErr(t, err)
}

func requireValidSdJwtVc(t *testing.T, builder *SdJwtVcBuilder) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdjwtvc, err := builder.Build(jwtCreator)
	requireNoErr(t, err)
	context := createTestVerificationContext(false)
	_, err = ParseAndVerifySdJwtVc(context, sdjwtvc)
	requireNoErr(t, err)
}

func requireValidSdJwtVcWithNonHttpsIssuer(t *testing.T, builder *SdJwtVcBuilder) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdjwtvc, err := builder.Build(jwtCreator)
	requireNoErr(t, err)
	context := createTestVerificationContext(true)
	_, err = ParseAndVerifySdJwtVc(context, sdjwtvc)
	requireNoErr(t, err)
}
