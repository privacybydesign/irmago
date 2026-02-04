package sdjwtvc

import (
	"fmt"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestNewBuilder(t *testing.T) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)
	sdJwt, err := NewSdJwtBuilder().
		WithPayload(
			Claim("iat", 13853353),
			Claim("vct", "pbdf.sidn-pbdf.email"),
			Claim("sd_alg", iana.SHA256),
			SdObject("address",
				SdClaim("street", "Schulstr 3"),
				SdClaim("country", "Germany"),
				// SdClaim("null", Null{}),
			),
			Object("personal_data",
				SdClaim("first_name", "Gerrit"),
				SdClaim("last_name", "Dijkstra"),
			),
		).
		WithIssuerCertificateChain(irmaAppCert).
		Build(jwtCreator)

	require.NoError(t, err)
	require.NotEmpty(t, sdJwt)
	fmt.Printf("sdjwt:\n%v\n\n", sdJwt)
}

func Test_BuildSdJwtVc_ValidX509_Success(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().
		WithHashingAlgorithm(iana.SHA256).
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
		WithHashingAlgorithm(iana.SHA256).
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
		WithHashingAlgorithm(iana.SHA256).
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
	holderVerifier := NewHolderVerificationProcessor(context)
	_, err = holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}
