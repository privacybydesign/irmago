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
			Claim(Key_SdAlg, iana.SHA256),
			SdObject("address",
				SdClaim("street", "Schulstr 3"),
				SdClaim("country", "Germany"),
				// SdClaim("null", Null{}),
			),
			Object("personal_data",
				SdClaim("first_name", "Gerrit"),
				SdClaim("last_name", "Dijkstra"),
			),
			Array("nationalities", Item("NL"), SdItem("FR")),
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

	builder := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_VerifiableCredentialType, "test.test.email"),
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_Issuer, "https://irma.app"),
			Claim(Key_ExpiryTime, time.Now().Unix()),
		).
		WithIssuerCertificateChain(irmaAppCert)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_InvalidIssuerUrl_BuildFailure(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtBuilder().WithPayload(
		Claim(Key_ExpiryTime, time.Now().Unix()),
		Claim(Key_VerifiableCredentialType, "test.test.email"),
		Claim(Key_Issuer, "http://irma.app"),
	).
		WithIssuerCertificateChain(irmaAppCert)

	requireBuildFailure(t, builder)
}

func Test_BuildSdJwtVc_WithDisclosures_Success(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	require.NoError(t, err)

	builder := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_ExpiryTime, time.Now().Unix()),
			Claim(Key_SdAlg, iana.SHA256),
			Claim(Key_VerifiableCredentialType, "test.test.email"),
			Claim(Key_Issuer, "https://irma.app"),
			SdClaim("email", "test@gmail.com"),
			SdClaim("domain", "gmail.com"),
		).
		WithIssuerCertificateChain(irmaAppCert)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_DisclosuresWithoutHashingAlg_Failure(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtBuilder().
		WithPayload(
			Claim(Key_ExpiryTime, time.Now().Unix()),
			Claim(Key_VerifiableCredentialType, "test.test.email"),
			SdClaim("email", "test@gmail.com"),
			SdClaim("domain", "gmail.com"),
		).
		WithIssuerCertificateChain(irmaAppCert)

	requireBuildFailure(t, builder)
}

func Test_BuildSdJwtVc_NoVct_BuildFailure(t *testing.T) {
	builder := NewSdJwtBuilder().WithPayload(Claim(Key_ExpiryTime, time.Now().Unix()))
	requireBuildFailure(t, builder)
}

func requireBuildFailure(t *testing.T, builder *SdJwtBuilder) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	_, err := builder.Build(jwtCreator)
	require.Error(t, err)
}

func requireValidSdJwtVc(t *testing.T, builder *SdJwtBuilder) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()
	sdjwtvc, err := builder.Build(jwtCreator)
	require.NoError(t, err)
	context := CreateTestVerificationContext()
	holderVerifier := NewHolderVerificationProcessor(context)
	_, err = holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}
