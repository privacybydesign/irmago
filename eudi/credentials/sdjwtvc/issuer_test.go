package sdjwtvc

import (
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
	sdJwt, err := NewSdJwtVcBuilder().
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
}

func Test_BuildSdJwtVc_ValidX509_Success(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().
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

	builder := NewSdJwtVcBuilder().WithPayload(
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

	builder := NewSdJwtVcBuilder().
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

// Test_BuildSdJwtVc_DisclosuresWithoutHashingAlg_DefaultsToSha256 verifies that
// omitting _sd_alg defaults to sha-256 per SD-JWT spec Section 4.1.1.
func Test_BuildSdJwtVc_DisclosuresWithoutHashingAlg_DefaultsToSha256(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().
		WithPayload(
			Claim(Key_Issuer, "https://example.com"),
			Claim(Key_ExpiryTime, time.Now().Unix()),
			Claim(Key_VerifiableCredentialType, "test.test.email"),
			SdClaim("email", "test@gmail.com"),
			SdClaim("domain", "gmail.com"),
		).
		WithIssuerCertificateChain(irmaAppCert)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_NoVct_BuildFailure(t *testing.T) {
	builder := NewSdJwtVcBuilder().WithPayload(Claim(Key_ExpiryTime, time.Now().Unix()))
	requireBuildFailure(t, builder)
}

// TestBuilder_NoVct_Success verifies that the generic SD-JWT Builder (unlike
// SdJwtVcBuilder) has no opinion on `vct`: a plain SD-JWT with no vct claim
// at all is valid per the SD-JWT core spec.
func TestBuilder_NoVct_Success(t *testing.T) {
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()

	sdJwt, err := NewBuilder().
		WithPayload(
			Claim(Key_Issuer, "not-necessarily-a-url"),
			SdClaim("email", "test@gmail.com"),
		).
		Build(jwtCreator)
	require.NoError(t, err)
	require.NotEmpty(t, sdJwt)

	payload, err := DecodeJwtPayload(sdJwt)
	require.NoError(t, err)
	require.NotContains(t, payload, Key_VerifiableCredentialType)
	require.Equal(t, "not-necessarily-a-url", payload[Key_Issuer])
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
