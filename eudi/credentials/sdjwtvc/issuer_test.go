package sdjwtvc

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt/sdjwttest"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestNewBuilder(t *testing.T) {
	jwtCreator := sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey()
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)
	sdJwt, err := NewSdJwtVcBuilder().
		WithPayload(
			sdjwt.Claim(jwt.IssuedAtKey, 13853353),
			sdjwt.Claim(sdjwt.SdAlgKey, iana.SHA256),
			sdjwt.Claim(VerifiableCredentialTypeKey, "pbdf.sidn-pbdf.email"),
			sdjwt.SdObject("address",
				sdjwt.SdClaim("street", "Schulstr 3"),
				sdjwt.SdClaim("country", "Germany"),
				// sdjwt.SdClaim("null", sdjwt.Null{}),
			),
			sdjwt.Object("personal_data",
				sdjwt.SdClaim("first_name", "Gerrit"),
				sdjwt.SdClaim("last_name", "Dijkstra"),
			),
			sdjwt.Array("nationalities", sdjwt.Item("NL"), sdjwt.SdItem("FR")),
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
			sdjwt.Claim(jwt.IssuerKey, "https://irma.app"),
			sdjwt.Claim(jwt.ExpirationKey, time.Now().Unix()),
			sdjwt.Claim(sdjwt.SdAlgKey, iana.SHA256),
			sdjwt.Claim(VerifiableCredentialTypeKey, "test.test.email"),
		).
		WithIssuerCertificateChain(irmaAppCert)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_InvalidIssuerUrl_BuildFailure(t *testing.T) {
	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	builder := NewSdJwtVcBuilder().WithPayload(
		sdjwt.Claim(jwt.IssuerKey, "http://irma.app"),
		sdjwt.Claim(jwt.ExpirationKey, time.Now().Unix()),
		sdjwt.Claim(VerifiableCredentialTypeKey, "test.test.email"),
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
			sdjwt.Claim(jwt.IssuerKey, "https://irma.app"),
			sdjwt.Claim(jwt.ExpirationKey, time.Now().Unix()),
			sdjwt.Claim(sdjwt.SdAlgKey, iana.SHA256),
			sdjwt.Claim(VerifiableCredentialTypeKey, "test.test.email"),
			sdjwt.SdClaim("email", "test@gmail.com"),
			sdjwt.SdClaim("domain", "gmail.com"),
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
			sdjwt.Claim(jwt.IssuerKey, "https://irma.app"),
			sdjwt.Claim(jwt.ExpirationKey, time.Now().Unix()),
			sdjwt.Claim(VerifiableCredentialTypeKey, "test.test.email"),
			sdjwt.SdClaim("email", "test@gmail.com"),
			sdjwt.SdClaim("domain", "gmail.com"),
		).
		WithIssuerCertificateChain(irmaAppCert)

	requireValidSdJwtVc(t, builder)
}

func Test_BuildSdJwtVc_NoVct_BuildFailure(t *testing.T) {
	builder := NewSdJwtVcBuilder().WithPayload(sdjwt.Claim(jwt.ExpirationKey, time.Now().Unix()))
	requireBuildFailure(t, builder)
}

func requireBuildFailure(t *testing.T, builder *SdJwtVcBuilder) {
	jwtCreator := sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey()
	_, err := builder.Build(jwtCreator)
	require.Error(t, err)
}

func requireValidSdJwtVc(t *testing.T, builder *SdJwtVcBuilder) {
	jwtCreator := sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey()
	sdjwtvc, err := builder.Build(jwtCreator)
	require.NoError(t, err)
	context := CreateTestVerificationContext()
	holderVerifier := NewHolderVerificationProcessor(context)
	_, err = holderVerifier.ParseAndVerifySdJwtVc(SdJwtVcKb(sdjwtvc))
	require.NoError(t, err)
}
