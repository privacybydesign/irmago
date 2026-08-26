package services

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt/sdjwttest"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func newTestSdJwtVcKb(t *testing.T, vct, issuerUrl string, claims map[string]string, x5c []string) sdjwtvc.SdJwtVcKb {
	t.Helper()

	sdjwtClaims := []*sdjwt.ClaimElement{
		sdjwt.Claim(sdjwt.SdAlgKey, iana.SHA256),
		sdjwt.Claim(sdjwtvc.VerifiableCredentialTypeKey, vct),
		sdjwt.Claim(jwt.IssuerKey, issuerUrl),
		sdjwt.Claim(jwt.IssuedAtKey, eudi_jwt.NewSystemClock().Now().Unix()),
		sdjwt.Claim(jwt.ExpirationKey, eudi_jwt.NewSystemClock().Now().Unix()+10000),
	}
	for key, value := range claims {
		sdjwtClaims = append(sdjwtClaims, sdjwt.SdClaim(key, value))
	}

	sdJwt, err := sdjwtvc.NewSdJwtVcBuilder().
		WithPayload(sdjwtClaims...).
		WithIssuerCertificateChain(x5c).
		Build(sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey())
	require.NoError(t, err)

	return sdjwtvc.SdJwtVcKb(sdJwt)
}

func TestSdJwtVcCredentialFormatParser_ParseAndVerify(t *testing.T) {
	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	x5c, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	require.NoError(t, err)

	sdJwt := newTestSdJwtVcKb(t, "test.credential.type", "https://openid4vc.staging.yivi.app", map[string]string{"name": "Test User"}, x5c)

	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdjwtvc.CreateDefaultVerificationContext(chain))
	parser := NewSdJwtVcCredentialFormatParser(holderVerifier)

	parsed, err := parser.ParseAndVerify(string(sdJwt), "https://openid4vc.staging.yivi.app", false)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	require.Equal(t, models.CredentialFormatSdJwtVc, parsed.Format)
	require.Equal(t, "test.credential.type", parsed.VerifiableCredentialType)
	require.Equal(t, "https://openid4vc.staging.yivi.app", parsed.IssuerIdentifier)
	require.NotEmpty(t, parsed.ResolvedClaims)
	require.NotEmpty(t, parsed.RawCredentialBytes)
	require.NotNil(t, parsed.IssuedAt)
	require.NotNil(t, parsed.ExpiresAt)
	require.NotNil(t, parsed.SdJwtVc)
	require.Nil(t, parsed.HolderBindingKeyThumbprint)
}

func TestSdJwtVcCredentialFormatParser_ParseAndVerify_InvalidCredential(t *testing.T) {
	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdjwtvc.CreateDefaultVerificationContext(chain))
	parser := NewSdJwtVcCredentialFormatParser(holderVerifier)

	_, err := parser.ParseAndVerify("not-a-real-sd-jwt", "https://openid4vc.staging.yivi.app", false)
	require.Error(t, err)
}

func TestSdJwtVcCredentialFormatParser_CheckBatchUniqueness_RejectsDuplicateKeyBinding(t *testing.T) {
	pubKey, _ := generateTestJwk(t)
	cnf := &sdjwt.CnfField{Jwk: &pubKey}

	vc1 := newVerifiedVcWithCnf("vct-1", "https://issuer.example.com", cnf)
	vc2 := newVerifiedVcWithCnf("vct-1", "https://issuer.example.com", cnf)

	parser := NewSdJwtVcCredentialFormatParser(nil)
	err := parser.CheckBatchUniqueness([]*ParsedCredential{
		{SdJwtVc: vc1},
		{SdJwtVc: vc2},
	})
	require.Error(t, err)
}
