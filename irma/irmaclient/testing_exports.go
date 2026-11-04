package irmaclient

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/eudi/sdjwt/sdjwttest"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// CreateTestSdJwtVc creates a test SD-JWT VC with the given parameters.
func CreateTestSdJwtVc[T sdjwt.LeafClaimDataType](keyBinder sdjwt.KeyBinder, vct, issuerUrl string, claims map[string]T, x5c []string) (sdjwtvc.SdJwtVc, error) {
	holderKey, err := keyBinder.CreateKeyPairs(1)
	if err != nil {
		return "", fmt.Errorf("failed to create holder keys: %v", err)
	}

	return CreateTestSdJwtVcWithHolderKey(vct, issuerUrl, claims, x5c, holderKey[0])
}

// CreateTestSdJwtVcWithHolderKey creates a test SD-JWT VC with a specific holder key.
func CreateTestSdJwtVcWithHolderKey[T sdjwt.LeafClaimDataType](vct, issuerUrl string, claims map[string]T, x5c []string, cnfHolderKey jwk.Key) (sdjwtvc.SdJwtVc, error) {
	holderKeyClaim, err := sdjwt.HolderKeyClaim(cnfHolderKey)
	if err != nil {
		return "", err
	}

	sdjwtClaims := []*sdjwt.ClaimElement{
		holderKeyClaim,
		sdjwt.Claim(sdjwt.SdAlgKey, iana.SHA256),
		sdjwt.Claim(jwt.IssuerKey, issuerUrl),
		sdjwt.Claim(jwt.IssuedAtKey, eudi_jwt.NewSystemClock().Now().Unix()),
		sdjwt.Claim(jwt.ExpirationKey, eudi_jwt.NewSystemClock().Now().Unix()+10000),
		sdjwt.Claim(sdjwtvc.VerifiableCredentialTypeKey, vct),
	}

	for key, value := range claims {
		sdjwtClaims = append(sdjwtClaims, sdjwt.SdClaim(key, value))
	}

	return sdjwtvc.NewSdJwtVcBuilder().
		WithPayload(sdjwtClaims...).
		WithIssuerCertificateChain(x5c).
		Build(sdjwttest.NewEcdsaJwtCreatorWithIssuerTestKey())
}

// CreateMultipleSdJwtVcsWithCustomKeyBinder creates multiple test SD-JWT VCs using a custom key binder.
func CreateMultipleSdJwtVcsWithCustomKeyBinder[T sdjwt.LeafClaimDataType](
	t *testing.T, keyBinder sdjwt.KeyBinder, vct string, issuer string, claims map[string]T, num uint,
) (SdJwtVcBatchMetadata, []sdjwtvc.SdJwtVc) {
	result := make([]sdjwtvc.SdJwtVc, num)

	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	if err != nil {
		panic(err)
	}

	for i := range num {
		vc, err := CreateTestSdJwtVc(keyBinder, vct, issuer, claims, certChain)
		require.NoError(t, err)
		result[i] = vc
	}

	// Convert to SdJwtVcKb since the holder doesn't know if a Key Binding JWT is present or not
	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdjwtvc.CreateDefaultVerificationContext(chain))
	info, _, err := createCredentialInfoAndVerifiedSdJwtVc(sdjwtvc.SdJwtVcKb(result[0]), holderVerifier, eudi.StrictSdJwtVerificationMode)
	require.NoError(t, err)
	return SdJwtVcBatchMetadata{
		BatchSize:              num,
		RemainingInstanceCount: num,
		SignedOn:               info.SignedOn,
		Expires:                info.Expires,
		Attributes:             info.Attributes,
		Hash:                   info.Hash,
		CredentialType:         info.CredentialType,
	}, result
}
