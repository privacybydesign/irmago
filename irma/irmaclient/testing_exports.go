package irmaclient

import (
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// CreateTestSdJwtVc creates a test SD-JWT VC with the given parameters.
func CreateTestSdJwtVc[T sdjwtvc.LeafClaimDataType](keyBinder sdjwtvc.KeyBinder, vct, issuerUrl string, claims map[string]T, x5c []string) (sdjwtvc.SdJwtVc, error) {
	holderKey, err := keyBinder.CreateKeyPairs(1)
	if err != nil {
		return "", fmt.Errorf("failed to create holder keys: %v", err)
	}

	return CreateTestSdJwtVcWithHolderKey(vct, issuerUrl, claims, x5c, holderKey[0])
}

// CreateTestSdJwtVcWithHolderKey creates a test SD-JWT VC with a specific holder key.
func CreateTestSdJwtVcWithHolderKey[T sdjwtvc.LeafClaimDataType](vct, issuerUrl string, claims map[string]T, x5c []string, cnfHolderKey jwk.Key) (sdjwtvc.SdJwtVc, error) {
	holderKeyClaim, err := sdjwtvc.HolderKeyClaim(cnfHolderKey)
	if err != nil {
		return "", err
	}

	sdjwtClaims := []*sdjwtvc.ClaimElement{
		holderKeyClaim,
		sdjwtvc.Claim(sdjwtvc.Key_SdAlg, iana.SHA256),
		sdjwtvc.Claim(sdjwtvc.Key_VerifiableCredentialType, vct),
		sdjwtvc.Claim(sdjwtvc.Key_Issuer, issuerUrl),
		sdjwtvc.Claim(sdjwtvc.Key_IssuedAt, eudi_jwt.NewSystemClock().Now().Unix()),
		sdjwtvc.Claim(sdjwtvc.Key_ExpiryTime, eudi_jwt.NewSystemClock().Now().Unix()+10000),
	}

	for key, value := range claims {
		sdjwtClaims = append(sdjwtClaims, sdjwtvc.SdClaim(key, value))
	}

	return sdjwtvc.NewSdJwtBuilder().
		WithPayload(sdjwtClaims...).
		WithIssuerCertificateChain(x5c).
		Build(sdjwtvc.NewEcdsaJwtCreatorWithIssuerTestkey())
}

// CreateMultipleSdJwtVcsWithCustomKeyBinder creates multiple test SD-JWT VCs using a custom key binder.
func CreateMultipleSdJwtVcsWithCustomKeyBinder[T sdjwtvc.LeafClaimDataType](
	t *testing.T, keyBinder sdjwtvc.KeyBinder, vct string, issuer string, claims map[string]T, num uint,
) (SdJwtVcBatchMetadata, []sdjwtvc.SdJwtVc) {
	result := make([]sdjwtvc.SdJwtVc, num)

	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	if err != nil {
		panic(err)
	}

	for i := range num {
		sdjwt, err := CreateTestSdJwtVc(keyBinder, vct, issuer, claims, certChain)
		require.NoError(t, err)
		result[i] = sdjwt
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
