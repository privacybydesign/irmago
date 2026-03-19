package openid4vci

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func createOpenID4VCiClientForTesting(t *testing.T) *Client {
	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	storage, err := irmaclient.NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	addTestCredentialsToStorage(t, storage, keyBinder)

	storageFolder := test.CreateTestStorage(t)
	testStoragePath := test.FindTestdataFolder(t)
	err = common.CopyDirectory(filepath.Join(testStoragePath, "eudi_configuration"), filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)

	conf, err := eudi.NewConfiguration(
		filepath.Join(storageFolder, "eudi_configuration"),
	)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	sdJwtVcVerificationContext := sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &conf.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwtvc.NewJwxJwtVerifier(),
	}

	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdJwtVcVerificationContext)

	client := NewOpenID4VciClient(&http.Client{}, conf, storage, holderVerifier, keyBinder)
	client.AllowInsecureHttpForTesting()

	return client
}

func TestOpenID4VciClient(t *testing.T) {
	var issuerBaseUrl string
	issuerTestServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/openid-credential-issuer") {
			w.Header().Add("Content-Type", "application/json")
			_, _ = w.Write([]byte(testdata.GetWellKnownConfigurationUrl(issuerBaseUrl)))
			return
		}
	}))
	defer issuerTestServer.Close()

	issuerBaseUrl = issuerTestServer.URL

	t.Run("issuing a credential successfully", func(t *testing.T) {
		testIssuingCredential_Success(t, testdata.GetCredentialOfferEndpointUrl(issuerBaseUrl))
	})
}

func testIssuingCredential_Success(t *testing.T, credentialOfferEndpointUrl string) {
	client := createOpenID4VCiClientForTesting(t)

	handler := newMockSessionHandler(t)
	client.NewSession(credentialOfferEndpointUrl, handler)

	authCodeRequestHandler := handler.AwaitAuthCodeRequest()

	permissionGranted := true
	authCodeRequestHandler(permissionGranted, "test-code", nil)
	success := handler.AwaitSessionEnd()

	require.True(t, success)
}

func addTestCredentialsToStorage(t *testing.T, storage irmaclient.SdJwtVcStorage, keyBinder sdjwtvc.KeyBinder) {
	// ignoring all errors here, since it's not production code anyway
	mobilephoneInfo, mobilephoneEntry := createMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, "test.test.mobilephone", "https://openid4vc.staging.yivi.app",
		map[string]string{
			"mobilephone": "+31612345678",
		}, 1,
	)
	require.NoError(t, storage.StoreCredential(mobilephoneInfo, mobilephoneEntry))

	emailInfo, emailSdjwts := createMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]string{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	}, 1)
	require.NoError(t, storage.StoreCredential(emailInfo, emailSdjwts))

	emailInfo2, emailSdjwt2 := createMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]string{
		"email":  "yivi@gmail.com",
		"domain": "gmail.com",
	}, 2)
	require.NoError(t, storage.StoreCredential(emailInfo2, emailSdjwt2))
}

func createMultipleSdJwtVcsWithCustomKeyBinder[T sdjwtvc.LeafClaimDataType](
	t *testing.T, keyBinder sdjwtvc.KeyBinder, vct string, issuer string, claims map[string]T, num uint,
) (irmaclient.SdJwtVcBatchMetadata, []sdjwtvc.SdJwtVc) {
	result := make([]sdjwtvc.SdJwtVc, num)

	chain := testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes
	certChain, err := utils.ParsePemCertificateChainToX5cFormat(chain)
	if err != nil {
		panic(err)
	}

	for i := range num {
		sdjwt, err := createTestSdJwtVc(keyBinder, vct, issuer, claims, certChain)
		require.NoError(t, err)
		result[i] = sdjwt
	}

	// Convert to SdJwtVcKb since the holder doesn't know if a Key Binding JWT is present or not
	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdjwtvc.CreateDefaultVerificationContext(chain))
	info, _, err := createCredentialInfoAndVerifiedSdJwtVc(sdjwtvc.SdJwtVcKb(result[0]), holderVerifier, eudi.StrictSdJwtVerificationMode)
	require.NoError(t, err)
	return irmaclient.SdJwtVcBatchMetadata{
		BatchSize:              num,
		RemainingInstanceCount: num,
		SignedOn:               info.SignedOn,
		Expires:                info.Expires,
		Attributes:             info.Attributes,
		Hash:                   info.Hash,
		CredentialType:         info.CredentialType,
	}, result
}

func createTestSdJwtVc[T sdjwtvc.LeafClaimDataType](keyBinder sdjwtvc.KeyBinder, vct, issuerUrl string, claims map[string]T, x5c []string) (sdjwtvc.SdJwtVc, error) {
	holderKey, err := keyBinder.CreateKeyPairs(1)
	if err != nil {
		return "", fmt.Errorf("failed to create holder keys: %v", err)
	}

	return createTestSdJwtVcWithHolderKey(vct, issuerUrl, claims, x5c, holderKey[0])
}

func createTestSdJwtVcWithHolderKey[T sdjwtvc.LeafClaimDataType](vct, issuerUrl string, claims map[string]T, x5c []string, cnfHolderHey jwk.Key) (sdjwtvc.SdJwtVc, error) {
	holderKeyClaim, err := sdjwtvc.HolderKeyClaim(cnfHolderHey)
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

func createCredentialInfoAndVerifiedSdJwtVc(
	sdJwt sdjwtvc.SdJwtVcKb,
	holderVerifier *sdjwtvc.HolderVerificationProcessor,
	mode eudi.SdJwtVerificationMode,
) (*irmaclient.SdJwtVcMetadata, *sdjwtvc.VerifiedSdJwtVc, error) {
	verifiedSdJwtVc, err := holderVerifier.ParseAndVerifySdJwtVc(sdJwt)

	if err != nil {
		return nil, nil, err
	}

	attributes := map[string]any{}

	for key, value := range verifiedSdJwtVc.Claims.Object {
		if value.Type != sdjwtvc.Claim_String {
			//return nil, nil, fmt.Errorf("attribute value not a string: %v %v", key, value.Type)
			irma.Logger.Infof("attribute value not a string, skipping attribute: %v %v", key, value.Type)
			continue
		}
		valStr, ok := value.Value.(string)
		if !ok {
			return nil, nil, fmt.Errorf("attribute value not a string: %v", key)
		}
		attributes[key] = valStr
	}

	hash, err := irmaclient.CreateHashForSdJwtVc(verifiedSdJwtVc.VerifiableCredentialType, attributes)
	if err != nil {
		return nil, nil, err
	}

	if mode == eudi.StrictSdJwtVerificationMode {
		idComponents := strings.Split(verifiedSdJwtVc.VerifiableCredentialType, ".")
		if num := len(idComponents); num != 3 {
			return nil, nil, fmt.Errorf(
				"credential id expected to have exactly 3 components, separated by dots: %s",
				verifiedSdJwtVc.VerifiableCredentialType,
			)
		}
	}

	info := irmaclient.SdJwtVcMetadata{
		Hash:           hash,
		CredentialType: verifiedSdJwtVc.VerifiableCredentialType,
		SignedOn: irma.Timestamp(
			time.Unix(verifiedSdJwtVc.IssuedAt, 0),
		),
		Expires: irma.Timestamp(
			time.Unix(verifiedSdJwtVc.Expiry, 0),
		),
		Attributes: attributes,
	}

	return &info, verifiedSdJwtVc, nil
}
