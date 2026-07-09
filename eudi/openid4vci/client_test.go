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
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func createOpenID4VCiClientForTesting(t *testing.T) (storage.Storage, *Client) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	sdJwtStorage, err := irmaclient.NewInMemorySdJwtVcStorage()
	require.NoError(t, err)

	addTestCredentialsToStorage(t, sdJwtStorage, keyBinder)

	storageFolder := test.CreateTestStorage(t)
	testStoragePath := test.FindTestdataFolder(t)
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")
	err = common.CopyDirectory(filepath.Join(testStoragePath, "eudi"), eudiAppDataPath)
	require.NoError(t, err)

	s, err := storage.NewStorage(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	conf, err := eudi.NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	sdJwtVcVerificationContext := sdjwtvc.SdJwtVcVerificationContext{
		X509VerificationContext: &conf.Issuers,
		Clock:                   eudi_jwt.NewSystemClock(),
		JwtVerifier:             sdjwtvc.NewJwxJwtVerifier(),
	}

	holderVerifier := sdjwtvc.NewHolderVerificationProcessor(sdJwtVcVerificationContext)

	credentialService := services.NewCredentialService(
		db.NewCredentialStore(s.Db()),
		db.NewHolderBindingKeyStore(s.Db()),
		s.FileSystem(),
	)
	client, err := NewClient(&http.Client{}, conf, holderVerifier, credentialService)
	require.NoError(t, err)
	client.AllowInsecureHttpForTesting()

	return s, client
}

func TestOpenID4VciClient(t *testing.T) {
	// TODO: The test server mock needs to handle additional endpoints (OAuth authorization server
	// metadata, token exchange, credential request) before this test can work end-to-end.
	t.Skip("test server mock is incomplete: only handles well-known endpoint")

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
	storage, client := createOpenID4VCiClientForTesting(t)

	handler := newMockSessionHandler(t)
	client.NewSession(1, credentialOfferEndpointUrl, "https://open.yivi.app/-/auth-callback", handler)

	authCodeRequest := handler.AwaitAuthCodeRequest()

	permissionGranted := true
	// Build the callback URL a compliant authorization server would redirect to,
	// echoing back the state the grant handler generated.
	callbackURL := "https://open.yivi.app/-/auth-callback?code=test-code&state=" + authCodeRequest.state
	authCodeRequest.callback(permissionGranted, &callbackURL)
	success := handler.AwaitSessionEnd()

	require.True(t, success)

	storage.Close()
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

// TODO: this func becomes irrelevant once we have our own metadata storage (and no longer depend on metadata in the IrmaClient)
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
	for _, d := range verifiedSdJwtVc.Disclosures {
		attributes[d.Key] = d.Value
	}

	hash, err := irmaclient.CreateHashForSdJwtVc(verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType, attributes)
	if err != nil {
		return nil, nil, err
	}

	if mode == eudi.StrictSdJwtVerificationMode {
		idComponents := strings.Split(verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType, ".")
		if num := len(idComponents); num != 3 {
			return nil, nil, fmt.Errorf(
				"credential id expected to have exactly 3 components, separated by dots: %s",
				verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType,
			)
		}
	}

	info := irmaclient.SdJwtVcMetadata{
		Hash:           hash,
		CredentialType: verifiedSdJwtVc.IssuerSignedJwtPayload.VerifiableCredentialType,
		Attributes:     attributes,
	}

	if verifiedSdJwtVc.IssuerSignedJwtPayload.IssuedAt != nil {
		signedOn := irma.Timestamp(
			time.Unix(*verifiedSdJwtVc.IssuerSignedJwtPayload.IssuedAt, 0),
		)
		info.SignedOn = &signedOn
	}

	if verifiedSdJwtVc.IssuerSignedJwtPayload.Expiry != nil {
		expires := irma.Timestamp(
			time.Unix(*verifiedSdJwtVc.IssuerSignedJwtPayload.Expiry, 0),
		)
		info.Expires = &expires
	}

	return &info, verifiedSdJwtVc, nil
}
