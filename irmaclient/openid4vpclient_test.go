package irmaclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func createOpenID4VPClientForTesting(t *testing.T) *OpenID4VPClient {
	keyBinder := sdjwtvc.NewDefaultKeyBinderWithInMemoryStorage()
	storage, err := NewInMemorySdJwtVcStorage()
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

	verifierValidator := eudi.NewRequestorCertificateStoreVerifierValidator(&conf.Verifiers, &eudi.MockQueryValidatorFactory{})
	client, err := NewOpenID4VPClient(conf, storage, verifierValidator, keyBinder, &InMemoryLogsStorage{})
	require.NoError(t, err)
	return client
}

func TestOpenID4VPClient(t *testing.T) {
	t.Run("disclosing two credentials successfully", func(t *testing.T) {
		testDisclosingTwoCredentials_Success(t, testdata.OpenID4VP_DirectPost_Host)
		testDisclosingTwoCredentials_Success(t, testdata.OpenID4VP_DirectPostJwt_Host)
	})
}

func testDisclosingTwoCredentials_Success(t *testing.T, verifierHost string) {
	url, err := startSessionAtEudiVerifier(verifierHost)
	require.NoError(t, err)

	client := createOpenID4VPClientForTesting(t)

	handler := NewMockSessionHandler(t)
	client.NewSession(url, handler)

	permissionRequest := handler.AwaitPermissionRequest()

	email, err := permissionRequest.Candidates[0][0].Choose()
	require.NoError(t, err)

	phone, err := permissionRequest.Candidates[1][0].Choose()
	require.NoError(t, err)

	choice := &irma.DisclosureChoice{
		Attributes: [][]*irma.AttributeIdentifier{
			email, phone,
		},
	}
	proceed := true
	permissionRequest.PermissionHandler(proceed, choice)
	success := handler.AwaitSessionEnd()

	require.True(t, success)
}

func startSessionAtEudiVerifier(verifierHost string) (string, error) {
	apiUrl := fmt.Sprintf("%s/ui/presentations", verifierHost)
	response, err := http.Post(apiUrl,
		"application/json",
		bytes.NewReader([]byte(testdata.CreateTestAuthorizationRequestRequest(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes))))

	if err != nil {
		return "", err
	}

	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)

	if err != nil {
		return "", err
	}

	var requestRequest map[string]string

	err = json.Unmarshal(body, &requestRequest)
	if err != nil {
		return "", err
	}

	queryParams := url.Values{}

	for key, value := range requestRequest {
		queryParams.Add(key, value)
	}

	url := url.URL{
		Scheme:   "eudi-openid4vp://",
		RawQuery: queryParams.Encode(),
	}

	return url.String(), nil
}

func addTestCredentialsToStorage(t *testing.T, storage SdJwtVcStorage, keyBinder sdjwtvc.KeyBinder) {
	// ignoring all errors here, since it's not production code anyway
	mobilephoneInfo, mobilephoneEntry := createMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, "test.test.mobilephone", "https://openid4vc.staging.yivi.app",
		map[string]any{
			"mobilephone": "+31612345678",
		}, 1,
	)
	require.NoError(t, storage.StoreCredential(mobilephoneInfo, mobilephoneEntry))

	emailInfo, emailSdjwts := createMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "test@gmail.com",
		"domain": "gmail.com",
	}, 1)
	require.NoError(t, storage.StoreCredential(emailInfo, emailSdjwts))

	emailInfo2, emailSdjwt2 := createMultipleSdJwtVcsWithCustomKeyBinder(t, keyBinder, "test.test.email", "https://openid4vc.staging.yivi.app", map[string]any{
		"email":  "yivi@gmail.com",
		"domain": "gmail.com",
	}, 2)
	require.NoError(t, storage.StoreCredential(emailInfo2, emailSdjwt2))
}
