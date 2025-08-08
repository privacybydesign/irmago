package irmaclient

import (
	"bytes"
	"encoding/json"
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

	addTestCredentialsToStorage(storage, keyBinder)

	storageFolder := test.CreateTestStorage(t)
	testStoragePath := test.FindTestdataFolder(t)
	err = common.CopyDirectory(filepath.Join(testStoragePath, "eudi_configuration"), filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)

	conf, err := eudi.NewConfiguration(
		filepath.Join(storageFolder, "eudi_configuration"),
	)
	require.NoError(t, err)

	verifierValidator := eudi.NewRequestorCertificateStoreVerifierValidator(&conf.Verifiers)
	client, err := NewOpenID4VPClient(conf, storage, verifierValidator, keyBinder, &InMemoryLogsStorage{})
	require.NoError(t, err)
	return client
}

func TestOpenID4VPClient(t *testing.T) {
	t.Run("disclosing two credentials successfully", testDisclosingTwoCredentials_Success)
}

func testDisclosingTwoCredentials_Success(t *testing.T) {
	url, err := startSessionAtEudiVerifier()
	require.NoError(t, err)

	client := createOpenID4VPClientForTesting(t)

	handler := NewMockSessionHandler(t)
	client.NewSession(url, handler)

	permissionRequest := handler.AwaitPermissionRequest()

	choice := &irma.DisclosureChoice{
		Attributes: [][]*irma.AttributeIdentifier{
			{
				&irma.AttributeIdentifier{
					Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.email.email"),
					CredentialHash: "2gLLz0ZpYXXW6-I1jZ3wBEggQ5eR7KKbdIvJLm5O8y8",
				},
			},
			{
				&irma.AttributeIdentifier{
					Type:           irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.mobilenumber.mobilenumber"),
					CredentialHash: "igACXd9kCRN7ypJ8iUS2c3UQ62S-Opjz0LCariGhQ_w",
				},
			},
		},
	}
	proceed := true
	permissionRequest.PermissionHandler(proceed, choice)
	success := handler.AwaitSessionEnd()

	require.True(t, success)
}

func startSessionAtEudiVerifier() (string, error) {
	response, err := http.Post("http://127.0.0.1:8089/ui/presentations",
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
