package irmaclient

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func createOpenID4VCiClientForTesting(t *testing.T) *OpenID4VciClient {
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

	sdJwtVcVerificationContext := sdjwtvc.SdJwtVcVerificationContext{
		VerificationContext: &conf.Issuers,
		Clock:               sdjwtvc.NewSystemClock(),
		JwtVerifier:         sdjwtvc.NewJwxJwtVerifier(),
	}

	client := NewOpenID4VciClient(&http.Client{}, conf, storage, sdJwtVcVerificationContext, keyBinder)
	client.AllowInsecureHttpForTesting()

	return client
}

func TestOpenID4VciClient(t *testing.T) {
	// TODO: further implement mock
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

	t.Run("issuing two credentials successfully", func(t *testing.T) {
		testIssuingTwoCredentials_Success(t, testdata.GetCredentialOfferEndpointUrl(issuerBaseUrl))
	})
}

func testIssuingTwoCredentials_Success(t *testing.T, credentialOfferEndpointUrl string) {
	client := createOpenID4VCiClientForTesting(t)

	handler := NewMockSessionHandler(t)
	client.NewSession(credentialOfferEndpointUrl, handler)

	authCodeRequestHandler := handler.AwaitAuthCodeRequest()

	permissionGranted := true
	authCodeRequestHandler(permissionGranted, "test-code")
	success := handler.AwaitSessionEnd()

	require.True(t, success)
}
