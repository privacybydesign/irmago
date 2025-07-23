package irmaclient

import (
	"fmt"
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

	storageFolder := test.SetupTestStorage(t)
	testStoragePath := test.FindTestdataFolder(t)
	err = common.CopyDirectory(filepath.Join(testStoragePath, "eudi_configuration"), filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)

	conf, err := eudi.NewConfiguration(
		filepath.Join(storageFolder, "eudi_configuration"),
	)
	require.NoError(t, err)
	err = conf.ParseFolder()
	require.NoError(t, err)

	verifierValidator := NewRequestorCertificateStoreVerifierValidator(conf.Verifiers.GetRootCerts(), conf.Verifiers.GetIntermediateCerts())
	client, err := NewOpenID4VPClient(conf, storage, verifierValidator, keyBinder, &InMemoryLogsStorage{})
	require.NoError(t, err)
	return client
}

func TestOpenID4VPClient(t *testing.T) {
	t.Run("disclosing two credentials successfully", testDisclosingTwoCredentials_Success)
}

func testDisclosingTwoCredentials_Success(t *testing.T) {
	url, err := StartTestSessionAtEudiVerifier(createAuthorizationRequestRequest())
	require.NoError(t, err)

	client := createOpenID4VPClientForTesting(t)
	defer test.ClearAllTestStorage()

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

func createAuthorizationRequestRequest() string {
	return fmt.Sprintf(`
{
  "type": "vp_token",  
  "dcql_query": {
    "credentials": [
      {
        "id": "32f54163-7166-48f1-93d8-ff217bdb0653",
        "format": "dc+sd-jwt",
        "meta": {
			"vct_values": ["pbdf.sidn-pbdf.email"]
        },
        "claims": [
          {
			"path": ["email"]
          }
        ]
      },
      {
        "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
        "format": "dc+sd-jwt",
        "meta": {
			"vct_values": ["pbdf.sidn-pbdf.mobilenumber"]
        },
        "claims": [
          {
			"path": ["mobilenumber"]
          }
        ]
      }
    ]
  },
  "nonce": "nonce",
  "jar_mode": "by_reference",
  "request_uri_method": "post",
  "issuer_chain": "%s"
}
`,
		string(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
	)
}
