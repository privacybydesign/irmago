package sessiontest

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestEudiClient(t *testing.T) {
	t.Run("session logs", testSessionLogs)

	t.Run("idemix and sdjwtvc combined issuance over irma", testIdemixAndSdJwtCombinedIssuance)
	t.Run("disclose single sdjwtvc over openid4vp", testDiscloseOverOpenID4VP)
	t.Run("idemix and sdjwtvc show up as single credential info", testIdemixAndSdJwtShowUpAsSingleCredentialInfo)
	t.Run("deleting combined credential deletes both formats", testDeletingCombinedCredentialDeletesBothFormats)
}

func testSessionLogs(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled())
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	logs, err := client.LoadNewestLogs(100)

	require.NoError(t, err)

	// only keyshare enrollment log should be there
	require.Len(t, logs, 1)

	issueSdJwtAndIdemixToClient(t, client, irmaServer)

	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 2)

	// credential with sdjwt included
	requireIrmaSdJwtIssuanceLog(t, logs[0])

	// keyshare attribute (no sdjwt included)
	requireRegularIrmaIssuanceLog(t, logs[1])

	discloseOverOpenID4VP(t, client)
	logs, err = client.LoadNewestLogs(100)
	require.NoError(t, err)

	require.Len(t, logs, 3)
	requireOpenID4VPLog(t, logs[0])
}

func requireOpenID4VPLog(t *testing.T, log irmaclient.LogInfo) {
	require.Equal(t, log.Type, irmaclient.LogType_Disclosure)
	require.NotNil(t, log.DisclosureLog)
	require.Len(t, log.DisclosureLog.Credentials, 1)
	require.Equal(t, log.DisclosureLog.Protocol, irmaclient.Protocol_OpenID4VP)

	cred := log.DisclosureLog.Credentials[0]
	require.Equal(t, cred.Formats, []irmaclient.CredentialFormat{irmaclient.Format_SdJwtVc})
}

func requireRegularIrmaIssuanceLog(t *testing.T, log irmaclient.LogInfo) {
	require.Equal(t, log.Type, irmaclient.LogType_Issuance)
	require.Equal(t, log.IssuanceLog.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, log.IssuanceLog.Credentials[0].Formats, []irmaclient.CredentialFormat{irmaclient.Format_Idemix})
}

func requireIrmaSdJwtIssuanceLog(t *testing.T, log irmaclient.LogInfo) {
	require.Equal(t, log.Type, irmaclient.LogType_Issuance)
	require.Equal(t, log.IssuanceLog.Protocol, irmaclient.Protocol_Irma)

	require.Len(t, log.IssuanceLog.Credentials, 1)

	cred := log.IssuanceLog.Credentials[0]
	require.Contains(t, cred.Formats, irmaclient.Format_SdJwtVc)
	require.Contains(t, cred.Formats, irmaclient.Format_Idemix)
}

func testDeletingCombinedCredentialDeletesBothFormats(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled())
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	issueSdJwtAndIdemixToClient(t, client, irmaServer)

	credentialInfoList := client.CredentialInfoList()
	require.Len(t, credentialInfoList, 2)

	sort.Stable(credentialInfoList)
	emailCred := credentialInfoList[1]

	require.NoError(t, client.RemoveCredentialByHash(emailCred.Hash))

	credentialInfoList = client.CredentialInfoList()
	require.Len(t, credentialInfoList, 1)
}

func testIdemixAndSdJwtShowUpAsSingleCredentialInfo(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled())
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	issueSdJwtAndIdemixToClient(t, client, irmaServer)

	credentialInfoList := client.CredentialInfoList()
	require.Len(t, credentialInfoList, 2)

	sort.Stable(credentialInfoList)
	emailCred := credentialInfoList[1]

	require.Equal(t, emailCred.Identifier().String(), irma.NewCredentialTypeIdentifier("test.test.email").String())
	require.Contains(t, emailCred.CredentialFormats, "idemix")
	require.Contains(t, emailCred.CredentialFormats, "dc+sd-jwt")
}

func testIdemixAndSdJwtCombinedIssuance(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled())
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	issueSdJwtAndIdemixToClient(t, client, irmaServer)
}

func testDiscloseOverOpenID4VP(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled())
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	issueSdJwtAndIdemixToClient(t, client, irmaServer)
	discloseOverOpenID4VP(t, client)
}

func discloseOverOpenID4VP(t *testing.T, client *irmaclient.Client) {
	sessionLink, err := irmaclient.StartTestSessionAtEudiVerifier(createAuthRequestRequest())
	require.NoError(t, err)
	session := irmaclient.SessionRequestData{
		Qr: irma.Qr{
			Type: irma.ActionDisclosing,
			URL:  sessionLink,
		},
		Protocol: "openid4vp",
	}
	sessionJson, err := json.Marshal(session)
	require.NoError(t, err)

	sessionHandler := irmaclient.NewMockSessionHandler(t)
	client.NewSession(string(sessionJson), sessionHandler)

	permissionRequest := sessionHandler.AwaitPermissionRequest()

	proceed := true
	permissionRequest.PermissionHandler(proceed, &irma.DisclosureChoice{
		Attributes: [][]*irma.AttributeIdentifier{
			{
				permissionRequest.Candidates[0][0][0].AttributeIdentifier,
			},
		},
	})

	require.True(t, sessionHandler.AwaitSessionEnd())
}

func issueSdJwtAndIdemixToClient(t *testing.T, client *irmaclient.Client, irmaServer *IrmaServer) {
	sessionRequestJson := startCombinedIssuanceSessionAtServer(t, irmaServer)

	sessionHandler := irmaclient.NewMockSessionHandler(t)
	client.NewSession(sessionRequestJson, sessionHandler)
	details := sessionHandler.AwaitPermissionRequest()
	details.PermissionHandler(true, nil)

	require.True(t, sessionHandler.AwaitSessionEnd())
}

func startCombinedIssuanceSessionAtServer(t *testing.T, server *IrmaServer) string {
	issuanceRequest := createIssuanceRequest()
	qr, _, _, err := server.irma.StartSession(issuanceRequest, nil, "")
	require.NoError(t, err)

	session := irmaclient.SessionRequestData{
		Qr:       *qr,
		Protocol: "irma",
	}
	sessionJson, err := json.Marshal(session)
	require.NoError(t, err)
	return string(sessionJson)
}

func createIssuanceRequest() *irma.IssuanceRequest {
	var sdJwtBatchSize uint = 10
	req := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.email"),
			Attributes: map[string]string{
				"email": "test@gmail.com",
			},
			SdJwtBatchSize: &sdJwtBatchSize,
		},
	})
	req.RequestSdJwts = true
	return req
}

func createClient(t *testing.T) *irmaclient.Client {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")

	clientHandler := irmaclient.NewMockClientHandler()
	client, err := irmaclient.New(storagePath, irmaConfigurationPath, clientHandler, test.NewSigner(t), aesKey)
	require.NoError(t, err)

	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")

	require.NoError(t, clientHandler.AwaitEnrollmentResult())

	return client
}

func createAuthRequestRequest() string {
	return fmt.Sprintf(`
		{
		  "type": "vp_token",  
		  "dcql_query": {
			"credentials": [
			  {
				"id": "32f54163-7166-48f1-93d8-ff217bdb0653",
				"format": "dc+sd-jwt",
				"meta": {
					"vct_values": ["test.test.email"]
				},
				"claims": [
				  {
					"path": ["email"]
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

func irmaServerConfWithSdJwtEnabled() *server.Configuration {
	conf := IrmaServerConfiguration()
	conf.SdJwtIssuanceSettings = &server.SdJwtIssuanceSettings{
		Issuer:                 "https://openid4vc.staging.yivi.app",
		IssuerCertificateChain: string(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		JwtPrivateKey:          string(testdata.IssuerPrivKeyBytes),
	}
	return conf
}
