package sessiontest

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestEudiClient(t *testing.T) {
	t.Run("double sdjwt issuance replaces instances", testDoubleSdJwtIssuanceReplacesInstances)
	t.Run("credential instance count", testCredentialInstanceCount)
	t.Run("test logs for combined issuance and disclosure", testLogsForCombinedIssuanceAndDisclosure)

	t.Run("test logs for completely optional disclosure", testLogsForCompletelyOptionalDisclosure)
	t.Run("remove storage empty client", testRemoveStorageEmptyClient)
	t.Run("remove storage with only idemix credentials", testRemoveStorageWithOnlyIdemixCredentials)

	t.Run("irma disclosure session logs", testIrmaDisclosureSessionLogs)
	t.Run("signature session logs", testIrmaSignatureSessionLogs)
	t.Run("eudi session logs", testEudiSessionLogs)

	t.Run("idemix only credential removal log", testIdemixOnlyCredentialRemovalLog)
	t.Run("idemix and sdjwt combined credential removal log", testIdemixAndSdJwtCombinedRemovalLog)

	t.Run("idemix and sdjwtvc combined issuance over irma", testIdemixAndSdJwtCombinedIssuance)
	t.Run("disclose single sdjwtvc over openid4vp", testDiscloseOverOpenID4VP)
	t.Run("idemix and sdjwtvc show up as single credential info", testIdemixAndSdJwtShowUpAsSeparateCredentialInfos)
	t.Run("deleting combined credential deletes both formats", testDeletingCombinedCredentialDeletesBothFormats)
}

func testDoubleSdJwtIssuanceReplacesInstances(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueSdJwtAndIdemixToClient(t, client, irmaServer)

	info := client.CredentialInfoList()
	require.Len(t, info, 3)

	creds := collectCredentialsWithId(info, "test.test.email")
	require.Len(t, creds, 2)

	cred := getCredWithFormat(creds, irmaclient.Format_SdJwtVc)

	require.Equal(t, 10, int(*cred.InstanceCount))

	issueSdJwtAndIdemixToClient(t, client, irmaServer)

	info = client.CredentialInfoList()
	require.Len(t, info, 3)

	creds = collectCredentialsWithId(info, "test.test.email")
	require.Len(t, creds, 2)

	cred = getCredWithFormat(creds, irmaclient.Format_SdJwtVc)

	require.Equal(t, 10, int(*cred.InstanceCount))
}

func testCredentialInstanceCount(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueSdJwtAndIdemixToClient(t, client, irmaServer)

	info := client.CredentialInfoList()
	require.Len(t, info, 3)

	creds := collectCredentialsWithId(info, "test.test.email")
	require.Len(t, creds, 2)

	cred := getCredWithFormat(creds, irmaclient.Format_SdJwtVc)

	numInstances := uint(10)

	require.Equal(t, numInstances, *cred.InstanceCount)

	for i := range numInstances {
		discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPost_Host)

		info = client.CredentialInfoList()
		require.Len(t, info, 3)

		creds = collectCredentialsWithId(info, "test.test.email")
		require.Len(t, creds, 2)

		cred = getCredWithFormat(creds, irmaclient.Format_SdJwtVc)
		require.Equal(t, numInstances-1-i, *cred.InstanceCount)
	}
}

func getCredWithFormat(creds []*irma.CredentialInfo, format irmaclient.CredentialFormat) *irma.CredentialInfo {
	return creds[slices.IndexFunc(creds, func(c *irma.CredentialInfo) bool {
		return irmaclient.CredentialFormat(c.CredentialFormat) == format
	})]
}

func testLogsForCombinedIssuanceAndDisclosure(t *testing.T) {
	conf := IrmaServerConfigurationWithTempStorage(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	performCombinedIssuanceAndDisclosureSession(t, client, irmaServer)

	logs, err := client.LoadNewestLogs(20)
	require.NoError(t, err)

	latestLog := logs[0]

	require.Equal(t, latestLog.Type, irmaclient.LogType_Issuance)
	require.Equal(t, latestLog.IssuanceLog.Protocol, irmaclient.Protocol_Irma)
	require.Len(t, latestLog.IssuanceLog.DisclosedCredentials, 2)
	require.Len(t, latestLog.IssuanceLog.Credentials, 1)
}

func performCombinedIssuanceAndDisclosureSession(t *testing.T, client *irmaclient.Client, irmaServer *IrmaServer) {
	regularIssuanceRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Barry",
				"firstname":  "",
				"familyname": "Batsbak",
			},
		},
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.singleton"),
			Attributes: map[string]string{
				"BSN": "1234",
			},
		},
	})

	performIrmaIssuanceSession(t, client, irmaServer, regularIssuanceRequest)

	combinedIssuanceRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test2.email"),
			Attributes: map[string]string{
				"email": "two@gmail.com",
			},
		},
	})
	combinedIssuanceRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN"),
			},
		},
	}

	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, combinedIssuanceRequest)

	sessionHandler := irmaclient.NewMockSessionHandler(t)
	client.NewSession(sessionRequestJson, sessionHandler)

	details := sessionHandler.AwaitPermissionRequest()
	details.PermissionHandler(true,
		&irma.DisclosureChoice{
			Attributes: [][]*irma.AttributeIdentifier{
				{
					details.Candidates[0][0][0].AttributeIdentifier,
					details.Candidates[0][0][1].AttributeIdentifier,
				},
			},
		})

	require.True(t, sessionHandler.AwaitSessionEnd())
}

func testLogsForCompletelyOptionalDisclosure(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	performCompletelyOptionalDisclosure(t, client, irmaServer)

	logs, err := client.LoadNewestLogs(10)
	require.NoError(t, err)

	latestLog := logs[0]

	require.Equal(t, latestLog.Type, irmaclient.LogType_Disclosure)
	require.Empty(t, latestLog.DisclosureLog.Credentials)
	require.Equal(t, latestLog.DisclosureLog.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, latestLog.DisclosureLog.Verifier.ID, irma.NewRequestorIdentifier("test-requestors.test-requestor"))
}

func performCompletelyOptionalDisclosure(t *testing.T, client *irmaclient.Client, irmaServer *IrmaServer) {
	req := irma.NewDisclosureRequest()
	req.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
			irma.AttributeCon{},
		},
	}
	sessionReqJson := startIrmaSessionAtServer(t, irmaServer, req)
	sessionHandler := irmaclient.NewMockSessionHandler(t)
	client.NewSession(sessionReqJson, sessionHandler)

	permissionRequest := sessionHandler.AwaitPermissionRequest()

	choice := [][]*irma.AttributeIdentifier{
		{},
	}

	permissionRequest.PermissionHandler(true, &irma.DisclosureChoice{Attributes: choice})
	require.True(t, sessionHandler.AwaitSessionEnd())
}

func testRemoveStorageWithOnlyIdemixCredentials(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueIdemixOnlyToClient(t, client, irmaServer)

	require.NoError(t, client.RemoveStorage())
}

func testRemoveStorageEmptyClient(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	require.NoError(t, client.RemoveStorage())
}

func testIdemixAndSdJwtCombinedRemovalLog(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueSdJwtAndIdemixToClient(t, client, irmaServer)

	credentials := client.CredentialInfoList()
	emailCreds := collectCredentialsWithId(credentials, "test.test.email")

	require.NoError(t, client.RemoveCredentialsByHash(hashByFormat(emailCreds)))

	logs, err := client.LoadNewestLogs(100)
	require.NoError(t, err)

	requireIdemixAndSdJwtCredentialRemovalLog(t, logs[0])
}

func testIdemixOnlyCredentialRemovalLog(t *testing.T) {
	conf := IrmaServerConfigurationWithTempStorage(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueIdemixOnlyToClient(t, client, irmaServer)

	credentials := client.CredentialInfoList()
	emailCreds := collectCredentialsWithId(credentials, "test.test.email")

	require.NoError(t, client.RemoveCredentialsByHash(hashByFormat(emailCreds)))

	logs, err := client.LoadNewestLogs(100)
	require.NoError(t, err)

	requireIdemixOnlyCredentialRemovalLog(t, logs[0])
}

func requireIdemixAndSdJwtCredentialRemovalLog(t *testing.T, log irmaclient.LogInfo) {
	require.Equal(t, log.Type, irmaclient.LogType_CredentialRemoval)

	credLog := log.RemovalLog.Credentials[0]

	require.Equal(t, credLog.CredentialType, "test.test.email")
	require.Contains(t, credLog.Formats, irmaclient.Format_Idemix)
	require.Contains(t, credLog.Formats, irmaclient.Format_SdJwtVc)
	require.Equal(t, credLog.Attributes, map[string]string{
		"email": "test@gmail.com",
	})
}

func requireIdemixOnlyCredentialRemovalLog(t *testing.T, log irmaclient.LogInfo) {
	require.Equal(t, log.Type, irmaclient.LogType_CredentialRemoval)
	require.Equal(t, log.RemovalLog.Credentials, []irmaclient.CredentialLog{
		{
			Formats:        []irmaclient.CredentialFormat{irmaclient.Format_Idemix},
			CredentialType: "test.test.email",
			Attributes: map[string]string{
				"email": "test@gmail.com",
			},
		},
	})
}

func testIrmaDisclosureSessionLogs(t *testing.T) {
	conf := IrmaServerConfigurationWithTempStorage(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueIdemixOnlyToClient(t, client, irmaServer)
	performIrmaDisclosureSession(t, client, irmaServer)

	logs, err := client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 3)

	requireIrmaDisclosureLog(t, logs[0])
}

func testIrmaSignatureSessionLogs(t *testing.T) {
	conf := IrmaServerConfigurationWithTempStorage(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueIdemixOnlyToClient(t, client, irmaServer)
	performIrmaSignatureSession(t, client, irmaServer)

	logs, err := client.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 3)

	requireSignatureLog(t, logs[0])
}

func requireIrmaDisclosureLog(t *testing.T, log irmaclient.LogInfo) {
	require.Equal(t, log.Type, irmaclient.LogType_Disclosure)
	require.Equal(t, log.DisclosureLog.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, log.DisclosureLog.Credentials, []irmaclient.CredentialLog{
		{
			Formats:        []irmaclient.CredentialFormat{irmaclient.Format_Idemix},
			CredentialType: "test.test.email",
			Attributes: map[string]string{
				"email": "test@gmail.com",
			},
		},
	})
}

func requireSignatureLog(t *testing.T, log irmaclient.LogInfo) {
	require.Equal(t, log.Type, irmaclient.LogType_Signature)
	require.Equal(t, log.SignedMessageLog.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, log.SignedMessageLog.Message, "Hello, World!")
	require.Equal(t, log.SignedMessageLog.Credentials, []irmaclient.CredentialLog{
		{
			Formats:        []irmaclient.CredentialFormat{irmaclient.Format_Idemix},
			CredentialType: "test.test.email",
			Attributes: map[string]string{
				"email": "test@gmail.com",
			},
		},
	})
}

func testEudiSessionLogs(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

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

	discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPostJwt_Host)
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

	require.Equal(t, cred.CredentialType, "test.test.email")
	require.Equal(t, cred.Attributes, map[string]string{
		"email": "test@gmail.com",
	})
}

func requireRegularIrmaIssuanceLog(t *testing.T, log irmaclient.LogInfo) {
	require.Equal(t, log.Type, irmaclient.LogType_Issuance)
	require.Equal(t, log.IssuanceLog.Protocol, irmaclient.Protocol_Irma)

	cred := log.IssuanceLog.Credentials[0]
	require.Equal(t, cred.Formats, []irmaclient.CredentialFormat{irmaclient.Format_Idemix})
}

func requireIrmaSdJwtIssuanceLog(t *testing.T, log irmaclient.LogInfo) {
	require.Equal(t, log.Type, irmaclient.LogType_Issuance)
	require.Equal(t, log.IssuanceLog.Protocol, irmaclient.Protocol_Irma)

	require.Len(t, log.IssuanceLog.Credentials, 1)

	cred := log.IssuanceLog.Credentials[0]

	require.Contains(t, cred.Formats, irmaclient.Format_SdJwtVc)
	require.Contains(t, cred.Formats, irmaclient.Format_Idemix)

	require.Equal(t, cred.CredentialType, "test.test.email")
	require.Equal(t, cred.Attributes, map[string]string{
		"email": "test@gmail.com",
	})
}

func testDeletingCombinedCredentialDeletesBothFormats(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueSdJwtAndIdemixToClient(t, client, irmaServer)

	credentialInfoList := client.CredentialInfoList()
	require.Len(t, credentialInfoList, 3)

	emailCreds := collectCredentialsWithId(credentialInfoList, "test.test.email")
	require.Len(t, emailCreds, 2)

	require.NoError(t, client.RemoveCredentialsByHash(hashByFormat(emailCreds)))

	credentialInfoList = client.CredentialInfoList()
	require.Len(t, credentialInfoList, 1)
}

func testIdemixAndSdJwtShowUpAsSeparateCredentialInfos(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueSdJwtAndIdemixToClient(t, client, irmaServer)

	credentialInfoList := client.CredentialInfoList()
	require.Len(t, credentialInfoList, 3)

	emailCreds := collectCredentialsWithId(credentialInfoList, "test.test.email")
	require.Len(t, emailCreds, 2)
}

func testIdemixAndSdJwtCombinedIssuance(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueSdJwtAndIdemixToClient(t, client, irmaServer)
}

func testDiscloseOverOpenID4VP(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client := createClient(t)
	defer client.Close()

	issueSdJwtAndIdemixToClient(t, client, irmaServer)
	discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPost_Host)
	discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPostJwt_Host)
}

func discloseOverOpenID4VP(t *testing.T, client *irmaclient.Client, openid4vpHost string) {
	sessionLink, err := irmaclient.StartTestSessionAtEudiVerifier(openid4vpHost, createAuthRequestRequest())
	require.NoError(t, err)
	session := irmaclient.SessionRequestData{
		Qr: irma.Qr{
			Type: irma.ActionDisclosing,
			URL:  sessionLink,
		},
		Protocol: irmaclient.Protocol_OpenID4VP,
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

func issueIdemixOnlyToClient(t *testing.T, client *irmaclient.Client, irmaServer *IrmaServer) {
	req := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.email"),
			Attributes: map[string]string{
				"email": "test@gmail.com",
			},
		},
	})
	session := startIrmaSessionAtServer(t, irmaServer, req)
	sessionHandler := irmaclient.NewMockSessionHandler(t)

	client.NewSession(session, sessionHandler)
	permissionReq := sessionHandler.AwaitPermissionRequest()

	permissionReq.PermissionHandler(true, nil)
	sessionHandler.AwaitSessionEnd()
}

func issueSdJwtAndIdemixToClient(t *testing.T, client *irmaclient.Client, irmaServer *IrmaServer) {
	sessionReq := createIrmaIssuanceRequestWithSdJwts()
	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, sessionReq)

	sessionHandler := irmaclient.NewMockSessionHandler(t)
	client.NewSession(sessionRequestJson, sessionHandler)
	details := sessionHandler.AwaitPermissionRequest()
	details.PermissionHandler(true, nil)

	require.True(t, sessionHandler.AwaitSessionEnd())
}

func performIrmaIssuanceSession(t *testing.T, client *irmaclient.Client, irmaServer *IrmaServer, request *irma.IssuanceRequest) {
	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, request)

	sessionHandler := irmaclient.NewMockSessionHandler(t)
	client.NewSession(sessionRequestJson, sessionHandler)
	details := sessionHandler.AwaitPermissionRequest()
	details.PermissionHandler(true, nil)

	require.True(t, sessionHandler.AwaitSessionEnd())
}

func performIrmaDisclosureSession(t *testing.T, client *irmaclient.Client, irmaServer *IrmaServer) {
	req := irma.NewDisclosureRequest()
	req.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
	}
	sessionReqJson := startIrmaSessionAtServer(t, irmaServer, req)
	sessionHandler := irmaclient.NewMockSessionHandler(t)
	client.NewSession(sessionReqJson, sessionHandler)

	permissionRequest := sessionHandler.AwaitPermissionRequest()

	choice := [][]*irma.AttributeIdentifier{
		{
			permissionRequest.Candidates[0][0][0].AttributeIdentifier,
		},
	}

	permissionRequest.PermissionHandler(true, &irma.DisclosureChoice{Attributes: choice})
	require.True(t, sessionHandler.AwaitSessionEnd())
}

func performIrmaSignatureSession(t *testing.T, client *irmaclient.Client, irmaServer *IrmaServer) {
	req := irma.NewSignatureRequest("Hello, World!")
	req.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
	}

	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, req)

	sessionHandler := irmaclient.NewMockSessionHandler(t)
	client.NewSession(sessionRequestJson, sessionHandler)

	permissionRequest := sessionHandler.AwaitPermissionRequest()

	choice := [][]*irma.AttributeIdentifier{
		{
			permissionRequest.Candidates[0][0][0].AttributeIdentifier,
		},
	}

	permissionRequest.PermissionHandler(true, &irma.DisclosureChoice{
		Attributes: choice,
	})

	require.True(t, sessionHandler.AwaitSessionEnd())
}

func startIrmaSessionAtServer(t *testing.T, server *IrmaServer, req irma.SessionRequest) string {
	qr, _, _, err := server.irma.StartSession(req, nil, "")
	require.NoError(t, err)
	session := irmaclient.SessionRequestData{
		Qr:       *qr,
		Protocol: irmaclient.Protocol_Irma,
	}
	sessionJson, err := json.Marshal(session)
	require.NoError(t, err)
	return string(sessionJson)
}

func createIrmaIssuanceRequestWithSdJwts() *irma.IssuanceRequest {
	var sdJwtBatchSize uint = 10
	req := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.email"),
			Attributes: map[string]string{
				"email": "test@gmail.com",
			},
			SdJwtBatchSize: sdJwtBatchSize,
		},
	})
	return req
}

func createClient(t *testing.T) *irmaclient.Client {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(storagePath, "irma_configuration")

	// Copy files to storage folder
	require.NoError(t, common.CopyDirectory(filepath.Join(path, "irma_configuration"), filepath.Join(storagePath, "irma_configuration")))
	require.NoError(t, common.CopyDirectory(filepath.Join(path, "eudi_configuration"), filepath.Join(storagePath, "eudi_configuration")))

	// Add test issuer certificates as trusted chain
	certsPath := filepath.Join(storagePath, "eudi_configuration", "issuers", "certs")
	require.NoError(t, common.EnsureDirectoryExists(certsPath))
	require.NoError(t, common.SaveFile(filepath.Join(certsPath, "issuer_cert_openid4vc_staging_yivi_app.pem"), testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes))

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

func irmaServerConfWithSdJwtEnabled(t *testing.T) *server.Configuration {
	conf := IrmaServerConfigurationWithTempStorage(t)
	conf.SdJwtIssuanceSettings = &server.SdJwtIssuanceSettings{
		Issuer:                 "https://openid4vc.staging.yivi.app",
		IssuerCertificateChain: string(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		JwtPrivateKey:          string(testdata.IssuerPrivKeyBytes),
	}
	return conf
}

func collectCredentialsWithId(credentials irma.CredentialInfoList, id string) []*irma.CredentialInfo {
	result := []*irma.CredentialInfo{}
	for _, cred := range credentials {
		if cred.Identifier() == irma.NewCredentialTypeIdentifier(id) {
			result = append(result, cred)
		}
	}
	return result
}

func hashByFormat(credentials []*irma.CredentialInfo) map[irmaclient.CredentialFormat]string {
	result := map[irmaclient.CredentialFormat]string{}
	for _, cred := range credentials {
		result[irmaclient.CredentialFormat(cred.CredentialFormat)] = cred.Hash
	}
	return result
}

func IrmaServerConfigurationWithTempStorage(t *testing.T) *server.Configuration {
	storageFolder := test.SetupTestStorage(t)
	testdataFolder := test.FindTestdataFolder(t)

	// Copy files to storage folder
	_ = common.CopyDirectory(filepath.Join(testdataFolder, "irma_configuration"), filepath.Join(storageFolder, "irma_configuration"))
	_ = common.CopyDirectory(filepath.Join(testdataFolder, "privatekeys"), filepath.Join(storageFolder, "privatekeys"))

	conf := IrmaServerConfiguration()
	conf.SchemesPath = filepath.Join(storageFolder, "irma_configuration")
	conf.IssuerPrivateKeysPath = filepath.Join(storageFolder, "privatekeys")

	return conf
}
