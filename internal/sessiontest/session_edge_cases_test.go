package sessiontest

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

func testSessionHandlerEdgeCases(t *testing.T) {
	runSessionTest(t,
		"keyshare blocked",
		testKeyshareBlocked,
	)

	t.Run("keyshare enrollment missing",
		testKeyshareEnrollmentMissing,
	)

	runSessionTest(t,
		"continue on second device",
		testContinueOnSecondDevice,
	)

	runSessionTest(t,
		"issuance session with pairing code",
		testSessionWithPairingCode,
	)

	runSessionTest(t,
		"errors are correctly propagated",
		testSessionErrorsArePropagated,
	)

	runSessionTest(t,
		"user can dismiss session",
		testUserCanDismissSession,
	)

	runSessionTest(t,
		"user can dismiss session during pin entry",
		testUserCanDismissSessionDuringPinEntry,
	)

	runEudiSessionTest(t,
		"user can dismiss openid4vp session",
		testUserCanDismissOpenID4VPSession,
	)

	runSessionTest(t,
		"chained session",
		testChainedSession,
	)
}

func testKeyshareBlocked(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// make sure we don't have a valid keyshare session
	c.DeleteKeyshareTokens()

	// specifically use the test.test.email since it requires a keyshare session
	sessionJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, createEmailIssuanceRequest())

	c.NewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_Permission,
		Payload: clientmodels.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})

	expectedRemainingAttempts := []*int{nil, intPtr(2), intPtr(1), intPtr(0)}
	for _, expected := range expectedRemainingAttempts {
		session = awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPin)
		require.Equal(t, expected, session.RemainingPinAttempts)

		// enter the wrong pin
		userInteraction(t, c, clientmodels.SessionUserInteraction{
			SessionId: session.Id,
			Type:      clientmodels.UI_EnteredPin,
			Payload: clientmodels.PinInteractionPayload{
				Proceed: true,
				Pin:     "54321",
			},
		})
	}

	session = awaitSessionState(t, sessionHandler)

	// after 3 attempts we expect a pin request with a non-zero block duration (in seconds)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPin)
	require.Nil(t, session.Error)
	require.NotNil(t, session.PinBlockedTimeSeconds)
	require.Equal(t, 1, *session.PinBlockedTimeSeconds)
}

func testKeyshareEnrollmentMissing(
	t *testing.T,
) {
	conf := IrmaServerConfigurationWithTempStorage(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// specifically use test.test.email because it requires a keyshare server session (irma-demo doesn't)
	sessionJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, createEmailIssuanceRequest())
	c.NewSession(sessionJson)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Type, clientmodels.Type_Issuance)
	require.Equal(t, session.Status, clientmodels.Status_Error)
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError, "keyshare enrollment is missing for scheme: 'test'")
}

func testContinueOnSecondDevice(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := createEmailIssuanceRequest()
	sesionJson := startCrossDeviceIrmaSessionAtServer(t, irmaServer, request)
	c.NewSession(sesionJson)
	session := awaitSessionState(t, sessionHandler)
	require.True(t, session.ContinueOnSecondDevice)
}

func testSessionWithPairingCode(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	qr, requestorToken, _, err := irmaServer.irma.StartSession(createEmailIssuanceRequest(), nil, "")
	require.NoError(t, err)
	sessionReq := client.SessionRequestData{
		Qr:       *qr,
		Protocol: clientmodels.Protocol_Irma,
	}
	sessionJson, err := json.Marshal(sessionReq)
	require.NoError(t, err)

	frontendOptions := irma.NewFrontendOptionsRequest()
	frontendOptions.PairingMethod = "pin"
	irmaServer.irma.SetFrontendOptions(requestorToken, &frontendOptions)

	c.NewSession(string(sessionJson))

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_ShowPairingCode)
	require.Len(t, session.PairingCode, 4)
	require.False(t, session.ContinueOnSecondDevice)

	// pretend the pairing was completed
	irmaServer.irma.PairingCompleted(requestorToken)

	// now the session should continue to issuance permission
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
}

func testSessionErrorsArePropagated(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{irma.NewAttributeRequest("not.existing.lol.yolo")},
		},
	}

	sessionJson, err := json.Marshal(request)
	require.NoError(t, err)

	// use the session request (meant for irma server) directly on client: should cause error
	c.NewSession(string(sessionJson))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_Error, session.Status)
	require.NotNil(t, session.Error)
	require.Equal(t, "unknownSchemeManager", session.Error.ErrorType)
	require.Equal(t, "Unknown identifiers: not, not.existing, not.existing.lol", session.Error.WrappedError)
}

func testUserCanDismissSession(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = studentCardOrMijnOverheidDisclosure()

	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Dismissed)
}

func testUserCanDismissSessionDuringPinEntry(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Delete keyshare tokens to force a fresh keyshare authentication (pin entry)
	c.DeleteKeyshareTokens()

	// Start an issuance session that requires keyshare (test scheme)
	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, createEmailIssuanceRequest()))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	// Grant permission — this will trigger a pin request from the keyshare server
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_Permission,
		Payload:   clientmodels.SessionPermissionInteractionPayload{Granted: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPin)

	// Dismiss the session while waiting for pin entry
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
}

func testUserCanDismissOpenID4VPSession(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	dcql := `{
		"credentials": [
		  {
			"id": "sc",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.RU.studentCard"] },
			"claims": [
			  { "id": "1", "path": ["university"] }
			]
		  }
		]
	}`

	testSession := startOpenID4VPSession(t, c, sessionHandler, dcql)
	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// Dismiss the OpenID4VP session
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Dismissed)
}

func testChainedSession(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	buildConfig := RequestorServerAuthConfiguration()
	requestorServer := StartRequestorServer(t, buildConfig)
	defer requestorServer.Stop()

	nextServer := StartNextRequestServer(t,
		&buildConfig.JwtRSAPrivateKey.PublicKey,
		buildConfig.IrmaConfiguration.CredentialTypes,
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
	)
	defer func() { _ = nextServer.Close() }()

	qr, _, _, err := requestorServer.StartSession(createStudentCardIssuanceRequest(), nil, "")
	require.NoError(t, err)

	sessionJson, err := json.MarshalIndent(qr, "", "   ")
	require.NoError(t, err)

	c.NewSession(string(sessionJson))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.Len(t, session.OfferedCredentials, 1)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// get the initial session request for the chained session
	var request irma.ServiceProviderRequest
	require.NoError(t, irma.NewHTTPTransport(nextSessionServerURL, false).Get("1", &request))
	requestJson, err := json.MarshalIndent(request, "", "   ")
	require.NoError(t, err)

	// start the session at the server
	sesPkg := startSessionAtServer(t, requestorServer, true, requestJson)
	require.NoError(t, err)

	sessionJson, err = json.MarshalIndent(sesPkg.SessionPtr, "", "   ")
	require.NoError(t, err)

	c.NewSession(string(sessionJson))
	session = awaitSessionState(t, sessionHandler)

	require.Equal(t, 2, session.Id)
	require.Equal(t, clientmodels.Type_Disclosure, session.Type)
	require.Empty(t, session.OfferedCredentials)

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Equal(t, "irma-demo.RU.studentCard", choice.CredentialId)

	grantPermission(t, c, session.Id, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)

	// the new (chained) session is still under the same id
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)
	require.Equal(t, "irma-demo.MijnOverheid.fullName", session.OfferedCredentials[0].CredentialId)

	// it's now an issuance session without disclosures, so no disclosure plan anymore
	require.Nil(t, session.DisclosurePlan)

	grantPermission(t, c, session.Id)

	// should now be the last session of the chain: another disclosure session
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 2, session.Id)
	require.Equal(t, clientmodels.Type_Disclosure, session.Type)
	require.Empty(t, session.OfferedCredentials)

	choice = session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Equal(t, "irma-demo.MijnOverheid.fullName", choice.CredentialId)

	grantPermission(t, c, session.Id, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)

	// session should now be finished
	require.Equal(t, clientmodels.Status_Success, session.Status)
}
