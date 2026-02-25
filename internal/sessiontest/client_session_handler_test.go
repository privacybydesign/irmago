package sessiontest

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"

	"github.com/stretchr/testify/require"
)

func TestSessionHandler(t *testing.T) {
	t.Run("disclosure", testSessionHandlerForIrmaDisclosures)
	t.Run("issuance", testSessionHandlerForIrmaIssuance)
	t.Run("signature", testSessionHandlerForIrmaSignature)
	t.Run("special", testSessionHandlerEdgeCases)
}

func testSessionHandlerForIrmaSignature(t *testing.T) {
	runSessionTest(t,
		"irma signature requestor info correct",
		testIrmaSignatureRequestorInfoCorrect,
	)

	runSessionTest(t,
		"signature request with unsatisfied disclosure",
		testSignatureRequest,
	)
}

func testSessionHandlerForIrmaDisclosures(t *testing.T) {
	runSessionTest(t,
		"irma requestor info correct",
		testIrmaDisclosureRequestorInfoCorrect,
	)

	runSessionTest(t,
		"disclosure with optional non-present credential moves to choices overview",
		testSingleCredentialDisclosureWithOptionalCredential_ShouldMoveToDisclosureOverview,
	)

	runSessionTest(t,
		"multiple steps of issuance during disclosure",
		testMultipleStepsOfIssuanceDuringDisclosure,
	)

	runSessionTest(t,
		"choice between two non-singleton credentials both present",
		testChoiceBetweenTwoNonSingletonCredentialsBothPresent,
	)

	runSessionTest(t,
		"choice between singleton and non-singleton credentials none present",
		testChoiceBetweenSingletonAndNonSingletonCredentialsNonePresent,
	)

	runSessionTest(t,
		"single credential disclosure unavailable singleton credential refresh after issuance",
		testSingleCredentialDisclosureWithUnavailableSingletonCredential_RefreshAfterIssuance,
	)

	runSessionTest(t,
		"single credential disclosure with available singleton credential",
		testSingleCredentialDisclosureWithAvailableSingletonCredential,
	)

	runSessionTest(t,
		"single credential single attribute disclosure with unavailable credential",
		testSingleCredentialDisclosureWithUnavailableCredential,
	)

	runSessionTest(t,
		"single credential single attribute disclosure with available credential",
		testSingleCredentialDisclosureWithAvailableCredential,
	)
}

func testSessionHandlerForIrmaIssuance(t *testing.T) {
	runSessionTest(t,
		"requestor info correct",
		testIrmaIssuanceRequestorInfoCorrect,
	)

	runSessionTest(t,
		"permission not granted",
		testIssuancePermissionNotGranted_SessionDismissed,
	)

	runSessionTest(t,
		"issuance session with unsatisfied disclosure",
		testIssuanceSessionWithUnsatisfiedDisclosure,
	)

	runSessionTest(t,
		"single credential issuance",
		testSingleCredentialIssuance,
	)

	runSessionTest(t,
		"multiple credential issuance",
		testMultipleCredentialsIssuance,
	)
}

func testSessionHandlerEdgeCases(t *testing.T) {
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
}

func testIrmaSignatureRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewSignatureRequest("Hello world")
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			// empty to signal the con above is optional
		},
	}

	sessionJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)
	c.NewNewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Id, 1)

	requestor := session.Requestor
	require.Equal(t, requestor.Id, "test-requestors.test-requestor")
	require.Equal(t, requestor.Name, client.TranslatedString{"nl": "Lokale IRMA server", "en": "Local IRMA server"})
	require.True(t, requestor.Verified)
}

func testIrmaDisclosureRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			// empty to signal the con above is optional
		},
	}

	sessionJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)
	c.NewNewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Id, 1)

	requestor := session.Requestor
	require.Equal(t, requestor.Id, "test-requestors.test-requestor")
	require.Equal(t, requestor.Name, client.TranslatedString{"nl": "Lokale IRMA server", "en": "Local IRMA server"})
	require.True(t, requestor.Verified)
}

func testIrmaIssuanceRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	c.NewNewSession(
		startSameDeviceIrmaSessionAtServer(
			t,
			irmaServer,
			createEmailIssuanceRequest(),
		),
	)
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)

	requestor := session.Requestor
	require.Equal(t, requestor.Id, "test-requestors.test-requestor")
	require.Equal(t, requestor.Name, client.TranslatedString{"nl": "Lokale IRMA server", "en": "Local IRMA server"})
	require.True(t, requestor.Verified)
}

func testMultipleCredentialsIssuance(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Barry",
				"firstname":  "",
				"familyname": "Batsbak",
				"prefix":     "Sir",
			},
		},
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "University of the Arts",
				"studentCardNumber": "12345",
				"studentID":         "67890",
				"level":             "high",
			},
		},
	})

	sessionJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionJson)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 2)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_Success)
}

func testIssuancePermissionNotGranted_SessionDismissed(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	requestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, createEmailIssuanceRequest())
	c.NewNewSession(requestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: false,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_Dismissed)
}

func testSingleCredentialDisclosureWithOptionalCredential_ShouldMoveToDisclosureOverview(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			// empty to signal the con above is optional
			irma.AttributeCon{},
		},
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}

	sessionJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)
	c.NewNewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Id, 1)
	plan := session.DisclosurePlan

	// only one step required to make the disclosure satisfiable, since the student card is optional
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// satisfy the required credential (not the optional)
	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequest())

	// disclosure session updated
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)

	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	require.Equal(t,
		plan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}},
	)

	choices := plan.DisclosureChoicesOverview
	// there's two choices, one of which is optional
	require.Len(t, choices, 2)

	optional := choices[0]
	required := choices[1]

	require.Len(t, optional.OwnedOptions, 0)
	require.Len(t, optional.ObtainableOptions, 1)
	require.True(t, optional.Optional)

	require.False(t, required.Optional)
	require.Len(t, required.OwnedOptions, 1)
	// MijnOverheid is a singleton and thus not obtainable
	require.Len(t, required.ObtainableOptions, 0)

	// finish the issuance session
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)

	choice := required.OwnedOptions[0]
	// finish the disclosure session
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: 1,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
			DisclosureChoices: []client.DisclosureDisconSelection{
				// for the first option we don't select anything since it's optional
				{},
				// for the second option we select the required credential
				{
					Credentials: []client.SelectedCredential{
						{
							CredentialId:   choice.CredentialId,
							CredentialHash: choice.Hash,
							AttributePaths: [][]any{{choice.Attributes[0].Id}, {choice.Attributes[1].Id}},
						},
					},
				},
			},
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_Success)
}

func testContinueOnSecondDevice(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := createEmailIssuanceRequest()
	sesionJson := startCrossDeviceIrmaSessionAtServer(t, irmaServer, request)
	c.NewNewSession(sesionJson)
	session := awaitSessionState(t, sessionHandler)
	require.True(t, session.ContinueOnSecondDevice)
}

func testSessionWithPairingCode(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := createEmailIssuanceRequest()

	qr, requestorToken, _, err := irmaServer.irma.StartSession(request, nil, "")
	require.NoError(t, err)
	sessionReq := client.SessionRequestData{
		Qr:       *qr,
		Protocol: irmaclient.Protocol_Irma,
	}
	sessionJson, err := json.Marshal(sessionReq)

	frontendOptions := irma.NewFrontendOptionsRequest()
	frontendOptions.PairingMethod = "pin"
	require.NoError(t, err)
	irmaServer.irma.SetFrontendOptions(requestorToken, &frontendOptions)

	c.NewNewSession(string(sessionJson))

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_ShowPairingCode)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Len(t, session.PairingCode, 4)
	require.False(t, session.ContinueOnSecondDevice)

	// pretend the pairing was completed
	irmaServer.irma.PairingCompleted(requestorToken)

	// now the session should continue to issuance permission
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Issuance)
}

func testSignatureRequest(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewSignatureRequest("Hello, World!")
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
	}

	sessionJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)
	c.NewNewSession(sessionJson)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Signature)
	require.Equal(t, session.MessageToSign, "Hello, World!")

	require.Len(t, session.OfferedCredentials, 0)
	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.Steps, 1)
	require.Nil(t, session.DisclosurePlan.DisclosureChoicesOverview)

	issue(t, irmaServer, c, sessionHandler, createEmailIssuanceRequest())

	// update disclosure candidates of signature session
	session = awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Signature)
	require.Equal(t, session.MessageToSign, "Hello, World!")

	require.Len(t, session.OfferedCredentials, 0)
	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.Steps, 1)
	require.NotNil(t, session.DisclosurePlan.DisclosureChoicesOverview)

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
			DisclosureChoices: []client.DisclosureDisconSelection{
				{
					Credentials: []client.SelectedCredential{
						{
							CredentialId:   choice.CredentialId,
							CredentialHash: choice.Hash,
							AttributePaths: [][]any{{choice.Attributes[0].Id}},
						},
					},
				},
			},
		},
	})

	// finish email issuance session
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)
	require.Equal(t, session.Status, client.Status_Success)

	// finish signature session
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_Success)
}

func testIssuanceSessionWithUnsatisfiedDisclosure(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// issue email and at the same time ask for either student card or MijnOverheid
	request := createEmailIssuanceRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}

	requestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)
	c.NewNewSession(requestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Status, client.Status_RequestPermission)

	require.Len(t, session.OfferedCredentials, 1)
	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.Steps, 1)
	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.Steps[0].Options, 2)
	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.IssuedCredentialIds, 0)
	require.Nil(t, session.DisclosurePlan.DisclosureChoicesOverview)

	// issue MijnOverheid
	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequest())

	session = awaitSessionState(t, sessionHandler)
	// updated the first session with new disclosure options
	require.Equal(t, session.Id, 1)

	require.Len(t, session.OfferedCredentials, 1)
	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.Steps, 1)
	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.Steps[0].Options, 2)
	require.Equal(t,
		session.DisclosurePlan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}},
	)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]

	// give permission to disclose the MijnOverheid credential
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
			DisclosureChoices: []client.DisclosureDisconSelection{
				{
					Credentials: []client.SelectedCredential{
						{
							CredentialId:   cred.CredentialId,
							CredentialHash: cred.Hash,
							AttributePaths: [][]any{{cred.Attributes[0].Id}, {cred.Attributes[1].Id}},
						},
					},
				},
			},
		},
	})

	// finish issuance session for missing credential
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)
	require.Equal(t, session.Status, client.Status_Success)

	// finish first issuance session
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_Success)
}

func testMultipleStepsOfIssuanceDuringDisclosure(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}

	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 1)

	plan := session.DisclosurePlan

	require.NotNil(t, plan)

	// the user should get one step to issue one of two options
	require.Len(t, plan.IssueDuringDislosure.Steps, 2)
	require.Len(t, plan.IssueDuringDislosure.IssuedCredentialIds, 0)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[1].Options, 2)

	// no disclosure choices overview yet since the session is not finishable
	require.Nil(t, plan.DisclosureChoicesOverview)

	// issue email
	issue(t, irmaServer, c, sessionHandler, createEmailIssuanceRequest())
	session = awaitSessionState(t, sessionHandler)

	// updated disclosure session
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.Steps, 2)
	require.Equal(t,
		session.DisclosurePlan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"test.test.email": {}},
	)

	// finished issuance session
	_ = awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequest())

	// new disclosure choices
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)

	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 2)

	// both credentials have now been issued, which means the request is satisfiable
	require.Equal(t,
		plan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}, "test.test.email": {}},
	)

	// finish second issuance request
	_ = awaitSessionState(t, sessionHandler)

	email := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	overheid := plan.DisclosureChoicesOverview[1].OwnedOptions[0]

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: 1,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
			DisclosureChoices: []client.DisclosureDisconSelection{
				{
					Credentials: []client.SelectedCredential{
						{
							CredentialId:   email.CredentialId,
							CredentialHash: email.Hash,
							AttributePaths: [][]any{{email.Attributes[0].Id}},
						},
					},
				},
				{
					Credentials: []client.SelectedCredential{
						{
							CredentialId:   overheid.CredentialId,
							CredentialHash: overheid.Hash,
							AttributePaths: [][]any{{overheid.Attributes[0].Id}, {overheid.Attributes[1].Id}},
						},
					},
				},
			},
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_Success)
}

func testSessionErrorsArePropagated(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("not.existing.lol.yolo"),
			},
		},
	}

	sessionJson, err := json.Marshal(request)
	require.NoError(t, err)

	// use the session request (meant for irma server) directly on client: should cause error
	c.NewNewSession(string(sessionJson))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_Error)
	require.EqualError(t,
		session.Error,
		"Error type: unknownSchemeManager\nDescription: Unknown identifiers: not, not.existing, not.existing.lol\nStatus code: 0",
	)
}

func testUserCanDismissSession(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}

	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Disclosure)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Status, client.Status_Dismissed)
}

func testChoiceBetweenSingletonAndNonSingletonCredentialsNonePresent(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}

	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 1)

	plan := session.DisclosurePlan

	require.NotNil(t, plan)

	// the user should get one step to issue one of two options
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.IssuedCredentialIds, 0)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 2)
	// no disclosure choices overview yet since the session is not finishable
	require.Nil(t, plan.DisclosureChoicesOverview)

	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequest())

	// disclosure session updated
	session = awaitSessionState(t, sessionHandler)

	// the user should now have no steps left because the step index is 1
	// but the previous step should still be available for UX purposes
	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Equal(t,
		plan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
	)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 2)

	// the disclosure choices overview should allow the user to add new versions of student card
	// and issue the MijnOverheid credential
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.Len(t, plan.DisclosureChoicesOverview[0].ObtainableOptions, 2)

	// only one obtained option should be available
	require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 1)

	// issuance session finished
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)

}

func testChoiceBetweenTwoNonSingletonCredentialsBothPresent(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequest())
	session := awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, createEmailIssuanceRequest())
	session = awaitSessionState(t, sessionHandler)

	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
	}

	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session = awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 3)

	plan := session.DisclosurePlan

	require.NotNil(t, plan)
	require.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	opt := plan.DisclosureChoicesOverview[0]
	// there are two options
	require.Len(t, opt.OwnedOptions, 2)
	// both are also obtainable
	require.Len(t, opt.ObtainableOptions, 2)

	studentCard := opt.OwnedOptions[slices.IndexFunc(
		opt.OwnedOptions,
		func(c *client.SelectableCredentialInstance) bool { return c.CredentialId == "irma-demo.RU.studentCard" },
	)]

	require.Equal(t,
		studentCard.Attributes,
		[]client.Attribute{
			{
				Id: "university",
				DisplayName: client.TranslatedString{
					"en": "University",
					"nl": "Universiteit",
				},
				Description: client.TranslatedString{
					"en": "The name of the university",
					"nl": "Naam van de universiteit",
				},
				Value: client.AttributeValue{
					Type: "translated_string",
					Data: irma.TranslatedString{
						"":   "University of the Arts",
						"en": "University of the Arts",
						"nl": "University of the Arts",
					},
				},
			},
			{
				Id: "level",
				DisplayName: client.TranslatedString{
					"en": "Type",
					"nl": "Soort",
				},
				Description: client.TranslatedString{
					"en": "Whether you are a regular or PhD student",
					"nl": "Of u een gewone of PhD student bent",
				},
				Value: client.AttributeValue{
					Type: "translated_string",
					Data: irma.TranslatedString{
						"":   "high",
						"en": "high",
						"nl": "high",
					},
				},
			},
		},
	)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
			DisclosureChoices: []client.DisclosureDisconSelection{
				{
					Credentials: []client.SelectedCredential{
						{
							CredentialId:   studentCard.CredentialId,
							CredentialHash: studentCard.Hash,
							AttributePaths: [][]any{{"university"}, {"level"}},
						},
					},
				},
			},
		},
	})

	session = awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_Success)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 3)
}

func testSingleCredentialDisclosureWithUnavailableSingletonCredential_RefreshAfterIssuance(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}

	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 1)

	plan := session.DisclosurePlan

	require.NotNil(t, plan)
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	require.Len(t, plan.IssueDuringDislosure.IssuedCredentialIds, 0)

	toIssue := plan.IssueDuringDislosure.Steps[0].Options[0]
	require.Equal(t, toIssue.CredentialId, "irma-demo.MijnOverheid.fullName")
	require.Equal(t, toIssue.Attributes, []client.AttributeDescriptor{
		{
			Id:   "firstnames",
			Name: client.TranslatedString{"nl": "Voornamen", "en": "First names"},
			Type: client.AttributeType_String,
		},
		{
			Id:   "firstname",
			Name: client.TranslatedString{"nl": "Voornaam", "en": "First name"},
			Type: client.AttributeType_String,
		},
		{
			Id:   "familyname",
			Name: client.TranslatedString{"nl": "Achternaam", "en": "Family name"},
			Type: client.AttributeType_String,
		},
		{
			Id:   "prefix",
			Name: client.TranslatedString{"nl": "Tussenvoegsel", "en": "Prefix"},
			Type: client.AttributeType_String,
		},
	})

	// start the issuance session
	issRequest := startSameDeviceIrmaSessionAtServer(t, irmaServer, createMijnOverheidIssuanceRequest())
	c.NewNewSession(issRequest)
	issuanceSession := awaitSessionState(t, sessionHandler)
	require.Equal(t, issuanceSession.Status, client.Status_RequestPermission)
	require.Equal(t, issuanceSession.Id, 2)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: issuanceSession.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})

	// expect the disclosure session to get updated
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)

	// expect the issuance session to be done
	issuanceSession = awaitSessionState(t, sessionHandler)
	require.Equal(t, issuanceSession.Id, 2)
	require.Equal(t, issuanceSession.Status, client.Status_Success)

	plan = session.DisclosurePlan

	// no more credentials left to issue (but the list of issuance steps should still be available)
	require.Equal(t,
		plan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}},
	)
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)

	// the disclosure options should contain the option
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	opt := plan.DisclosureChoicesOverview[0]
	require.Len(t, opt.OwnedOptions, 1)
	// no new version of this is obtainable because it's a singleton
	require.Len(t, opt.ObtainableOptions, 0)
}

func testSingleCredentialDisclosureWithAvailableSingletonCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequest())
	_ = awaitSessionState(t, sessionHandler)

	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}

	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)
	require.Len(t, session.OfferedCredentials, 0)

	plan := session.DisclosurePlan

	require.NotNil(t, plan)

	// no issuance steps
	require.Nil(t, plan.IssueDuringDislosure)

	require.Len(t, plan.DisclosureChoicesOverview, 1)
	discon := plan.DisclosureChoicesOverview[0]

	require.Len(t, discon.OwnedOptions, 1)
	require.Len(t, discon.ObtainableOptions, 0)
}

func testSingleCredentialDisclosureWithUnavailableCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
	}

	c.DeleteKeyshareTokens()
	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 1)
	require.Len(t, session.OfferedCredentials, 0)
	require.NotNil(t, session.DisclosurePlan)

	plan := session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	require.Len(t, plan.IssueDuringDislosure.IssuedCredentialIds, 0)

	credToIssue := plan.IssueDuringDislosure.Steps[0].Options[0]

	require.Equal(t, credToIssue.Name, client.TranslatedString{
		"nl": "Demo E-mailadres",
		"en": "Demo Email address",
	})
	require.Equal(t, credToIssue.CredentialId, "test.test.email")
}

func testSingleCredentialDisclosureWithAvailableCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	schemalessPerformIrmaIssuanceSession(
		t,
		c,
		sessionHandler,
		irmaServer,
		createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"),
	)

	disclosureRequest := irma.NewDisclosureRequest()
	disclosureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
	}

	c.DeleteKeyshareTokens()
	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, disclosureRequest)

	c.NewNewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)
	require.Len(t, session.OfferedCredentials, 0)
	require.NotNil(t, session.DisclosurePlan)

	plan := session.DisclosurePlan
	require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 1)
	// it's also possible to obtain a new one, since it not a singleton
	require.Len(t, plan.DisclosureChoicesOverview[0].ObtainableOptions, 1)

	emailCred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]

	choice := client.DisclosureDisconSelection{
		Credentials: []client.SelectedCredential{
			{
				CredentialId:   emailCred.CredentialId,
				CredentialHash: emailCred.Hash,
				AttributePaths: [][]any{
					{"email"},
				},
			},
		},
	}

	// give disclosure permission
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted:           true,
			DisclosureChoices: []client.DisclosureDisconSelection{choice},
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPin)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)

	// give pin
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_EnteredPin,
		Payload: client.PinInteractionPayload{
			Pin:     "12345",
			Proceed: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_Success)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)
}

func userInteraction(t *testing.T, c *client.Client, interaction client.SessionUserInteraction) {
	go func() {
		require.NoError(
			t,
			c.HandleUserInteraction(interaction),
		)
	}()
}

func testSingleCredentialIssuance(t *testing.T, irmaServer *IrmaServer, c *client.Client, sessionHandler *MockSessionHandler) {
	schemalessPerformIrmaIssuanceSession(
		t,
		c,
		sessionHandler,
		irmaServer,
		createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"),
	)
}

func schemalessPerformIrmaIssuanceSession(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	irmaServer *IrmaServer,
	request *irma.IssuanceRequest,
) {
	// delete keyshare session token so the pin is required
	c.DeleteKeyshareTokens()
	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Id, 1)
	require.Len(t, session.OfferedCredentials, 1)

	// give issuance permission
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPin)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Id, 1)

	// give pin
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_EnteredPin,
		Payload: client.PinInteractionPayload{
			Pin:     "12345",
			Proceed: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_Success)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Id, 1)
}

func awaitWithTimeout[T any](t *testing.T, channel chan T, timeout time.Duration) T {
	select {
	case msg := <-channel:
		return msg
	case <-time.After(timeout):
		require.Fail(t, "failed to await after %s", timeout)
	}
	// unreachable in theory
	var ret T
	return ret
}

type SessionIntegrationTest func(t *testing.T, irmaServer *IrmaServer, client *client.Client, handler *MockSessionHandler)

func runSessionTest(t *testing.T, name string, test SessionIntegrationTest) {
	conf := IrmaServerConfigurationWithTempStorage(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	t.Run(name, func(t *testing.T) {
		test(t, irmaServer, c, sessionHandler)
	})
}

func issue(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	req *irma.IssuanceRequest,
) {
	issRequest := startSameDeviceIrmaSessionAtServer(t, irmaServer, req)
	c.NewNewSession(issRequest)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Status, client.Status_RequestPermission)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})
}

func awaitSessionState(t *testing.T, sessionHandler *MockSessionHandler) client.SessionState {
	return awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
}
