package sessiontest

import (
	"slices"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"

	"github.com/stretchr/testify/require"
)

func TestClientHandler(t *testing.T) {
	runSessionTest(t,
		"choice between two non-singleton credentials both present",
		testChoiceBetweenTwoNonSingletonCredentialsBothPresent,
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

	runSessionTest(t,
		"single credential issuance",
		testSingleCredentialIssuance,
	)
}

func testChoiceBetweenTwoNonSingletonCredentialsBothPresent(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequest())
	issue(t, irmaServer, c, sessionHandler, createEmailIssuanceRequest())

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

	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_AskingDisclosurePermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 3)

	plan := session.DisclosurePlan

	require.NotNil(t, plan)
	require.Len(t, plan.IssueDuringDislosure.LeftToIssue, 0)

	require.Len(t, plan.IssueDuringDislosure.IssuedDuringSession, 0)

	require.Len(t, plan.DisclosureOptions, 1)

	opt := plan.DisclosureOptions[0]
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

	c.HandleUserInteraction(client.SessionUserInteraction{
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

							AttributePaths: [][]any{
								{"university"},
								{"level"},
							},
						},
					},
				},
			},
		},
	})

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)

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

	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_AskingDisclosurePermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 1)

	plan := session.DisclosurePlan

	require.NotNil(t, plan)
	require.Len(t, plan.IssueDuringDislosure.LeftToIssue, 1)
	require.Len(t, plan.IssueDuringDislosure.IssuedDuringSession, 0)

	toIssue := plan.IssueDuringDislosure.LeftToIssue[0]
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
	issRequest := startIrmaSessionAtServer(t, irmaServer, createMijnOverheidIssuanceRequest())
	c.NewNewSession(issRequest)
	issuanceSession := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, issuanceSession.Status, client.Status_AskingIssuancePermission)
	require.Equal(t, issuanceSession.Id, 2)

	c.HandleUserInteraction(client.SessionUserInteraction{
		SessionId: issuanceSession.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})

	// expect the disclosure session to get updated
	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Id, 1)

	// expect the issuance session to be done
	issuanceSession = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, issuanceSession.Id, 2)
	require.Equal(t, issuanceSession.Status, client.Status_Success)

	plan = session.DisclosurePlan

	// no more credentials left to issue
	require.Len(t, plan.IssueDuringDislosure.LeftToIssue, 0)
	require.Len(t, plan.IssueDuringDislosure.IssuedDuringSession, 1)

	// the disclosure options should contain the option
	require.Len(t, plan.DisclosureOptions, 1)
	opt := plan.DisclosureOptions[0]
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

	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}

	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_AskingDisclosurePermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)
	require.Len(t, session.OfferedCredentials, 0)

	plan := session.DisclosurePlan

	require.NotNil(t, plan)
	require.Len(t, plan.IssueDuringDislosure.LeftToIssue, 0)
	require.Len(t, plan.DisclosureOptions, 1)

	discon := plan.DisclosureOptions[0]

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
	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_AskingDisclosurePermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 1)
	require.Len(t, session.OfferedCredentials, 0)
	require.NotNil(t, session.DisclosurePlan)

	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.LeftToIssue, 1)
	credToIssue := session.DisclosurePlan.IssueDuringDislosure.LeftToIssue[0]

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
	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, disclosureRequest)

	c.NewNewSession(sessionRequestJson)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_AskingDisclosurePermission)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)
	require.Len(t, session.OfferedCredentials, 0)
	require.NotNil(t, session.DisclosurePlan)

	plan := session.DisclosurePlan
	require.Len(t, plan.DisclosureOptions[0].OwnedOptions, 1)
	// it's also possible to obtain a new one, since it not a singleton
	require.Len(t, plan.DisclosureOptions[0].ObtainableOptions, 1)

	emailCred := plan.DisclosureOptions[0].OwnedOptions[0]

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
	go func() {
		require.NoError(
			t,
			c.HandleUserInteraction(client.SessionUserInteraction{
				SessionId: session.Id,
				Type:      client.UI_Permission,
				Payload: client.SessionPermissionInteractionPayload{
					Granted:           true,
					DisclosureChoices: []client.DisclosureDisconSelection{choice},
				},
			}),
		)
	}()

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPin)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)

	// give pin
	go func() {
		require.NoError(
			t,
			c.HandleUserInteraction(client.SessionUserInteraction{
				SessionId: session.Id,
				Type:      client.UI_EnteredPin,
				Payload: client.PinInteractionPayload{
					Pin:     "12345",
					Proceed: true,
				},
			}),
		)
	}()

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_Success)
	require.Equal(t, session.Type, client.Type_Disclosure)
	require.Equal(t, session.Id, 2)
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
	sessionRequestJson := startIrmaSessionAtServer(t, irmaServer, request)

	c.NewNewSession(sessionRequestJson)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)

	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_AskingIssuancePermission)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Id, 1)
	require.Len(t, session.OfferedCredentials, 1)

	// give issuance permission
	go func() {
		require.NoError(
			t,
			c.HandleUserInteraction(client.SessionUserInteraction{
				SessionId: session.Id,
				Type:      client.UI_Permission,
				Payload: client.SessionPermissionInteractionPayload{
					Granted: true,
				},
			}),
		)
	}()

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Protocol, irmaclient.Protocol_Irma)
	require.Equal(t, session.Status, client.Status_RequestPin)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Id, 1)

	// give pin
	go func() {
		require.NoError(
			t,
			c.HandleUserInteraction(client.SessionUserInteraction{
				SessionId: session.Id,
				Type:      client.UI_EnteredPin,
				Payload: client.PinInteractionPayload{
					Pin:     "12345",
					Proceed: true,
				},
			}),
		)
	}()

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
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
	issRequest := startIrmaSessionAtServer(t, irmaServer, req)
	c.NewNewSession(issRequest)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Status, client.Status_AskingIssuancePermission)

	c.HandleUserInteraction(client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Status, client.Status_Success)
}
