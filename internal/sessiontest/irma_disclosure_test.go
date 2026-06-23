package sessiontest

import (
	"slices"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

func testSessionHandlerForIrmaDisclosures(t *testing.T) {
	runSessionTest(t,
		"disclosure with pre-defined values",
		testDisclosureWithPredefinedValues,
	)

	runSessionTest(t,
		"multi-singleton inner con produces single bundle",
		testMultiSingletonInnerConProducesBundle,
	)

	runSessionTest(t,
		"issuance step emits multi-cred bundle",
		testIssuanceStepEmitsMultiCredBundle,
	)

	runSessionTest(t,
		"multi-cred bundle issuance flow end-to-end",
		testMultiCredBundleIssuanceFlow,
	)

	runSessionTest(t,
		"multiple issuance bundle options",
		testMultipleIssuanceBundleOptions,
	)

	runSessionTest(t,
		"optional attributes from same credential credential not present",
		testDisclosureWithOptionalAttributesFromSameCredential_CredentialNotPresent,
	)

	runSessionTest(t,
		"irma requestor info correct",
		testIrmaDisclosureRequestorInfoCorrect,
	)

	runSessionTest(t,
		"trusted party logo paths not empty during disclosure",
		testDisclosureTrustedPartyLogoPaths,
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
		"wrong credential issued during disclosure notifies frontend",
		testWrongCredentialIssuedDuringDisclosure,
	)

	runSessionTest(t,
		"pre-existing wrong credential is not reported as wrongly issued",
		testPreExistingWrongCredentialNotReported,
	)

	runSessionTest(t,
		"choice between two non-singleton credentials both present",
		testChoiceBetweenTwoNonSingletonCredentialsBothPresent,
	)

	runSessionTest(t,
		"selection survives deleting another credential mid-session",
		testDisclosureKeepsSelectionAfterDeletingAnotherCredential,
	)

	runSessionTest(t,
		"choice between email and student card credentials both present",
		testChoiceBetweenEmailAndStudentCardBothPresent,
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

	runSessionTest(t,
		"client return url",
		testDisclosureClientReturnUrl,
	)

	runSessionTest(t,
		"client return url is not dispatched before status is populated",
		testClientReturnUrlNotDispatchedBeforeStatusPopulated,
	)

	runSessionTest(t,
		"disclosure attribute order follows schema",
		testDisclosureAttributeOrderFollowsSchema,
	)
}

func testDisclosureWithPredefinedValues(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	value := "Universiteit Utrecht"
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.studentID"),
				irma.AttributeRequest{
					Type:  irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"),
					Value: &value,
				},
			},
		},
	}

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(1, sessionJson)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{Attributes: []expectedAttr{
					{
						Path:           []any{"studentID"},
						DisplayName:    &clientmodels.TranslatedString{"nl": "Studentnummer", "en": "Student number"},
						RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
					},
					{
						Path:           []any{"university"},
						DisplayName:    &clientmodels.TranslatedString{"nl": "Universiteit", "en": "University"},
						RequestedValue: strVal("Universiteit Utrecht"),
					},
				}},
			}},
		},
	})

	// issue the credential with an invalid value
	issue(t, irmaServer, c, sessionHandler, 2, createStudentCardIssuanceRequest())
	// updated disclosure request
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)

	plan = session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"studentID"},
							DisplayName:    &clientmodels.TranslatedString{"nl": "Studentnummer", "en": "Student number"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"nl": "Universiteit", "en": "University"},
							RequestedValue: strVal("Universiteit Utrecht"),
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{},
		WrongCredentialIssued: &expectedCredentialDescriptor{
			CredentialId: "irma-demo.RU.studentCard",
			Attributes: []expectedAttr{
				{
					Path:           []any{"university"},
					DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
					Value:          strVal("University of the Arts"),
					RequestedValue: strVal("Universiteit Utrecht"),
				},
			},
		},
	})

	// make sure the previous issuance session was finished
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)
	require.Equal(t, session.Status, clientmodels.Status_Success)

	// satisfy the disclosure by issuing the credential with the pre-defined value
	issueRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "Universiteit Utrecht",
				"studentCardNumber": "12345",
				"studentID":         "67890",
				"level":             "high",
			},
		},
	})
	issue(t, irmaServer, c, sessionHandler, 3, issueRequest)
	session = awaitSessionState(t, sessionHandler)

	// expect the disclosure session to be updated and satisfiable
	require.Equal(t, session.Id, 1)
	plan = session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"studentID"},
							DisplayName:    &clientmodels.TranslatedString{"nl": "Studentnummer", "en": "Student number"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"nl": "Universiteit", "en": "University"},
							RequestedValue: strVal("Universiteit Utrecht"),
						},
					},
				},
			}},
		},
		IssuedCredentialIds:      map[string]struct{}{"irma-demo.RU.studentCard": {}},
		WrongCredentialIssuedNil: true,
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo Radboud University Nijmegen", "nl": "Demo Radboud Universiteit Nijmegen"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"studentID"},
								DisplayName: &clientmodels.TranslatedString{"nl": "Studentnummer", "en": "Student number"},
								Description: &clientmodels.TranslatedString{"en": "Your student number", "nl": "Uw studentnummer"},
								Value:       strVal("67890"),
							},
							{
								Path:           []any{"university"},
								DisplayName:    &clientmodels.TranslatedString{"nl": "Universiteit", "en": "University"},
								Description:    &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
								Value:          strVal("Universiteit Utrecht"),
								RequestedValue: strVal("Universiteit Utrecht"),
							},
						},
					},
				},
			},
		},
	})

	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1, makeDisclosureChoice(choice))

	// make sure the previous issuance session is finished
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// make sure the disclosure session is finished
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "irma-demo.RU.studentCard.studentID", Value: "67890"},
			{Identifier: "irma-demo.RU.studentCard.university", Value: "Universiteit Utrecht"},
		},
	})
}

func testDisclosureWithOptionalAttributesFromSameCredential_CredentialNotPresent(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{irma.NewAttributeRequest("irma-demo.RU.studentCard.university")},
		},
		irma.AttributeDisCon{
			irma.AttributeCon{},
			irma.AttributeCon{irma.NewAttributeRequest("irma-demo.RU.studentCard.level")},
		},
	}

	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)
	plan := session.DisclosurePlan
	// only attributes from one credential type is asked, so we only expect one step to obtain that one
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{},
	})

	// issue that credential
	issue(t, irmaServer, c, sessionHandler, 2, createStudentCardIssuanceRequest())

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	plan = session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{"irma-demo.RU.studentCard": {}},
		Choices: []expectedPickOneChoice{
			{
				Optional: false,
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo Radboud University Nijmegen", "nl": "Demo Radboud Universiteit Nijmegen"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"university"},
								DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								Description: &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
								Value:       strVal("University of the Arts"),
							},
						},
					},
				},
				Obtainable: []expectedCredentialDescriptor{
					{CredentialId: "irma-demo.RU.studentCard"},
				},
			},
			{
				Optional: true,
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo Radboud University Nijmegen", "nl": "Demo Radboud Universiteit Nijmegen"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"level"},
								DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
								Description: &clientmodels.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"},
								Value:       strVal("high"),
							},
						},
					},
				},
				Obtainable: []expectedCredentialDescriptor{
					{CredentialId: "irma-demo.RU.studentCard"},
				},
			},
		},
	})
}

func testIrmaDisclosureRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = studentCardDisclosure()

	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	requireRequestorInfo(t, session)
}

func testDisclosureTrustedPartyLogoPaths(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// First issue a credential so we have something to disclose
	schemalessPerformIrmaIssuanceSession(t, c, sessionHandler, irmaServer, 1,
		createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"),
	)

	// Now start a disclosure session for that credential
	disclosureRequest := irma.NewDisclosureRequest()
	disclosureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
		},
	}

	c.NewSession(2, startSameDeviceIrmaSessionAtServer(t, irmaServer, disclosureRequest))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	// Requestor should have a logo
	require.NotNil(t, session.Requestor.Image, "requestor Image should not be nil")
	require.NotEmpty(t, session.Requestor.Image.Base64, "requestor Image should have base64 data")

	// Disclosure plan credential issuers should have logos
	require.NotNil(t, session.DisclosurePlan)
	for _, choice := range session.DisclosurePlan.DisclosureChoicesOverview {
		for _, bundle := range choice.OwnedOptions {
			for _, opt := range bundle.Credentials {
				require.NotNil(t, opt.Issuer.Image, "issuer Image for %s should not be nil", opt.CredentialId)
				require.NotEmpty(t, opt.Issuer.Image.Base64, "issuer Image for %s should have base64 data", opt.CredentialId)
			}
		}
		for _, opt := range choice.ObtainableOptions {
			require.NotNil(t, opt.Issuer.Image, "issuer Image for %s should not be nil", opt.CredentialId)
			require.NotEmpty(t, opt.Issuer.Image.Base64, "issuer Image for %s should have base64 data", opt.CredentialId)
		}
	}
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

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(1, sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	plan := session.DisclosurePlan

	// only one step required to make the disclosure satisfiable, since the student card is optional
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.MijnOverheid.fullName",
					Attributes: []expectedAttr{
						{
							Path:           []any{"firstnames"},
							DisplayName:    &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"familyname"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{},
	})

	// satisfy the required credential (not the optional)
	issue(t, irmaServer, c, sessionHandler, 2, createMijnOverheidIssuanceRequest())

	// disclosure session updated
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)

	plan = session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.MijnOverheid.fullName",
					Attributes: []expectedAttr{
						{
							Path:           []any{"firstnames"},
							DisplayName:    &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"familyname"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}},
		// there's two choices, one of which is optional
		Choices: []expectedPickOneChoice{
			{
				Optional: true,
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Attributes: []expectedAttr{
							{
								Path:           []any{"level"},
								DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:        []any{"studentID"},
								DisplayName: &clientmodels.TranslatedString{"en": "Student number", "nl": "Studentnummer"},
								Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:        []any{"studentCardNumber"},
								DisplayName: &clientmodels.TranslatedString{"en": "Student card number", "nl": "Studentenkaartnummer"},
								Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:           []any{"university"},
								DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
						},
					},
				},
			},
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.MijnOverheid.fullName",
						Name:         clientmodels.TranslatedString{"en": "Demo Name", "nl": "Demo Naam"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo MijnOverheid.nl", "nl": "Demo MijnOverheid.nl"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"firstnames"},
								DisplayName: &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
								Description: &clientmodels.TranslatedString{"en": "All of your first names", "nl": "Al uw voornamen"},
								Value:       strVal("Barry"),
							},
							{
								Path:        []any{"familyname"},
								DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
								Description: &clientmodels.TranslatedString{"en": "Your family name", "nl": "Uw achternaam"},
								Value:       strVal("Batsbak"),
							},
						},
					},
				},
			},
		},
	})

	required := plan.DisclosureChoicesOverview[1]

	// finish the issuance session
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 2, session.Id)

	// finish the disclosure session
	// for the first option we don't select anything since it's optional
	choice := required.OwnedOptions[0]
	grantPermission(t, c, 1,
		clientmodels.DisclosureDisconSelection{}, // empty for optional
		makeDisclosureChoice(choice),
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{}, // optional disjunction, nothing disclosed
		{
			{Identifier: "irma-demo.MijnOverheid.fullName.firstnames", Value: "Barry"},
			{Identifier: "irma-demo.MijnOverheid.fullName.familyname", Value: "Batsbak"},
		},
	})
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
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
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

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(1, sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan

	// the user should get two steps: one for email, one with choice between student card and MijnOverheid
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "test.test.email",
					Attributes: []expectedAttr{
						{
							Path:           []any{"email"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"level"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
				{
					CredentialId: "irma-demo.MijnOverheid.fullName",
					Attributes: []expectedAttr{
						{
							Path:           []any{"firstnames"},
							DisplayName:    &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"familyname"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{},
	})

	// issue email
	issue(t, irmaServer, c, sessionHandler, 2, createEmailIssuanceRequest())
	session = awaitSessionState(t, sessionHandler)

	// updated disclosure session
	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "test.test.email",
					Attributes: []expectedAttr{
						{
							Path:           []any{"email"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"level"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
				{
					CredentialId: "irma-demo.MijnOverheid.fullName",
					Attributes: []expectedAttr{
						{
							Path:           []any{"firstnames"},
							DisplayName:    &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"familyname"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{"test.test.email": {}},
	})

	// finished issuance session
	_ = awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, 3, createMijnOverheidIssuanceRequest())

	// new disclosure choices
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)

	plan = session.DisclosurePlan

	// both credentials have now been issued, which means the request is satisfiable
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "test.test.email",
					Attributes: []expectedAttr{
						{
							Path:           []any{"email"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"level"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
				{
					CredentialId: "irma-demo.MijnOverheid.fullName",
					Attributes: []expectedAttr{
						{
							Path:           []any{"firstnames"},
							DisplayName:    &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"familyname"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}, "test.test.email": {}},
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "test.test.email",
						Name:         clientmodels.TranslatedString{"en": "Demo Email address", "nl": "Demo E-mailadres"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo test issuer", "nl": "Demo test issuer"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
								Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
								Value:       strVal("test@gmail.com"),
							},
						},
					},
				},
				Obtainable: []expectedCredentialDescriptor{
					{CredentialId: "test.test.email"},
				},
			},
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.MijnOverheid.fullName",
						Name:         clientmodels.TranslatedString{"en": "Demo Name", "nl": "Demo Naam"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo MijnOverheid.nl", "nl": "Demo MijnOverheid.nl"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"firstnames"},
								DisplayName: &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
								Description: &clientmodels.TranslatedString{"en": "All of your first names", "nl": "Al uw voornamen"},
								Value:       strVal("Barry"),
							},
							{
								Path:        []any{"familyname"},
								DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
								Description: &clientmodels.TranslatedString{"en": "Your family name", "nl": "Uw achternaam"},
								Value:       strVal("Batsbak"),
							},
						},
					},
				},
				Obtainable: []expectedCredentialDescriptor{
					{CredentialId: "irma-demo.RU.studentCard"},
				},
			},
		},
	})

	// finish second issuance request
	_ = awaitSessionState(t, sessionHandler)

	email := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	overheid := plan.DisclosureChoicesOverview[1].OwnedOptions[0]

	grantPermission(t, c, 1,
		makeDisclosureChoice(email),
		makeDisclosureChoice(overheid),
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "test.test.email.email", Value: "test@gmail.com"},
		},
		{
			{Identifier: "irma-demo.MijnOverheid.fullName.firstnames", Value: "Barry"},
			{Identifier: "irma-demo.MijnOverheid.fullName.familyname", Value: "Batsbak"},
		},
	})
}

func testWrongCredentialIssuedDuringDisclosure(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Request a student card with a specific university value
	requiredValue := "Radboud University"
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.AttributeRequest{
					Type:  irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"),
					Value: &requiredValue,
				},
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
		},
	}

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(1, sessionJson)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"level"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
							RequestedValue: strVal("Radboud University"),
						},
					},
				},
			}},
		},
		WrongCredentialIssuedNil: true,
	})

	// Issue a credential with a non-matching university value
	wrongRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
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
	issue(t, irmaServer, c, sessionHandler, 2, wrongRequest)

	// Disclosure session updates but the credential doesn't satisfy the required value
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{},
		WrongCredentialIssued: &expectedCredentialDescriptor{
			CredentialId: "irma-demo.RU.studentCard",
			Attributes: []expectedAttr{
				{
					Path:           []any{"university"},
					DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
					Value:          strVal("University of the Arts"),
					RequestedValue: strVal("Radboud University"),
				},
			},
		},
	})

	// Finish the first wrong issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Issue a second credential with a different non-matching university value
	wrongRequest2 := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "Open University",
				"studentCardNumber": "12345",
				"studentID":         "67890",
				"level":             "high",
			},
		},
	})
	issue(t, irmaServer, c, sessionHandler, 3, wrongRequest2)

	// Disclosure session updates again, still not satisfied
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan

	// The frontend should show the latest wrongly issued credential, not the first one
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{},
		WrongCredentialIssued: &expectedCredentialDescriptor{
			CredentialId: "irma-demo.RU.studentCard",
			Attributes: []expectedAttr{
				{
					Path:        []any{"university"},
					DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
					Value:       strVal("Open University"),
				},
			},
		},
	})

	// Finish the second wrong issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Now issue the correct credential
	correctRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "Radboud University",
				"studentCardNumber": "12345",
				"studentID":         "67890",
				"level":             "high",
			},
		},
	})
	issue(t, irmaServer, c, sessionHandler, 4, correctRequest)

	// Disclosure session now satisfiable
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds:      map[string]struct{}{"irma-demo.RU.studentCard": {}},
		WrongCredentialIssuedNil: true,
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo Radboud University Nijmegen", "nl": "Demo Radboud Universiteit Nijmegen"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"level"},
								DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
								Description: &clientmodels.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"},
								Value:       strVal("high"),
							},
							{
								Path:           []any{"university"},
								DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								Description:    &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
								Value:          strVal("Radboud University"),
								RequestedValue: strVal("Radboud University"),
							},
						},
					},
				},
			},
		},
	})

	// Finish issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 4, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Grant permission and complete
	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "irma-demo.RU.studentCard.university", Value: "Radboud University"},
			{Identifier: "irma-demo.RU.studentCard.level", Value: "high"},
		},
	})
}

func testPreExistingWrongCredentialNotReported(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Pre-issue a credential with a non-matching university value BEFORE the disclosure session
	preExistingRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
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
	issue(t, irmaServer, c, sessionHandler, 1, preExistingRequest)

	// Finish the issuance session
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Now start a disclosure session that requires a specific university value
	requiredValue := "Radboud University"
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.AttributeRequest{
					Type:  irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.university"),
					Value: &requiredValue,
				},
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
		},
	}

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(2, sessionJson)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan

	// The pre-existing credential with the wrong value should NOT be reported as wrongly issued
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"level"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
							RequestedValue: strVal("Radboud University"),
						},
					},
				},
			}},
		},
		WrongCredentialIssuedNil: true,
	})

	// Now issue another wrong credential DURING the disclosure session
	wrongDuringSession := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "Open University",
				"studentCardNumber": "12345",
				"studentID":         "67890",
				"level":             "high",
			},
		},
	})
	issue(t, irmaServer, c, sessionHandler, 3, wrongDuringSession)

	// Disclosure session updates
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan

	// Only the newly issued wrong credential should be reported, not the pre-existing one
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{},
		WrongCredentialIssued: &expectedCredentialDescriptor{
			CredentialId: "irma-demo.RU.studentCard",
			Attributes: []expectedAttr{
				{
					Path:        []any{"university"},
					DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
					Value:       strVal("Open University"),
				},
			},
		},
	})

	// Finish the wrong issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Issue the correct credential to complete the flow
	correctRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "Radboud University",
				"studentCardNumber": "12345",
				"studentID":         "67890",
				"level":             "high",
			},
		},
	})
	issue(t, irmaServer, c, sessionHandler, 4, correctRequest)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds:      map[string]struct{}{"irma-demo.RU.studentCard": {}},
		WrongCredentialIssuedNil: true,
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo Radboud University Nijmegen", "nl": "Demo Radboud Universiteit Nijmegen"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"level"},
								DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
								Description: &clientmodels.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"},
								Value:       strVal("high"),
							},
							{
								Path:           []any{"university"},
								DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								Description:    &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
								Value:          strVal("Radboud University"),
								RequestedValue: strVal("Radboud University"),
							},
						},
					},
				},
			},
		},
	})

	// Finish issuance and complete disclosure
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 4, clientmodels.Type_Issuance, clientmodels.Status_Success)

	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 2, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "irma-demo.RU.studentCard.university", Value: "Radboud University"},
			{Identifier: "irma-demo.RU.studentCard.level", Value: "high"},
		},
	})
}

func testChoiceBetweenTwoNonSingletonCredentialsBothPresent(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issue(t, irmaServer, c, sessionHandler, 1, createStudentCardIssuanceRequest())
	_ = awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, 2, createEmailIssuanceRequest())
	_ = awaitSessionState(t, sessionHandler)

	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
		},
	}

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(3, sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo Radboud University Nijmegen", "nl": "Demo Radboud Universiteit Nijmegen"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"level"},
								DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
								Description: &clientmodels.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"},
								Value:       strVal("high"),
							},
							{
								Path:        []any{"university"},
								DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								Description: &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
								Value:       strVal("University of the Arts"),
							},
						},
					},
					{
						CredentialId: "test.test.email",
						Name:         clientmodels.TranslatedString{"en": "Demo Email address", "nl": "Demo E-mailadres"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo test issuer", "nl": "Demo test issuer"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
								Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
								Value:       strVal("test@gmail.com"),
							},
						},
					},
				},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Attributes: []expectedAttr{
							{
								Path:           []any{"level"},
								DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:        []any{"studentID"},
								DisplayName: &clientmodels.TranslatedString{"en": "Student number", "nl": "Studentnummer"},
								Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:        []any{"studentCardNumber"},
								DisplayName: &clientmodels.TranslatedString{"en": "Student card number", "nl": "Studentenkaartnummer"},
								Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:           []any{"university"},
								DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
						},
					},
					{
						CredentialId: "test.test.email",
						Attributes: []expectedAttr{
							{
								Path:           []any{"email"},
								DisplayName:    &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
						},
					},
				},
			},
		},
	})

	studentCard := plan.DisclosureChoicesOverview[0].OwnedOptions[slices.IndexFunc(
		plan.DisclosureChoicesOverview[0].OwnedOptions,
		func(b *clientmodels.DisclosureBundle) bool {
			return len(b.Credentials) > 0 && b.Credentials[0].CredentialId == "irma-demo.RU.studentCard"
		},
	)]

	grantPermission(t, c, session.Id, makeDisclosureChoice(studentCard))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "irma-demo.RU.studentCard.university", Value: "University of the Arts"},
			{Identifier: "irma-demo.RU.studentCard.level", Value: "high"},
		},
	})
}

func testChoiceBetweenEmailAndStudentCardBothPresent(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issue(t, irmaServer, c, sessionHandler, 1, createEmailIssuanceRequest())
	_ = awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, 2, createStudentCardIssuanceRequest())
	_ = awaitSessionState(t, sessionHandler)

	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
			irma.AttributeCon{irma.NewAttributeRequest("irma-demo.RU.studentCard.university")},
		},
	}

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(3, sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "test.test.email",
						Name:         clientmodels.TranslatedString{"en": "Demo Email address", "nl": "Demo E-mailadres"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo test issuer", "nl": "Demo test issuer"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
								Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
								Value:       strVal("test@gmail.com"),
							},
						},
					},
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo Radboud University Nijmegen", "nl": "Demo Radboud Universiteit Nijmegen"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"university"},
								DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								Description: &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
								Value:       strVal("University of the Arts"),
							},
						},
					},
				},
				Obtainable: []expectedCredentialDescriptor{
					{CredentialId: "test.test.email"},
					{CredentialId: "irma-demo.RU.studentCard"},
				},
			},
		},
	})

	emailOption := plan.DisclosureChoicesOverview[0].OwnedOptions[slices.IndexFunc(
		plan.DisclosureChoicesOverview[0].OwnedOptions,
		func(b *clientmodels.DisclosureBundle) bool {
			return len(b.Credentials) > 0 && b.Credentials[0].CredentialId == "test.test.email"
		},
	)]

	grantPermission(t, c, session.Id, makeDisclosureChoice(emailOption))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "test.test.email.email", Value: "test@gmail.com"},
		},
	})
}

func testChoiceBetweenSingletonAndNonSingletonCredentialsNonePresent(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = studentCardOrMijnOverheidDisclosure()

	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan

	// the user should get one step to issue one of two options
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"level"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
				{
					CredentialId: "irma-demo.MijnOverheid.fullName",
					Attributes: []expectedAttr{
						{
							Path:           []any{"firstnames"},
							DisplayName:    &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"familyname"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{},
	})

	issue(t, irmaServer, c, sessionHandler, 2, createStudentCardIssuanceRequest())

	// disclosure session updated
	session = awaitSessionState(t, sessionHandler)

	// the user should now have no steps left because the step index is 1
	// but the previous step should still be available for UX purposes
	plan = session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.RU.studentCard",
					Attributes: []expectedAttr{
						{
							Path:           []any{"level"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"university"},
							DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
				{
					CredentialId: "irma-demo.MijnOverheid.fullName",
					Attributes: []expectedAttr{
						{
							Path:           []any{"firstnames"},
							DisplayName:    &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"familyname"},
							DisplayName:    &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{"irma-demo.RU.studentCard": {}},
		// the disclosure choices overview should allow the user to add new versions of student card
		// and issue the MijnOverheid credential; only one obtained option should be available
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo Radboud University Nijmegen", "nl": "Demo Radboud Universiteit Nijmegen"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"level"},
								DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
								Description: &clientmodels.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"},
								Value:       strVal("high"),
							},
							{
								Path:        []any{"university"},
								DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								Description: &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
								Value:       strVal("University of the Arts"),
							},
						},
					},
				},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Attributes: []expectedAttr{
							{
								Path:           []any{"level"},
								DisplayName:    &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:        []any{"studentID"},
								DisplayName: &clientmodels.TranslatedString{"en": "Student number", "nl": "Studentnummer"},
								Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:        []any{"studentCardNumber"},
								DisplayName: &clientmodels.TranslatedString{"en": "Student card number", "nl": "Studentenkaartnummer"},
								Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:           []any{"university"},
								DisplayName:    &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
						},
					},
					{
						CredentialId: "irma-demo.MijnOverheid.fullName",
						Attributes: []expectedAttr{
							{
								Path:           []any{"firstnames"},
								DisplayName:    &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:        []any{"firstname"},
								DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"},
								Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:           []any{"familyname"},
								DisplayName:    &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
							{
								Path:        []any{"prefix"},
								DisplayName: &clientmodels.TranslatedString{"en": "Prefix", "nl": "Tussenvoegsel"},
								Value:       &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
						},
					},
				},
			},
		},
	})

	// issuance session finished
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 2, session.Id)
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

	c.NewSession(1, sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, clientmodels.Protocol_Irma)
	require.Equal(t, session.Status, clientmodels.Status_RequestPermission)
	require.Equal(t, session.Type, clientmodels.Type_Disclosure)
	require.Equal(t, session.Id, 1)

	plan := session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.MijnOverheid.fullName",
					Attributes: []expectedAttr{
						{
							Path:           []any{"firstname"},
							DisplayName:    &clientmodels.TranslatedString{"nl": "Voornaam", "en": "First name"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"familyname"},
							DisplayName:    &clientmodels.TranslatedString{"nl": "Achternaam", "en": "Family name"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{},
	})

	// start the issuance session
	issRequest := startSameDeviceIrmaSessionAtServer(t, irmaServer, createMijnOverheidIssuanceRequest())
	c.NewSession(2, issRequest)
	issuanceSession := awaitSessionState(t, sessionHandler)
	require.Equal(t, issuanceSession.Status, clientmodels.Status_RequestPermission)
	require.Equal(t, issuanceSession.Id, 2)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: issuanceSession.Id,
		Type:      clientmodels.UI_Permission,
		Payload: clientmodels.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})

	// expect the disclosure session to get updated
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)

	// expect the issuance session to be done
	issuanceSession = awaitSessionState(t, sessionHandler)
	require.Equal(t, issuanceSession.Id, 2)
	require.Equal(t, issuanceSession.Status, clientmodels.Status_Success)

	plan = session.DisclosurePlan

	// no more credentials left to issue (but the list of issuance steps should still be available)
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "irma-demo.MijnOverheid.fullName",
					Attributes: []expectedAttr{
						{
							Path:           []any{"firstname"},
							DisplayName:    &clientmodels.TranslatedString{"nl": "Voornaam", "en": "First name"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
						{
							Path:           []any{"familyname"},
							DisplayName:    &clientmodels.TranslatedString{"nl": "Achternaam", "en": "Family name"},
							RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
						},
					},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}},
		// the disclosure options should contain the option;
		// no new version of this is obtainable because it's a singleton
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.MijnOverheid.fullName",
						Name:         clientmodels.TranslatedString{"en": "Demo Name", "nl": "Demo Naam"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo MijnOverheid.nl", "nl": "Demo MijnOverheid.nl"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"firstname"},
								DisplayName: &clientmodels.TranslatedString{"nl": "Voornaam", "en": "First name"},
								Description: &clientmodels.TranslatedString{"en": "Your first name", "nl": "Uw voornaam"},
								Value:       strVal("Bar"),
							},
							{
								Path:        []any{"familyname"},
								DisplayName: &clientmodels.TranslatedString{"nl": "Achternaam", "en": "Family name"},
								Description: &clientmodels.TranslatedString{"en": "Your family name", "nl": "Uw achternaam"},
								Value:       strVal("Batsbak"),
							},
						},
					},
				},
			},
		},
	})
}

func testSingleCredentialDisclosureWithAvailableSingletonCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issue(t, irmaServer, c, sessionHandler, 1, createMijnOverheidIssuanceRequest())
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

	c.NewSession(2, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan

	// no issuance steps
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.MijnOverheid.fullName",
						Name:         clientmodels.TranslatedString{"en": "Demo Name", "nl": "Demo Naam"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo MijnOverheid.nl", "nl": "Demo MijnOverheid.nl"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"firstname"},
								DisplayName: &clientmodels.TranslatedString{"nl": "Voornaam", "en": "First name"},
								Description: &clientmodels.TranslatedString{"en": "Your first name", "nl": "Uw voornaam"},
								Value:       strVal("Bar"),
							},
							{
								Path:        []any{"familyname"},
								DisplayName: &clientmodels.TranslatedString{"nl": "Achternaam", "en": "Family name"},
								Description: &clientmodels.TranslatedString{"en": "Your family name", "nl": "Uw achternaam"},
								Value:       strVal("Batsbak"),
							},
						},
					},
				},
			},
		},
	})
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
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
		},
	}

	c.DeleteKeyshareTokens()
	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)
	require.NotNil(t, session.DisclosurePlan)

	plan := session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{
					CredentialId: "test.test.email",
					Name:         &clientmodels.TranslatedString{"nl": "Demo E-mailadres", "en": "Demo Email address"},
				},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{},
	})
}

func testSingleCredentialDisclosureWithAvailableCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	schemalessPerformIrmaIssuanceSession(t, c, sessionHandler, irmaServer, 1,
		createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"),
	)

	disclosureRequest := irma.NewDisclosureRequest()
	disclosureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
		},
	}

	c.DeleteKeyshareTokens()
	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, disclosureRequest)
	c.NewSession(2, sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)
	require.NotNil(t, session.DisclosurePlan)

	plan := session.DisclosurePlan

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		// it's also possible to obtain a new one, since it not a singleton
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "test.test.email",
						Name:         clientmodels.TranslatedString{"en": "Demo Email address", "nl": "Demo E-mailadres"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo test issuer", "nl": "Demo test issuer"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
								Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
								Value:       strVal("test@gmail.com"),
							},
						},
					},
				},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "test.test.email",
						Attributes: []expectedAttr{
							{
								Path:           []any{"email"},
								DisplayName:    &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
								RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
								Value:          &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String},
							},
						},
					},
				},
			},
		},
	})

	emailCred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(emailCred))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPin)

	// give pin
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_EnteredPin,
		Payload:   clientmodels.PinInteractionPayload{Pin: "12345", Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "test.test.email.email", Value: "test@gmail.com"},
		},
	})
}

func testDisclosureClientReturnUrl(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = studentCardDisclosure()
	request.ClientReturnURL = "https://yivi.app"

	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	require.Equal(t, "https://yivi.app", session.ClientReturnUrl)
}

// testClientReturnUrlNotDispatchedBeforeStatusPopulated guards against a
// regression where ClientReturnURLSet would dispatch the SessionState before
// any other field had been populated, producing a state with Status == ""
// (the Go zero value). Frontends that JSON-decode SessionState as a typed
// enum reject the empty value and crash. The fix is in irmaSessionAdapter:
// if Status is still empty, store the URL on State and let the next
// dispatch (RequestPermission/RequestPin/etc.) carry it.
//
// The first state we receive must therefore have a populated Status and
// the URL set.
func testClientReturnUrlNotDispatchedBeforeStatusPopulated(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	const returnURL = "tel:+31612345678"

	request := irma.NewDisclosureRequest()
	request.Disclose = studentCardDisclosure()
	request.ClientReturnURL = returnURL

	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	first := awaitSessionState(t, sessionHandler)

	require.NotEmpty(t, first.Status,
		"first dispatched SessionState must not have an empty Status; "+
			"ClientReturnURLSet should defer dispatch until Status is set")
	require.Equal(t, clientmodels.Status_RequestPermission, first.Status)
	require.Equal(t, clientmodels.Type_Disclosure, first.Type)
	require.Equal(t, returnURL, first.ClientReturnUrl)
	require.NotNil(t, first.Requestor.Name,
		"requestor info must be populated by the time the URL is delivered")
}

// Mirrors irmamobile's `attribute-order` integration test
// (yivi_app/integration_test/disclosure_session/special_scenarios/attribute_order.dart),
// which uses irma-demo.gemeente.address — that scheme isn't present in irmago's
// testdata, so we use MijnOverheid.fullName as an analogous 4-attribute fixture.
//
// The schema for MijnOverheid.fullName declares attributes in this order:
// firstnames, firstname, familyname, prefix. The request asks for them in the
// reverse order. The disclosure plan must reorder them back to schema order so
// frontends can render attributes consistently regardless of how the verifier
// happened to phrase the request.
func testDisclosureAttributeOrderFollowsSchema(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issue(t, irmaServer, c, sessionHandler, 1, createMijnOverheidIssuanceRequest())
	_ = awaitSessionState(t, sessionHandler)

	// Single ConDisCon → DisCon → Con, matching the irmamobile test's
	// "disclose": [[[ ... ]]] structure. Attributes deliberately reversed
	// from the schema declaration order.
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.prefix"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
			},
		},
	}

	c.NewSession(2, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "irma-demo.MijnOverheid.fullName",
						Name:         clientmodels.TranslatedString{"en": "Demo Name", "nl": "Demo Naam"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo MijnOverheid.nl", "nl": "Demo MijnOverheid.nl"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"firstnames"},
								DisplayName: &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
								Description: &clientmodels.TranslatedString{"en": "All of your first names", "nl": "Al uw voornamen"},
								Value:       strVal("Barry"),
							},
							{
								Path:        []any{"firstname"},
								DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"},
								Description: &clientmodels.TranslatedString{"en": "Your first name", "nl": "Uw voornaam"},
								Value:       strVal("Bar"),
							},
							{
								Path:        []any{"familyname"},
								DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
								Description: &clientmodels.TranslatedString{"en": "Your family name", "nl": "Uw achternaam"},
								Value:       strVal("Batsbak"),
							},
							{
								Path:        []any{"prefix"},
								DisplayName: &clientmodels.TranslatedString{"en": "Prefix", "nl": "Tussenvoegsel"},
								Description: &clientmodels.TranslatedString{"en": "Family name prefix", "nl": "Tussenvoegsel van uw achternaam"},
								Value:       strVal("Sir"),
							},
						},
					},
				},
			},
		},
	})
}
