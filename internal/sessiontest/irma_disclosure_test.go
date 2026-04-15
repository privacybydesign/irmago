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
	c.NewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Nil(t, plan.DisclosureChoicesOverview)

	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	step1 := plan.IssueDuringDislosure.Steps[0]
	require.Len(t, step1.Options, 1)

	expectedValue := value

	require.Equal(t, step1.Options[0].Attributes, []clientmodels.Attribute{
		{
			ClaimPath: []any{"studentID"},
			DisplayName: clientmodels.TranslatedString{
				"nl": "Studentnummer",
				"en": "Student number",
			},
			RequestedValue: &clientmodels.AttributeValue{
				Type: clientmodels.AttributeType_String,
			},
		},
		{
			ClaimPath: []any{"university"},
			DisplayName: clientmodels.TranslatedString{
				"nl": "Universiteit",
				"en": "University",
			},
			RequestedValue: &clientmodels.AttributeValue{
				Type:   clientmodels.AttributeType_String,
				String: &expectedValue,
			},
		},
	})

	// issue the credential with an invalid value
	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequest())
	// updated disclosure request
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)

	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	// since the issued credential doesn't satisfy the pre-defined value, pretend like it hasn't been issued
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// only the mismatched pre-defined attribute should be reported
	wrongCred := plan.IssueDuringDislosure.WrongCredentialIssued
	require.NotNil(t, wrongCred)
	require.Equal(t, "irma-demo.RU.studentCard", wrongCred.CredentialId)
	// only university (which has a pre-defined value that doesn't match), not studentID
	requireAttrsInOrder(t, wrongCred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("University of the Arts"),
		},
	)
	require.Equal(t, &expectedValue, wrongCred.Attributes[0].RequestedValue.String)

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
	issue(t, irmaServer, c, sessionHandler, issueRequest)
	session = awaitSessionState(t, sessionHandler)

	// expect the disclosure session to be updated and satisfiable
	require.Equal(t, session.Id, 1)
	plan = session.DisclosurePlan
	require.Equal(t,
		plan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
	)
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	// once satisfied, the wrong credential notification should be cleared
	require.Nil(t, plan.IssueDuringDislosure.WrongCredentialIssued)
	// once satisfied, the option is no longer obtainable, since theorectially it doesn't matter
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1})

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

	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)
	plan := session.DisclosurePlan
	// only attributes from one credential type is asked, so we only expect one step to obtain that one
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// issue that credential
	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequest())

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	plan = session.DisclosurePlan
	require.Equal(t, map[string]struct{}{"irma-demo.RU.studentCard": {}}, plan.IssueDuringDislosure.IssuedCredentialIds)

	// expect two disclosure choices, one is optional
	require.Len(t, plan.DisclosureChoicesOverview, 2)
	require.False(t, plan.DisclosureChoicesOverview[0].Optional)
	require.True(t, plan.DisclosureChoicesOverview[1].Optional)
}

func testIrmaDisclosureRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = studentCardDisclosure()

	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
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
	schemalessPerformIrmaIssuanceSession(t, c, sessionHandler, irmaServer,
		createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"),
	)

	// Now start a disclosure session for that credential
	disclosureRequest := irma.NewDisclosureRequest()
	disclosureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
		},
	}

	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, disclosureRequest))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	// Requestor should have a logo that exists on disk
	require.NotNil(t, session.Requestor.ImagePath, "requestor ImagePath should not be nil")
	require.FileExists(t, *session.Requestor.ImagePath)

	// Disclosure plan credential issuers should have logos that exist on disk
	require.NotNil(t, session.DisclosurePlan)
	for _, choice := range session.DisclosurePlan.DisclosureChoicesOverview {
		for _, opt := range choice.OwnedOptions {
			require.NotNil(t, opt.Issuer.ImagePath, "issuer ImagePath for %s should not be nil", opt.CredentialId)
			require.FileExists(t, *opt.Issuer.ImagePath)
		}
		for _, opt := range choice.ObtainableOptions {
			require.NotNil(t, opt.Issuer.ImagePath, "issuer ImagePath for %s should not be nil", opt.CredentialId)
			require.FileExists(t, *opt.Issuer.ImagePath)
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
		mijnOverheidDisclosure()[0],
	}

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	plan := session.DisclosurePlan

	// only one step required to make the disclosure satisfiable, since the student card is optional
	requireIssuanceSteps(t, plan, 1)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// satisfy the required credential (not the optional)
	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequest())

	// disclosure session updated
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)

	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	require.Equal(t,
		map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}},
		plan.IssueDuringDislosure.IssuedCredentialIds,
	)
	// there's two choices, one of which is optional
	requireDisclosureChoices(t, plan, expectedPickOne{optional: true, obtainable: 1}, expectedPickOne{owned: 1})

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
		studentCardOrMijnOverheidDisclosure()[0],
	}

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)

	// the user should get two steps: one for email, one with choice between student card and MijnOverheid
	requireIssuanceSteps(t, plan, 1, 2)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)

	// no disclosure choices overview yet since the session is not finishable
	require.Nil(t, plan.DisclosureChoicesOverview)

	// issue email
	issue(t, irmaServer, c, sessionHandler, createEmailIssuanceRequest())
	session = awaitSessionState(t, sessionHandler)

	// updated disclosure session
	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.Len(t, session.DisclosurePlan.IssueDuringDislosure.Steps, 2)
	require.Equal(t,
		map[string]struct{}{"test.test.email": {}},
		session.DisclosurePlan.IssueDuringDislosure.IssuedCredentialIds,
	)

	// finished issuance session
	_ = awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequest())

	// new disclosure choices
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)

	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 2)

	// both credentials have now been issued, which means the request is satisfiable
	require.Equal(t,
		map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}, "test.test.email": {}},
		plan.IssueDuringDislosure.IssuedCredentialIds,
	)

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
	c.NewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	requireIssuanceSteps(t, plan, 1)
	require.Nil(t, plan.IssueDuringDislosure.WrongCredentialIssued)

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
	issue(t, irmaServer, c, sessionHandler, wrongRequest)

	// Disclosure session updates but the credential doesn't satisfy the required value
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// Only the mismatched pre-defined attribute should be reported
	wrongCred := plan.IssueDuringDislosure.WrongCredentialIssued
	require.NotNil(t, wrongCred)
	require.Equal(t, "irma-demo.RU.studentCard", wrongCred.CredentialId)
	// only university (which has a pre-defined value that doesn't match), not level
	requireAttrsInOrder(t, wrongCred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("University of the Arts"),
		},
	)
	expectedRequiredValue := requiredValue
	require.Equal(t, &expectedRequiredValue, wrongCred.Attributes[0].RequestedValue.String)

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
	issue(t, irmaServer, c, sessionHandler, wrongRequest2)

	// Disclosure session updates again, still not satisfied
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// The frontend should show the latest wrongly issued credential, not the first one
	wrongCred = plan.IssueDuringDislosure.WrongCredentialIssued
	require.NotNil(t, wrongCred)
	require.Equal(t, "irma-demo.RU.studentCard", wrongCred.CredentialId)
	requireAttrsInOrder(t, wrongCred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("Open University"),
		},
	)

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
	issue(t, irmaServer, c, sessionHandler, correctRequest)

	// Disclosure session now satisfiable
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan
	require.Equal(t,
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
		plan.IssueDuringDislosure.IssuedCredentialIds,
	)
	// Wrong credential notification is cleared once the step is satisfied
	require.Nil(t, plan.IssueDuringDislosure.WrongCredentialIssued)
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1})

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
	issue(t, irmaServer, c, sessionHandler, preExistingRequest)

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
	c.NewSession(sessionJson)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	requireIssuanceSteps(t, plan, 1)

	// The pre-existing credential with the wrong value should NOT be reported as wrongly issued
	require.Nil(t, plan.IssueDuringDislosure.WrongCredentialIssued)

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
	issue(t, irmaServer, c, sessionHandler, wrongDuringSession)

	// Disclosure session updates
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// Only the newly issued wrong credential should be reported, not the pre-existing one
	wrongCred := plan.IssueDuringDislosure.WrongCredentialIssued
	require.NotNil(t, wrongCred)
	require.Equal(t, "irma-demo.RU.studentCard", wrongCred.CredentialId)
	requireAttrsInOrder(t, wrongCred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("Open University"),
		},
	)

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
	issue(t, irmaServer, c, sessionHandler, correctRequest)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan
	require.Equal(t,
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
		plan.IssueDuringDislosure.IssuedCredentialIds,
	)
	require.Nil(t, plan.IssueDuringDislosure.WrongCredentialIssued)
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1})

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
	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequest())
	_ = awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, createEmailIssuanceRequest())
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
	c.NewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

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
		func(c *clientmodels.SelectableCredentialInstance) bool {
			return c.CredentialId == "irma-demo.RU.studentCard"
		},
	)]

	require.Equal(t,
		[]clientmodels.Attribute{
			{
				ClaimPath:   []any{"university"},
				DisplayName: clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
				Description: &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
				Value: &clientmodels.AttributeValue{
					Type:   clientmodels.AttributeType_String,
					String: strPtr("University of the Arts"),
				},
			},
			{
				ClaimPath:   []any{"level"},
				DisplayName: clientmodels.TranslatedString{"en": "Type", "nl": "Soort"},
				Description: &clientmodels.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"},
				Value: &clientmodels.AttributeValue{
					Type:   clientmodels.AttributeType_String,
					String: strPtr("high"),
				},
			},
		},
		studentCard.Attributes,
	)

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
	issue(t, irmaServer, c, sessionHandler, createEmailIssuanceRequest())
	_ = awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequest())
	_ = awaitSessionState(t, sessionHandler)

	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
			irma.AttributeCon{irma.NewAttributeRequest("irma-demo.RU.studentCard.university")},
		},
	}

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Nil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	opt := plan.DisclosureChoicesOverview[0]
	// both credentials are owned
	require.Len(t, opt.OwnedOptions, 2)

	emailOption := opt.OwnedOptions[slices.IndexFunc(
		opt.OwnedOptions,
		func(c *clientmodels.SelectableCredentialInstance) bool { return c.CredentialId == "test.test.email" },
	)]
	require.Equal(t, "test.test.email", emailOption.CredentialId)
	require.Equal(t, []clientmodels.Attribute{
		{
			ClaimPath:   []any{"email"},
			DisplayName: clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
			Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
			Value: &clientmodels.AttributeValue{
				Type:   clientmodels.AttributeType_String,
				String: strPtr("test@gmail.com"),
			},
		},
	}, emailOption.Attributes)

	studentCardOption := opt.OwnedOptions[slices.IndexFunc(
		opt.OwnedOptions,
		func(c *clientmodels.SelectableCredentialInstance) bool {
			return c.CredentialId == "irma-demo.RU.studentCard"
		},
	)]
	require.Equal(t, "irma-demo.RU.studentCard", studentCardOption.CredentialId)
	require.Equal(t, []clientmodels.Attribute{
		{
			ClaimPath:   []any{"university"},
			DisplayName: clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Description: &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
			Value: &clientmodels.AttributeValue{
				Type:   clientmodels.AttributeType_String,
				String: strPtr("University of the Arts"),
			},
		},
	}, studentCardOption.Attributes)

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

	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)

	// the user should get one step to issue one of two options
	requireIssuanceSteps(t, plan, 2)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
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
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
		plan.IssueDuringDislosure.IssuedCredentialIds,
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

	c.NewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, clientmodels.Protocol_Irma)
	require.Equal(t, session.Status, clientmodels.Status_RequestPermission)
	require.Equal(t, session.Type, clientmodels.Type_Disclosure)
	require.Equal(t, session.Id, 1)

	plan := session.DisclosurePlan

	require.NotNil(t, plan)
	requireIssuanceSteps(t, plan, 1)
	require.Len(t, plan.IssueDuringDislosure.IssuedCredentialIds, 0)

	toIssue := plan.IssueDuringDislosure.Steps[0].Options[0]
	require.Equal(t, toIssue.CredentialId, "irma-demo.MijnOverheid.fullName")

	require.Equal(t, toIssue.Attributes, []clientmodels.Attribute{
		{
			ClaimPath:   []any{"firstname"},
			DisplayName: clientmodels.TranslatedString{"nl": "Voornaam", "en": "First name"},
			RequestedValue: &clientmodels.AttributeValue{
				Type: clientmodels.AttributeType_String,
			},
		},
		{
			ClaimPath:   []any{"familyname"},
			DisplayName: clientmodels.TranslatedString{"nl": "Achternaam", "en": "Family name"},
			RequestedValue: &clientmodels.AttributeValue{
				Type: clientmodels.AttributeType_String,
			},
		},
	})

	// start the issuance session
	issRequest := startSameDeviceIrmaSessionAtServer(t, irmaServer, createMijnOverheidIssuanceRequest())
	c.NewSession(issRequest)
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

	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)

	// no issuance steps
	require.Nil(t, plan.IssueDuringDislosure)

	require.Len(t, plan.DisclosureChoicesOverview, 1)
	discon := plan.DisclosureChoicesOverview[0]

	require.Len(t, discon.OwnedOptions, 1)
	require.Empty(t, discon.ObtainableOptions)
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
	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)
	require.NotNil(t, session.DisclosurePlan)

	plan := session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)

	credToIssue := plan.IssueDuringDislosure.Steps[0].Options[0]

	require.Equal(t, clientmodels.TranslatedString{"nl": "Demo E-mailadres", "en": "Demo Email address"}, credToIssue.Name)
	require.Equal(t, "test.test.email", credToIssue.CredentialId)
}

func testSingleCredentialDisclosureWithAvailableCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	schemalessPerformIrmaIssuanceSession(t, c, sessionHandler, irmaServer,
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
	c.NewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)
	require.NotNil(t, session.DisclosurePlan)

	plan := session.DisclosurePlan
	require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 1)
	// it's also possible to obtain a new one, since it not a singleton
	require.Len(t, plan.DisclosureChoicesOverview[0].ObtainableOptions, 1)

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

	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	require.Equal(t, "https://yivi.app", session.ClientReturnUrl)
}
