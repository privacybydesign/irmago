package sessiontest

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"

	"github.com/stretchr/testify/require"
)

func testSessionHandlerForOpenId4VpWithIrmaSdJwts(t *testing.T) {
	runEudiSessionTest(t,
		"single credential",
		testOpenID4VP_YiviScheme_SingleCredential,
	)

	runEudiSessionTest(t,
		"choice between two credentials",
		testOpenID4VP_YiviScheme_ChoiceBetweenTwoCredentials,
	)

	runEudiSessionTest(t,
		"complex choices",
		testOpenID4VP_YiviScheme_ComplexChoices,
	)

	runEudiSessionTest(t,
		"optional credential",
		testOpenID4VP_YiviScheme_OptionalCredential,
	)

	runEudiSessionTest(t,
		"predefined claim values",
		testOpenID4VP_YiviScheme_PredefinedClaimValues,
	)

	runEudiSessionTest(t,
		"complex choices without claim ids",
		testOpenID4VP_YiviScheme_ComplexChoices_NoClaimIds,
	)

	runEudiSessionTest(t,
		"claim sets",
		testOpenID4VP_YiviScheme_ClaimSets,
	)

	runEudiSessionTest(t,
		"multiple instances attribute ordering",
		testOpenID4VP_YiviScheme_MultipleInstances_AttributeOrdering,
	)

	runEudiSessionTest(t,
		"unknown credential type results in error",
		testOpenID4VP_YiviScheme_UnknownCredentialError,
	)
}

func testOpenID4VP_YiviScheme_SingleCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	testSession := startOpenID4VPSessionWithAuthRequest(t, c, sessionHandler, createEmailAuthRequestRequest())
	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps:       []expectedIssuanceStep{{Options: []expectedCredentialDescriptor{{CredentialId: "test.test.email"}}}},
		IssuedCredentialIds: map[string]struct{}{},
	})

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	// get updated openid4vp session state
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan = session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{{Options: []expectedCredentialDescriptor{{CredentialId: "test.test.email"}}}},
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{{CredentialId: "test.test.email"}},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "test.test.email",
						Name:         &clientmodels.TranslatedString{"en": "Demo Email address", "nl": "Demo E-mailadres"},
						Attributes: []expectedAttr{
							{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"}, SkipValueCheck: true},
						},
					},
				},
			},
		},
	})

	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1, makeDisclosureChoice(choice))

	// expect end for issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// expect end for disclosure session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireVerifierResult(t, testSession.VerifierSession, expectedVpToken{
		"32f54163-7166-48f1-93d8-ff217bdb0653": {"email": "test@gmail.com"},
	})
}

func testOpenID4VP_YiviScheme_ChoiceBetweenTwoCredentials(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	dcql := `{
		"credentials": [
		  {
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ { "path": ["email"] } ]
		  },
		  {
			"id": "sc",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.RU.studentCard"] },
			"claims": [ { "path": ["university"] }, { "path": ["level"] } ]
		  }
		],
		"credential_sets": [ { "options": [["email"], ["sc"]] } ]
	}`

	testSession := startOpenID4VPSession(t, c, sessionHandler, dcql)
	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{{Options: []expectedCredentialDescriptor{
			{CredentialId: "test.test.email"},
			{CredentialId: "irma-demo.RU.studentCard"},
		}}},
		IssuedCredentialIds: map[string]struct{}{},
	})

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	// get updated openid4vp session state
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan = session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{{Options: []expectedCredentialDescriptor{{CredentialId: "irma-demo.RU.studentCard"}}}},
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{{CredentialId: "test.test.email"}},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "test.test.email",
						Name:         &clientmodels.TranslatedString{"en": "Demo Email address", "nl": "Demo E-mailadres"},
						Attributes: []expectedAttr{
							{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"}, SkipValueCheck: true},
						},
					},
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         &clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						Attributes: []expectedAttr{
							{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, SkipValueCheck: true},
							{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, SkipValueCheck: true},
						},
					},
				},
			},
		},
	})

	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1, makeDisclosureChoice(choice))

	// expect end for issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// expect end for disclosure session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireVerifierResult(t, testSession.VerifierSession, expectedVpToken{
		"email": {"email": "test@gmail.com"},
	})
}

func testOpenID4VP_YiviScheme_ComplexChoices(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// (email || studentcard) && name
	dcql := `{
		"credentials": [
		  {
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ { "id": "1", "path": ["email"] } ]
		  },
		  {
			"id": "sc",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.RU.studentCard"] },
			"claims": [ { "id": "2", "path": ["university"] }, { "id": "3", "path": ["level"] } ]
		  },
		  {
			"id": "name",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.MijnOverheid.fullName"] },
			"claims": [ { "id": "4", "path": ["firstname"] }, { "id": "5", "path": ["familyname"] } ]
		  }
		],
		"credential_sets": [
		  { "options": [["email"], ["sc"]] },
		  { "options": [["name"]] }
		]
	}`

	testSession := startOpenID4VPSession(t, c, sessionHandler, dcql)
	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{CredentialId: "test.test.email", Attributes: []expectedAttr{
					{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
				}},
				{CredentialId: "irma-demo.RU.studentCard", Attributes: []expectedAttr{
					{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
					{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
				}},
			}},
			{Options: []expectedCredentialDescriptor{
				{CredentialId: "irma-demo.MijnOverheid.fullName", Attributes: []expectedAttr{
					{Path: []any{"firstname"}, DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
					{Path: []any{"familyname"}, DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
				}},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{},
	})

	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)

	plan = session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{"irma-demo.RU.studentCard": {}},
	})

	// expect issuance session end
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)
	require.Equal(t, session.Status, clientmodels.Status_Success)

	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequestWithSdJwt())
	session = awaitSessionState(t, sessionHandler)

	// expect disclosure session to be updated
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, clientmodels.Status_RequestPermission)
	plan = session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{"irma-demo.RU.studentCard": {}, "irma-demo.MijnOverheid.fullName": {}},
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{CredentialId: "irma-demo.RU.studentCard", Attributes: []expectedAttr{
						{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, Description: &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"}, Value: strVal("University of the Arts")},
						{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, Description: &clientmodels.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"}, Value: strVal("high")},
					}},
				},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "test.test.email",
						Name:         &clientmodels.TranslatedString{"en": "Demo Email address", "nl": "Demo E-mailadres"},
						Attributes: []expectedAttr{
							{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"}, SkipValueCheck: true},
						},
					},
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         &clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						Attributes: []expectedAttr{
							{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, SkipValueCheck: true},
							{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, SkipValueCheck: true},
						},
					},
				},
			},
			{
				Owned: []expectedPlanCredential{{CredentialId: "irma-demo.MijnOverheid.fullName"}},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "irma-demo.MijnOverheid.fullName",
						Name:         &clientmodels.TranslatedString{"en": "Demo Name", "nl": "Demo Naam"},
						Attributes: []expectedAttr{
							{Path: []any{"firstname"}, DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"}, SkipValueCheck: true},
							{Path: []any{"familyname"}, DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"}, SkipValueCheck: true},
						},
					},
				},
			},
		},
	})

	firstChoice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	secondChoice := plan.DisclosureChoicesOverview[1].OwnedOptions[0]

	// give permission to disclose
	grantPermission(t, c, session.Id,
		makeDisclosureChoice(firstChoice),
		makeDisclosureChoice(secondChoice),
	)

	// expect issuance session to be done
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// expect disclosure session to be done
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireVerifierResult(t, testSession.VerifierSession, expectedVpToken{
		"sc":   {"university": "University of the Arts", "level": "high"},
		"name": {"firstname": "Bar", "familyname": "Batsbak"},
	})
}

func testOpenID4VP_YiviScheme_OptionalCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// required: studentCard; optional: fullName
	dcql := `{
		"credentials": [
		  {
			"id": "sc",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.RU.studentCard"] },
			"claims": [ { "path": ["university"] } ]
		  },
		  {
			"id": "name",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.MijnOverheid.fullName"] },
			"claims": [ { "path": ["firstname"] } ]
		  }
		],
		"credential_sets": [
		  { "options": [["sc"]] },
		  { "options": [["name"]], "required": false }
		]
	}`

	testSession := startOpenID4VPSession(t, c, sessionHandler, dcql)
	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	// only the required studentCard produces an issuance step;
	// the optional fullName set is already satisfied by its empty option
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps:       []expectedIssuanceStep{{Options: []expectedCredentialDescriptor{{CredentialId: "irma-demo.RU.studentCard"}}}},
		IssuedCredentialIds: map[string]struct{}{},
	})

	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())

	// updated disclosure session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{"irma-demo.RU.studentCard": {}},
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{{CredentialId: "irma-demo.RU.studentCard"}},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         &clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						Attributes: []expectedAttr{
							{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, SkipValueCheck: true},
						},
					},
				},
			},
			{
				Optional: true,
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "irma-demo.MijnOverheid.fullName",
						Name:         &clientmodels.TranslatedString{"en": "Demo Name", "nl": "Demo Naam"},
						Attributes: []expectedAttr{
							{Path: []any{"firstname"}, DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"}, SkipValueCheck: true},
						},
					},
				},
			},
		},
	})

	requiredChoice := plan.DisclosureChoicesOverview[0]

	// issuance session ended
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// grant permission with only the required credential; skip the optional one with an empty selection
	sc := requiredChoice.OwnedOptions[0]
	grantPermission(t, c, 1,
		makeDisclosureChoice(sc),
		clientmodels.DisclosureDisconSelection{},
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireVerifierResult(t, testSession.VerifierSession, expectedVpToken{
		"sc": {"university": "University of the Arts"},
	})
}

func testOpenID4VP_YiviScheme_PredefinedClaimValues(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// request studentCard with a specific required university value
	dcql := `{
		"credentials": [
		  {
			"id": "sc",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.RU.studentCard"] },
			"claims": [
			  { "id": "1", "path": ["university"], "values": ["University of the Arts"] },
			  { "id": "2", "path": ["level"] }
			]
		  }
		]
	}`

	testSession := startOpenID4VPSession(t, c, sessionHandler, dcql)
	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	// the issuance step shows the predefined university value as RequestedValue
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{{Options: []expectedCredentialDescriptor{
			{CredentialId: "irma-demo.RU.studentCard", Attributes: []expectedAttr{
				{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, RequestedValue: strVal("University of the Arts"), SkipValueCheck: true},
				{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
			}},
		}}},
	})

	// issue a credential with a non-matching university value
	wrongUniversityRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "Some Other University",
				"studentCardNumber": "12345",
				"studentID":         "67890",
				"level":             "high",
			},
			SdJwtBatchSize: 10,
		},
	})
	issue(t, irmaServer, c, sessionHandler, wrongUniversityRequest)

	// disclosure session updated, but the credential does not satisfy the predefined value
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps:       []expectedIssuanceStep{{Options: []expectedCredentialDescriptor{{CredentialId: "irma-demo.RU.studentCard"}}}},
		IssuedCredentialIds: map[string]struct{}{},
		WrongCredentialIssued: &expectedCredentialDescriptor{
			CredentialId: "irma-demo.RU.studentCard",
			Attributes: []expectedAttr{
				{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, Value: strVal("Some Other University"), RequestedValue: strVal("University of the Arts")},
			},
		},
	})

	// issuance session ended
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// issue a credential with the correct university value
	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())

	// disclosure session updated with the satisfying credential
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan
	// once satisfied, the wrong credential notification should be cleared
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds:      map[string]struct{}{"irma-demo.RU.studentCard": {}},
		WrongCredentialIssuedNil: true,
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{{CredentialId: "irma-demo.RU.studentCard"}},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         &clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						Attributes: []expectedAttr{
							{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, RequestedValue: strVal("University of the Arts"), SkipValueCheck: true},
							{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, SkipValueCheck: true},
						},
					},
				},
			},
		},
	})

	// issuance session ended
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// grant permission to disclose the credential with the correct value
	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1,
		makeDisclosureChoice(choice),
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireVerifierResult(t, testSession.VerifierSession, expectedVpToken{
		"sc": {"university": "University of the Arts", "level": "high"},
	})
}

func testOpenID4VP_YiviScheme_ComplexChoices_NoClaimIds(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Same (email || studentcard) && name logic as testOpenID4VP_YiviScheme_ComplexChoices,
	// but claim objects have no "id" field — DCQL allows this when claim_sets is absent
	// for a credential query, or when the credential_sets only reference credential ids.
	// Note: credential_sets reference credential ids ("email", "sc", "name"), not claim ids.
	dcql := `{
		"credentials": [
		  {
			"id": "email",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.email"] },
			"claims": [ { "path": ["email"] } ]
		  },
		  {
			"id": "sc",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.RU.studentCard"] },
			"claims": [ { "path": ["university"] }, { "path": ["level"] } ]
		  },
		  {
			"id": "name",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.MijnOverheid.fullName"] },
			"claims": [ { "path": ["firstname"] }, { "path": ["familyname"] } ]
		  }
		],
		"credential_sets": [
		  { "options": [["email"], ["sc"]] },
		  { "options": [["name"]] }
		]
	}`

	testSession := startOpenID4VPSession(t, c, sessionHandler, dcql)
	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{
			{Options: []expectedCredentialDescriptor{
				{CredentialId: "test.test.email", Attributes: []expectedAttr{
					{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
				}},
				{CredentialId: "irma-demo.RU.studentCard", Attributes: []expectedAttr{
					{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
					{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
				}},
			}},
			{Options: []expectedCredentialDescriptor{
				{CredentialId: "irma-demo.MijnOverheid.fullName", Attributes: []expectedAttr{
					{Path: []any{"firstname"}, DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
					{Path: []any{"familyname"}, DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
				}},
			}},
		},
		IssuedCredentialIds: map[string]struct{}{},
	})

	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, clientmodels.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)

	plan = session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{"irma-demo.RU.studentCard": {}},
	})

	// expect issuance session end
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)
	require.Equal(t, session.Status, clientmodels.Status_Success)

	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequestWithSdJwt())
	session = awaitSessionState(t, sessionHandler)

	// expect disclosure session to be updated
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, clientmodels.Status_RequestPermission)
	plan = session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{"irma-demo.RU.studentCard": {}, "irma-demo.MijnOverheid.fullName": {}},
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{CredentialId: "irma-demo.RU.studentCard", Attributes: []expectedAttr{
						{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, Description: &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"}, Value: strVal("University of the Arts")},
						{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, Description: &clientmodels.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"}, Value: strVal("high")},
					}},
				},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "test.test.email",
						Name:         &clientmodels.TranslatedString{"en": "Demo Email address", "nl": "Demo E-mailadres"},
						Attributes: []expectedAttr{
							{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"}, SkipValueCheck: true},
						},
					},
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         &clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						Attributes: []expectedAttr{
							{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, SkipValueCheck: true},
							{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, SkipValueCheck: true},
						},
					},
				},
			},
			{
				Owned: []expectedPlanCredential{{CredentialId: "irma-demo.MijnOverheid.fullName"}},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "irma-demo.MijnOverheid.fullName",
						Name:         &clientmodels.TranslatedString{"en": "Demo Name", "nl": "Demo Naam"},
						Attributes: []expectedAttr{
							{Path: []any{"firstname"}, DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"}, SkipValueCheck: true},
							{Path: []any{"familyname"}, DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"}, SkipValueCheck: true},
						},
					},
				},
			},
		},
	})

	firstChoice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	secondChoice := plan.DisclosureChoicesOverview[1].OwnedOptions[0]

	// give permission to disclose
	grantPermission(t, c, session.Id,
		makeDisclosureChoice(firstChoice),
		makeDisclosureChoice(secondChoice),
	)

	// expect issuance session to be done
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// expect disclosure session to be done
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireVerifierResult(t, testSession.VerifierSession, expectedVpToken{
		"sc":   {"university": "University of the Arts", "level": "high"},
		"name": {"firstname": "Bar", "familyname": "Batsbak"},
	})
}

func testOpenID4VP_YiviScheme_ClaimSets(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// The verifier accepts either (university + level) OR just (studentID) from a studentCard.
	// claim_sets provides OR logic for which claims to disclose within a credential.
	dcql := `{
		"credentials": [
		  {
			"id": "sc",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.RU.studentCard"] },
			"claims": [
			  { "id": "univ", "path": ["university"] },
			  { "id": "lvl",  "path": ["level"] },
			  { "id": "sid",  "path": ["studentID"] }
			],
			"claim_sets": [
			  ["univ", "lvl"],
			  ["sid"]
			]
		  }
		]
	}`

	testSession := startOpenID4VPSession(t, c, sessionHandler, dcql)
	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)

	plan := session.DisclosurePlan
	// the issuance step shows the first claim_set (university + level), not studentID
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuanceSteps: []expectedIssuanceStep{{Options: []expectedCredentialDescriptor{
			{CredentialId: "irma-demo.RU.studentCard", Attributes: []expectedAttr{
				{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
				{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, RequestedValue: &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String}, SkipValueCheck: true},
			}},
		}}},
		IssuedCredentialIds: map[string]struct{}{},
	})

	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())

	// disclosure session updated
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan = session.DisclosurePlan
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		IssuedCredentialIds: map[string]struct{}{"irma-demo.RU.studentCard": {}},
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{CredentialId: "irma-demo.RU.studentCard", Attributes: []expectedAttr{
						{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, Description: &clientmodels.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"}, Value: strVal("University of the Arts")},
						{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, Description: &clientmodels.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"}, Value: strVal("high")},
					}},
				},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "irma-demo.RU.studentCard",
						Name:         &clientmodels.TranslatedString{"en": "Demo Student Card", "nl": "Demo Studentenkaart"},
						Attributes: []expectedAttr{
							{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}, SkipValueCheck: true},
							{Path: []any{"level"}, DisplayName: &clientmodels.TranslatedString{"en": "Type", "nl": "Soort"}, SkipValueCheck: true},
						},
					},
				},
			},
		},
	})

	// issuance session ended
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// the first satisfied claim_set (university + level) is offered for disclosure
	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]

	grantPermission(t, c, 1,
		makeDisclosureChoice(choice),
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireVerifierResult(t, testSession.VerifierSession, expectedVpToken{
		"sc": {"university": "University of the Arts", "level": "high"},
	})
}

func testOpenID4VP_YiviScheme_MultipleInstances_AttributeOrdering(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	studentCards := []map[string]string{
		{"university": "University of Amsterdam", "studentCardNumber": "11111", "studentID": "AAA", "level": "bachelor"},
		{"university": "Delft University", "studentCardNumber": "22222", "studentID": "BBB", "level": "master"},
		{"university": "Leiden University", "studentCardNumber": "33333", "studentID": "CCC", "level": "phd"},
	}

	for _, attrs := range studentCards {
		req := irma.NewIssuanceRequest([]*irma.CredentialRequest{
			{
				CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
				Attributes:       attrs,
				SdJwtBatchSize:   10,
			},
		})
		issue(t, irmaServer, c, sessionHandler, req)
		session := awaitSessionState(t, sessionHandler)
		require.Equal(t, clientmodels.Status_Success, session.Status)
	}

	dcql := `{
		"credentials": [
		  {
			"id": "sc",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["irma-demo.RU.studentCard"] },
			"claims": [
				{ "path": ["university"] },
				{ "path": ["studentCardNumber"] },
				{ "path": ["studentID"] },
				{ "path": ["level"] }
			]
		  }
		]
	}`

	testSession := startOpenID4VPSession(t, c, sessionHandler, dcql)
	session := testSession.ClientSession
	requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan.DisclosureChoicesOverview)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pick := plan.DisclosureChoicesOverview[0]
	require.Len(t, pick.OwnedOptions, 3, "should have 3 owned credential instances")

	expectedOrder := []string{pk("university"), pk("studentCardNumber"), pk("studentID"), pk("level")}

	for i, option := range pick.OwnedOptions {
		require.Equal(t, "irma-demo.RU.studentCard", option.CredentialId)
		require.Len(t, option.Attributes, 4, "option %d should have 4 attributes", i)

		actualOrder := make([]string, len(option.Attributes))
		for j, attr := range option.Attributes {
			actualOrder[j] = clientmodels.ClaimPathKey(attr.ClaimPath)
		}
		require.Equal(t, expectedOrder, actualOrder,
			"option %d: attributes should be in scheme-defined order", i)
	}

	// Verify that each issued credential is present (order of owned options may differ from issuance order)
	foundUniversities := map[string]bool{}
	for _, option := range pick.OwnedOptions {
		uni := findAttr(option.Attributes, "university")
		require.NotNil(t, uni, "option should have university attribute")
		require.NotNil(t, uni.Value)
		require.NotNil(t, uni.Value.String)
		foundUniversities[*uni.Value.String] = true
	}
	for _, attrs := range studentCards {
		require.True(t, foundUniversities[attrs["university"]],
			"credential with university %q should be present", attrs["university"])
	}

	// Disclose the Amsterdam credential specifically and verify the result with hardcoded values.
	var chosen *clientmodels.SelectableCredentialInstance
	for _, opt := range pick.OwnedOptions {
		if uni := findAttr(opt.Attributes, "university"); uni != nil && *uni.Value.String == "University of Amsterdam" {
			chosen = opt
			break
		}
	}
	require.NotNil(t, chosen, "should find the Amsterdam credential")

	grantPermission(t, c, session.Id,
		makeDisclosureChoice(chosen),
	)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireVerifierResult(t, testSession.VerifierSession, expectedVpToken{
		"sc": {
			"university":        "University of Amsterdam",
			"studentCardNumber": "11111",
			"studentID":         "AAA",
			"level":             "bachelor",
		},
	})
}

func testOpenID4VP_YiviScheme_UnknownCredentialError(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	dcql := `{
		"credentials": [
		  {
			"id": "unknown",
			"format": "dc+sd-jwt",
			"meta": { "vct_values": ["test.test.test"] },
			"claims": [
			  { "id": "1", "path": ["test"] }
			]
		  }
		]
	}`

	testSession := startOpenID4VPSession(t, c, sessionHandler, dcql)
	session := testSession.ClientSession

	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_Error, session.Status)
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError, "test.test.test")
}

// openID4VPTestSession holds both the client session state and verifier session info
type openID4VPTestSession struct {
	ClientSession   clientmodels.SessionState
	VerifierSession irmaclient.EudiVerifierSession
}

// startOpenID4VPSession starts an OpenID4VP session with DCQL and returns the initial session state
func startOpenID4VPSession(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	dcql string,
) openID4VPTestSession {
	t.Helper()
	return startOpenID4VPSessionWithAuthRequest(t, c, sessionHandler, createAuthRequestRequestWithDcql(dcql))
}

// startOpenID4VPSessionWithAuthRequest starts an OpenID4VP session with an auth request JSON string and returns the initial session state
func startOpenID4VPSessionWithAuthRequest(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	authRequestJson string,
) openID4VPTestSession {
	t.Helper()
	verifierSession, err := irmaclient.StartTestSessionAtEudiVerifier(testdata.OpenID4VP_DirectPostJwt_Host, authRequestJson)
	require.NoError(t, err)
	sessionRequest := client.SessionRequestData{
		Qr: irma.Qr{
			Type: irma.ActionDisclosing,
			URL:  verifierSession.SessionLink,
		},
		Protocol: clientmodels.Protocol_OpenID4VP,
	}
	sessionJson, err := json.Marshal(sessionRequest)
	require.NoError(t, err)

	c.NewSession(string(sessionJson))
	return openID4VPTestSession{
		ClientSession:   awaitSessionState(t, sessionHandler),
		VerifierSession: verifierSession,
	}
}

// expectedVpToken maps DCQL query IDs to the claims expected to be disclosed for that query.
type expectedVpToken map[string]expectedClaims

// expectedClaims maps claim names to their expected values.
type expectedClaims map[string]string

// requireVerifierResult fetches the wallet response from the EUDI verifier and checks that
// the vp_token contains the expected DCQL query IDs with the expected disclosed claims.
func requireVerifierResult(t *testing.T, verifierSession irmaclient.EudiVerifierSession, expectedCredentials expectedVpToken) {
	t.Helper()

	result, err := irmaclient.GetWalletResponseFromEudiVerifier(verifierSession)
	require.NoError(t, err)

	require.Nil(t, result["error"], "verifier returned error: %v", result["error_description"])

	vpToken, ok := result["vp_token"].(map[string]any)
	require.True(t, ok, "vp_token should be a JSON object, got: %T", result["vp_token"])

	require.Len(t, vpToken, len(expectedCredentials), "vp_token should have %d query IDs", len(expectedCredentials))

	for queryID, expectedClaims := range expectedCredentials {
		credArray, ok := vpToken[queryID].([]any)
		require.True(t, ok, "vp_token[%q] should be an array", queryID)
		require.NotEmpty(t, credArray, "vp_token[%q] should contain at least one credential", queryID)

		// Parse disclosed claims from the first SD-JWT in the array
		sdJwtStr, ok := credArray[0].(string)
		require.True(t, ok, "credential should be a string")

		disclosedClaims := extractDisclosedClaims(t, sdJwtStr)

		for expectedName, expectedValue := range expectedClaims {
			actualValue, found := disclosedClaims[expectedName]
			require.True(t, found,
				"query %q: expected disclosed claim %q not found in %v", queryID, expectedName, disclosedClaims)
			require.Equal(t, expectedValue, actualValue,
				"query %q: claim %q has wrong value", queryID, expectedName)
		}
	}
}

// extractDisclosedClaims parses an SD-JWT presentation string and returns the disclosed claims
// as a map of claim name -> claim value.
// An SD-JWT has the format: <issuer-jwt>~<disclosure1>~<disclosure2>~...~<kb-jwt>
// Each disclosure is a base64url-encoded JSON array: [salt, claim-name, claim-value]
func extractDisclosedClaims(t *testing.T, sdJwt string) map[string]string {
	t.Helper()

	parts := strings.Split(sdJwt, "~")
	// An SD-JWT-KB has the format: <issuer-jwt>~<disc1>~<disc2>~...~<kb-jwt>
	// With no disclosures it's just: <issuer-jwt>~<kb-jwt> (2 parts)
	require.GreaterOrEqual(t, len(parts), 2, "SD-JWT should have at least 2 parts (issuer JWT and KB JWT)")

	claims := make(map[string]string)
	// Disclosures are in parts[1..len-2] (between the issuer JWT and KB JWT)
	for _, disclosure := range parts[1 : len(parts)-1] {
		if disclosure == "" {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(disclosure)
		require.NoError(t, err, "failed to decode disclosure: %s", disclosure)

		var arr []any
		require.NoError(t, json.Unmarshal(decoded, &arr), "failed to parse disclosure JSON")
		require.Len(t, arr, 3, "disclosure should be [salt, name, value]")

		name, ok := arr[1].(string)
		require.True(t, ok, "disclosure name should be a string")

		// Claim values are typically strings, but could be other JSON types
		value, ok := arr[2].(string)
		if !ok {
			// Fall back to JSON representation for non-string values
			valueBytes, err := json.Marshal(arr[2])
			require.NoError(t, err)
			value = string(valueBytes)
		}

		claims[name] = value
	}

	return claims
}
