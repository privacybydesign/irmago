package sessiontest

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"

	"github.com/stretchr/testify/require"
)

func TestSessionHandler(t *testing.T) {
	t.Run("disclosure/irma", testSessionHandlerForIrmaDisclosures)
	t.Run("disclosure/openid4vp", testSessionHandlerForOpenID4VPDisclosures)
	t.Run("issuance/irma", testSessionHandlerForIrmaIssuance)
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

	runSessionTest(t,
		"client return url",
		testDisclosureClientReturnUrl,
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

	runSessionTest(t,
		"client return url",
		testIssuanceClientReturnUrl,
	)
}

func testSessionHandlerEdgeCases(t *testing.T) {
	// this test is not working as expected...
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
		"chained session",
		testChainedSession,
	)
}

func testSessionHandlerForOpenID4VPDisclosures(t *testing.T) {
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

	session := startOpenID4VPSession(t, c, sessionHandler, dcql)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)
	require.Equal(t, irmaclient.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan
	requireIssuanceSteps(t, plan, 2, 1)

	firstOption := plan.IssueDuringDislosure.Steps[0].Options[0]
	require.Equal(t, firstOption.CredentialId, "test.test.email")
	require.Equal(t, firstOption.Attributes, []client.Attribute{
		{
			Id: "email",
			DisplayName: client.TranslatedString{
				"en": "Email address",
				"nl": "E-mailadres",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
	})

	secondOption := plan.IssueDuringDislosure.Steps[0].Options[1]
	require.Equal(t, secondOption.CredentialId, "irma-demo.RU.studentCard")
	require.Equal(t, secondOption.Attributes, []client.Attribute{
		{
			Id: "university",
			DisplayName: client.TranslatedString{
				"en": "University",
				"nl": "Universiteit",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
		{
			Id: "level",
			DisplayName: client.TranslatedString{
				"en": "Type",
				"nl": "Soort",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
	})

	secondStep := plan.IssueDuringDislosure.Steps[1].Options[0]
	require.Equal(t, secondStep.CredentialId, "irma-demo.MijnOverheid.fullName")
	require.Equal(t, secondStep.Attributes, []client.Attribute{
		{
			Id: "firstname",
			DisplayName: client.TranslatedString{
				"en": "First name",
				"nl": "Voornaam",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
		{
			Id: "familyname",
			DisplayName: client.TranslatedString{
				"en": "Family name",
				"nl": "Achternaam",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
	})

	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)

	plan = session.DisclosurePlan
	require.Equal(t,
		plan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
	)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// expect issuance session end
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)
	require.Equal(t, session.Status, client.Status_Success)

	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequestWithSdJwt())
	session = awaitSessionState(t, sessionHandler)

	// expect disclosure session to be updated
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	plan = session.DisclosurePlan
	require.Equal(t,
		plan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.RU.studentCard": {}, "irma-demo.MijnOverheid.fullName": {}},
	)
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1, obtainable: 2}, expectedPickOne{owned: 1, obtainable: 1})

	firstChoice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]

	require.Equal(t, firstChoice.CredentialId, "irma-demo.RU.studentCard")
	require.Equal(t, firstChoice.Attributes, []client.Attribute{
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
			Value: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
				TranslatedString: &client.TranslatedString{
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
			Value: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
				TranslatedString: &client.TranslatedString{
					"":   "high",
					"en": "high",
					"nl": "high",
				},
			},
		},
	})

	secondChoice := plan.DisclosureChoicesOverview[1].OwnedOptions[0]

	// give permission to disclose
	grantPermission(t, c, session.Id,
		makeDisclosureChoice(firstChoice, firstChoice.Attributes[0].Id, firstChoice.Attributes[1].Id),
		makeDisclosureChoice(secondChoice, secondChoice.Attributes[0].Id, secondChoice.Attributes[1].Id),
	)

	// expect issuance session to be done
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, client.Type_Issuance, client.Status_Success)

	// expect disclosure session to be done
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
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

	session := startOpenID4VPSession(t, c, sessionHandler, dcql)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)
	require.Equal(t, irmaclient.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan
	requireIssuanceSteps(t, plan, 2)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	// get updated openid4vp session state
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)
	require.Equal(t, irmaclient.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.IssuedCredentialIds, 1)
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1, obtainable: 2})

	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1, makeDisclosureChoice(choice, choice.Attributes[0].Id))

	// expect end for issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, client.Type_Issuance, client.Status_Success)

	// expect end for disclosure session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
}

func testOpenID4VP_YiviScheme_SingleCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	session := startOpenID4VPSessionWithAuthRequest(t, c, sessionHandler, createEmailAuthRequestRequest())
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)
	require.Equal(t, irmaclient.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	// get updated openid4vp session state
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)
	require.Equal(t, irmaclient.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.IssuedCredentialIds, 1)
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1, obtainable: 1})

	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1, makeDisclosureChoice(choice, choice.Attributes[0].Id))

	// expect end for issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, client.Type_Issuance, client.Status_Success)

	// expect end for disclosure session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
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

	session := startOpenID4VPSession(t, c, sessionHandler, dcql)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

	plan := session.DisclosurePlan
	// only the required studentCard produces an issuance step;
	// the optional fullName set is already satisfied by its empty option
	requireIssuanceSteps(t, plan, 1)
	require.Equal(t, "irma-demo.RU.studentCard", plan.IssueDuringDislosure.Steps[0].Options[0].CredentialId)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())

	// updated disclosure session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

	plan = session.DisclosurePlan
	require.Equal(t,
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
		plan.IssueDuringDislosure.IssuedCredentialIds,
	)
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1, obtainable: 1}, expectedPickOne{optional: true, obtainable: 1})

	requiredChoice := plan.DisclosureChoicesOverview[0]

	// issuance session ended
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, client.Type_Issuance, client.Status_Success)

	// grant permission with only the required credential; skip the optional one with an empty selection
	sc := requiredChoice.OwnedOptions[0]
	grantPermission(t, c, 1,
		makeDisclosureChoice(sc, sc.Attributes[0].Id),
		client.DisclosureDisconSelection{},
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
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

	session := startOpenID4VPSession(t, c, sessionHandler, dcql)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

	plan := session.DisclosurePlan
	requireIssuanceSteps(t, plan, 1)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// the issuance step shows the predefined university value as RequestedValue
	expectedUniversityValue := client.TranslatedString{
		"":   "University of the Arts",
		"en": "University of the Arts",
		"nl": "University of the Arts",
	}
	require.Equal(t, plan.IssueDuringDislosure.Steps[0].Options[0].Attributes, []client.Attribute{
		{
			Id: "university",
			DisplayName: client.TranslatedString{
				"en": "University",
				"nl": "Universiteit",
			},
			RequestedValue: &client.AttributeValue{
				Type:             client.AttributeType_TranslatedString,
				TranslatedString: &expectedUniversityValue,
			},
		},
		{
			Id: "level",
			DisplayName: client.TranslatedString{
				"en": "Type",
				"nl": "Soort",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
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
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// issuance session ended
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, client.Type_Issuance, client.Status_Success)

	// issue a credential with the correct university value
	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())

	// disclosure session updated with the satisfying credential
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

	plan = session.DisclosurePlan
	require.Equal(t,
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
		plan.IssueDuringDislosure.IssuedCredentialIds,
	)
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1, obtainable: 1})

	// issuance session ended
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, client.Type_Issuance, client.Status_Success)

	// grant permission to disclose the credential with the correct value
	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1,
		makeDisclosureChoice(choice, choice.Attributes[0].Id, choice.Attributes[1].Id),
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
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

	session := startOpenID4VPSession(t, c, sessionHandler, dcql)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)
	require.Equal(t, irmaclient.Protocol_OpenID4VP, session.Protocol)

	plan := session.DisclosurePlan
	requireIssuanceSteps(t, plan, 1)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// the issuance step shows the first claim_set (university + level), not studentID
	require.Equal(t, "irma-demo.RU.studentCard", plan.IssueDuringDislosure.Steps[0].Options[0].CredentialId)
	require.Equal(t, plan.IssueDuringDislosure.Steps[0].Options[0].Attributes, []client.Attribute{
		{
			Id: "university",
			DisplayName: client.TranslatedString{
				"en": "University",
				"nl": "Universiteit",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
		{
			Id: "level",
			DisplayName: client.TranslatedString{
				"en": "Type",
				"nl": "Soort",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
	})

	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())

	// disclosure session updated
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

	plan = session.DisclosurePlan
	require.Equal(t,
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
		plan.IssueDuringDislosure.IssuedCredentialIds,
	)
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1, obtainable: 1})

	// issuance session ended
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, client.Type_Issuance, client.Status_Success)

	// the first satisfied claim_set (university + level) is offered for disclosure
	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Equal(t, "irma-demo.RU.studentCard", choice.CredentialId)
	require.Equal(t, choice.Attributes, []client.Attribute{
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
			Value: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
				TranslatedString: &client.TranslatedString{
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
			Value: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
				TranslatedString: &client.TranslatedString{
					"":   "high",
					"en": "high",
					"nl": "high",
				},
			},
		},
	})

	grantPermission(t, c, 1,
		makeDisclosureChoice(choice, choice.Attributes[0].Id, choice.Attributes[1].Id),
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
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

	session := startOpenID4VPSession(t, c, sessionHandler, dcql)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)
	require.Equal(t, irmaclient.Protocol_OpenID4VP, session.Protocol)
	require.Empty(t, session.OfferedCredentials)

	plan := session.DisclosurePlan
	requireIssuanceSteps(t, plan, 2, 1)

	firstOption := plan.IssueDuringDislosure.Steps[0].Options[0]
	require.Equal(t, firstOption.CredentialId, "test.test.email")
	require.Equal(t, firstOption.Attributes, []client.Attribute{
		{
			Id: "email",
			DisplayName: client.TranslatedString{
				"en": "Email address",
				"nl": "E-mailadres",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
	})

	secondOption := plan.IssueDuringDislosure.Steps[0].Options[1]
	require.Equal(t, secondOption.CredentialId, "irma-demo.RU.studentCard")
	require.Equal(t, secondOption.Attributes, []client.Attribute{
		{
			Id: "university",
			DisplayName: client.TranslatedString{
				"en": "University",
				"nl": "Universiteit",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
		{
			Id: "level",
			DisplayName: client.TranslatedString{
				"en": "Type",
				"nl": "Soort",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
	})

	secondStep := plan.IssueDuringDislosure.Steps[1].Options[0]
	require.Equal(t, secondStep.CredentialId, "irma-demo.MijnOverheid.fullName")
	require.Equal(t, secondStep.Attributes, []client.Attribute{
		{
			Id: "firstname",
			DisplayName: client.TranslatedString{
				"en": "First name",
				"nl": "Voornaam",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
		{
			Id: "familyname",
			DisplayName: client.TranslatedString{
				"en": "Family name",
				"nl": "Achternaam",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
	})

	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	issue(t, irmaServer, c, sessionHandler, createStudentCardIssuanceRequestWithSdJwt())
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)

	plan = session.DisclosurePlan
	require.Equal(t,
		plan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.RU.studentCard": {}},
	)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// expect issuance session end
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)
	require.Equal(t, session.Status, client.Status_Success)

	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequestWithSdJwt())
	session = awaitSessionState(t, sessionHandler)

	// expect disclosure session to be updated
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Status, client.Status_RequestPermission)
	plan = session.DisclosurePlan
	require.Equal(t,
		plan.IssueDuringDislosure.IssuedCredentialIds,
		map[string]struct{}{"irma-demo.RU.studentCard": {}, "irma-demo.MijnOverheid.fullName": {}},
	)
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1, obtainable: 2}, expectedPickOne{owned: 1, obtainable: 1})

	firstChoice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]

	require.Equal(t, firstChoice.CredentialId, "irma-demo.RU.studentCard")
	require.Equal(t, firstChoice.Attributes, []client.Attribute{
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
			Value: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
				TranslatedString: &client.TranslatedString{
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
			Value: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
				TranslatedString: &client.TranslatedString{
					"":   "high",
					"en": "high",
					"nl": "high",
				},
			},
		},
	})

	secondChoice := plan.DisclosureChoicesOverview[1].OwnedOptions[0]

	// give permission to disclose
	grantPermission(t, c, session.Id,
		makeDisclosureChoice(firstChoice, firstChoice.Attributes[0].Id, firstChoice.Attributes[1].Id),
		makeDisclosureChoice(secondChoice, secondChoice.Attributes[0].Id, secondChoice.Attributes[1].Id),
	)

	// expect issuance session to be done
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, client.Type_Issuance, client.Status_Success)

	// expect disclosure session to be done
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
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

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Nil(t, plan.DisclosureChoicesOverview)

	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	step1 := plan.IssueDuringDislosure.Steps[0]
	require.Len(t, step1.Options, 1)

	expectedValue := client.TranslatedString{
		"":   value,
		"nl": value,
		"en": value,
	}

	require.Equal(t, step1.Options[0].Attributes, []client.Attribute{
		{
			Id: "studentID",
			DisplayName: client.TranslatedString{
				"nl": "Studentnummer",
				"en": "Student number",
			},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
		{
			Id: "university",
			DisplayName: client.TranslatedString{
				"nl": "Universiteit",
				"en": "University",
			},
			RequestedValue: &client.AttributeValue{
				Type:             client.AttributeType_TranslatedString,
				TranslatedString: &expectedValue,
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
	// since the issued credential doens't satisfy the pre-defined value, pretend like it hasn't been issued
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// make sure the previous issuance session was finished
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 2)
	require.Equal(t, session.Status, client.Status_Success)

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
	// once satisfied, the option is no longer obtainable, since theorectially it doesn't matter
	requireDisclosureChoices(t, plan, expectedPickOne{owned: 1})

	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 1, makeDisclosureChoice(choice, choice.Attributes[0].Id, choice.Attributes[1].Id))

	// make sure the previous issuance session is finished
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, client.Type_Issuance, client.Status_Success)

	// make sure the disclosure session is finished
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
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

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)
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

	c.NewNewSession(sessionJson)
	session := awaitSessionState(t, sessionHandler)

	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPermission)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})

	expectedRemainingAttempts := []int{-1, 2, 1, 0}
	for _, expected := range expectedRemainingAttempts {
		session = awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPin)
		require.Equal(t, expected, session.RemainingPinAttempts)

		// enter the wrong pin
		userInteraction(t, c, client.SessionUserInteraction{
			SessionId: session.Id,
			Type:      client.UI_EnteredPin,
			Payload: client.PinInteractionPayload{
				Proceed: true,
				Pin:     "54321",
			},
		})
	}

	session = awaitSessionState(t, sessionHandler)

	// after 3 attempts we expect an error with a non-zero block duration (in seconds)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_Error)
	require.ErrorContains(t, session.Error, "session blocked")
	require.Equal(t, session.PinBlockedTimeSeconds, 1)
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
	c.NewNewSession(sessionJson)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Id, 1)
	require.Equal(t, session.Type, client.Type_Issuance)
	require.Equal(t, session.Status, client.Status_Error)
	require.ErrorContains(t, session.Error, "Keyshare enrollment is missing for scheme: 'test'")
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

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	require.Equal(t, "https://yivi.app", session.ClientReturnUrl)
}

func testIssuanceClientReturnUrl(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := createEmailIssuanceRequest()
	request.ClientReturnURL = "https://yivi.app"

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	require.Equal(t, "https://yivi.app", session.ClientReturnUrl)
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

	c.NewNewSession(string(sessionJson))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	require.Equal(t, client.Status_RequestPermission, session.Status)
	require.Len(t, session.OfferedCredentials, 1)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_Success)

	// get the initial session request for the chained session
	var request irma.ServiceProviderRequest
	require.NoError(t, irma.NewHTTPTransport(nextSessionServerURL, false).Get("1", &request))
	requestJson, err := json.MarshalIndent(request, "", "   ")
	require.NoError(t, err)

	// start the session at the server
	sesPkg := startSessionAtServer(t, requestorServer, true, requestJson)
	require.NoError(t, err)

	sessionJson, err = json.MarshalIndent(sesPkg.SessionPtr, "", "   ")

	c.NewNewSession(string(sessionJson))
	session = awaitSessionState(t, sessionHandler)

	require.Equal(t, 2, session.Id)
	require.Equal(t, client.Type_Disclosure, session.Type)
	require.Empty(t, session.OfferedCredentials)

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Equal(t, "irma-demo.RU.studentCard", choice.CredentialId)

	grantPermission(t, c, session.Id, makeDisclosureChoice(choice, choice.Attributes[0].Id))

	session = awaitSessionState(t, sessionHandler)

	// the new (chained) session is still under the same id
	requireSessionState(t, session, 2, client.Type_Issuance, client.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)
	require.Equal(t, "irma-demo.MijnOverheid.fullName", session.OfferedCredentials[0].CredentialId)

	// it's now an issuance session without disclosures, so no disclosure plan anymore
	require.Nil(t, session.DisclosurePlan)

	grantPermission(t, c, session.Id)

	// should now be the last session of the chain: another disclosure session
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 2, session.Id)
	require.Equal(t, client.Type_Disclosure, session.Type)
	require.Empty(t, session.OfferedCredentials)

	choice = session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Equal(t, "irma-demo.MijnOverheid.fullName", choice.CredentialId)

	grantPermission(t, c, session.Id, makeDisclosureChoice(choice, choice.Attributes[0].Id))

	session = awaitSessionState(t, sessionHandler)

	// session should now be finished
	require.Equal(t, client.Status_Success, session.Status)
}

func testIrmaSignatureRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewSignatureRequest("Hello world")
	request.Disclose = studentCardDisclosure()

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	requireRequestorInfo(t, session)
}

func testIrmaDisclosureRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = studentCardDisclosure()

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	requireRequestorInfo(t, session)
}

func testIrmaIssuanceRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, createEmailIssuanceRequest()))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	requireRequestorInfo(t, session)
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

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	require.Equal(t, client.Status_RequestPermission, session.Status)
	require.Len(t, session.OfferedCredentials, 2)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_Success)
}

func testIssuancePermissionNotGranted_SessionDismissed(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, createEmailIssuanceRequest()))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	require.Equal(t, client.Status_RequestPermission, session.Status)
	require.Len(t, session.OfferedCredentials, 1)

	denyPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_Dismissed)
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

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
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
		client.DisclosureDisconSelection{}, // empty for optional
		makeDisclosureChoice(choice, choice.Attributes[0].Id, choice.Attributes[1].Id),
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
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
	qr, requestorToken, _, err := irmaServer.irma.StartSession(createEmailIssuanceRequest(), nil, "")
	require.NoError(t, err)
	sessionReq := client.SessionRequestData{
		Qr:       *qr,
		Protocol: irmaclient.Protocol_Irma,
	}
	sessionJson, err := json.Marshal(sessionReq)
	require.NoError(t, err)

	frontendOptions := irma.NewFrontendOptionsRequest()
	frontendOptions.PairingMethod = "pin"
	irmaServer.irma.SetFrontendOptions(requestorToken, &frontendOptions)

	c.NewNewSession(string(sessionJson))

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_ShowPairingCode)
	require.Len(t, session.PairingCode, 4)
	require.False(t, session.ContinueOnSecondDevice)

	// pretend the pairing was completed
	irmaServer.irma.PairingCompleted(requestorToken)

	// now the session should continue to issuance permission
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPermission)
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
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
		},
	}

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Signature, client.Status_RequestPermission)
	require.Equal(t, "Hello, World!", session.MessageToSign)

	require.Empty(t, session.OfferedCredentials)
	plan := session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Nil(t, plan.DisclosureChoicesOverview)

	issue(t, irmaServer, c, sessionHandler, createEmailIssuanceRequest())

	// update disclosure candidates of signature session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Signature, client.Status_RequestPermission)
	require.Equal(t, "Hello, World!", session.MessageToSign)

	require.Empty(t, session.OfferedCredentials)
	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.NotNil(t, plan.DisclosureChoicesOverview)

	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(choice, choice.Attributes[0].Id))

	// finish email issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, client.Type_Issuance, client.Status_Success)

	// finish signature session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Signature, client.Status_Success)
}

func testIssuanceSessionWithUnsatisfiedDisclosure(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// issue email and at the same time ask for either student card or MijnOverheid
	request := createEmailIssuanceRequest()
	request.Disclose = studentCardOrMijnOverheidDisclosure()

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPermission)

	require.Len(t, session.OfferedCredentials, 1)
	plan := session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 2)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// issue MijnOverheid
	issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequest())

	session = awaitSessionState(t, sessionHandler)
	// updated the first session with new disclosure options
	require.Equal(t, 1, session.Id)

	require.Len(t, session.OfferedCredentials, 1)
	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 2)
	require.Equal(t,
		map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}},
		plan.IssueDuringDislosure.IssuedCredentialIds,
	)

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]

	// give permission to disclose the MijnOverheid credential
	grantPermission(t, c, session.Id,
		makeDisclosureChoice(cred, cred.Attributes[0].Id, cred.Attributes[1].Id),
	)

	// finish issuance session for missing credential
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, client.Type_Issuance, client.Status_Success)

	// finish first issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_Success)
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

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, irmaclient.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

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
	require.Equal(t, client.Status_RequestPermission, session.Status)
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
		makeDisclosureChoice(email, email.Attributes[0].Id),
		makeDisclosureChoice(overheid, overheid.Attributes[0].Id, overheid.Attributes[1].Id),
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Success)
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
	c.NewNewSession(string(sessionJson))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	require.Equal(t, client.Status_Error, session.Status)
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
	request.Disclose = studentCardOrMijnOverheidDisclosure()

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_Dismissed)
}

func testChoiceBetweenSingletonAndNonSingletonCredentialsNonePresent(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = studentCardOrMijnOverheidDisclosure()

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, irmaclient.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)

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

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, irmaclient.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 3, client.Type_Disclosure, client.Status_RequestPermission)

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
		[]client.Attribute{
			{
				Id:          "university",
				DisplayName: client.TranslatedString{"en": "University", "nl": "Universiteit"},
				Description: client.TranslatedString{"en": "The name of the university", "nl": "Naam van de universiteit"},
				Value: &client.AttributeValue{
					Type:             "translated_string",
					TranslatedString: &client.TranslatedString{"": "University of the Arts", "en": "University of the Arts", "nl": "University of the Arts"},
				},
			},
			{
				Id:          "level",
				DisplayName: client.TranslatedString{"en": "Type", "nl": "Soort"},
				Description: client.TranslatedString{"en": "Whether you are a regular or PhD student", "nl": "Of u een gewone of PhD student bent"},
				Value: &client.AttributeValue{
					Type:             "translated_string",
					TranslatedString: &client.TranslatedString{"": "high", "en": "high", "nl": "high"},
				},
			},
		},
		studentCard.Attributes,
	)

	grantPermission(t, c, session.Id, makeDisclosureChoice(studentCard, "university", "level"))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, irmaclient.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 3, client.Type_Disclosure, client.Status_Success)
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
	requireIssuanceSteps(t, plan, 1)
	require.Len(t, plan.IssueDuringDislosure.IssuedCredentialIds, 0)

	toIssue := plan.IssueDuringDislosure.Steps[0].Options[0]
	require.Equal(t, toIssue.CredentialId, "irma-demo.MijnOverheid.fullName")

	require.Equal(t, toIssue.Attributes, []client.Attribute{
		{
			Id:          "firstname",
			DisplayName: client.TranslatedString{"nl": "Voornaam", "en": "First name"},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
		},
		{
			Id:          "familyname",
			DisplayName: client.TranslatedString{"nl": "Achternaam", "en": "Family name"},
			RequestedValue: &client.AttributeValue{
				Type: client.AttributeType_TranslatedString,
			},
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

	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, irmaclient.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, client.Type_Disclosure, client.Status_RequestPermission)
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
	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, irmaclient.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 1, client.Type_Disclosure, client.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)
	require.NotNil(t, session.DisclosurePlan)

	plan := session.DisclosurePlan
	require.Len(t, plan.IssueDuringDislosure.Steps, 1)
	require.Len(t, plan.IssueDuringDislosure.Steps[0].Options, 1)
	require.Empty(t, plan.IssueDuringDislosure.IssuedCredentialIds)

	credToIssue := plan.IssueDuringDislosure.Steps[0].Options[0]

	require.Equal(t, client.TranslatedString{"nl": "Demo E-mailadres", "en": "Demo Email address"}, credToIssue.Name)
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
	c.NewNewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, disclosureRequest))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, irmaclient.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, client.Type_Disclosure, client.Status_RequestPermission)
	require.Empty(t, session.OfferedCredentials)
	require.NotNil(t, session.DisclosurePlan)

	plan := session.DisclosurePlan
	require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 1)
	// it's also possible to obtain a new one, since it not a singleton
	require.Len(t, plan.DisclosureChoicesOverview[0].ObtainableOptions, 1)

	emailCred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(emailCred, "email"))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, irmaclient.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, client.Type_Disclosure, client.Status_RequestPin)

	// give pin
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_EnteredPin,
		Payload:   client.PinInteractionPayload{Pin: "12345", Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, irmaclient.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 2, client.Type_Disclosure, client.Status_Success)
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

func runEudiSessionTest(t *testing.T, name string, test SessionIntegrationTest) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	t.Run(name, func(t *testing.T) {
		test(t, irmaServer, c, sessionHandler)
	})
}

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

// studentCardDisclosure returns a common disclosure request for student card university and level
func studentCardDisclosure() irma.AttributeConDisCon {
	return irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
		},
	}
}

// mijnOverheidDisclosure returns a common disclosure request for MijnOverheid fullName
func mijnOverheidDisclosure() irma.AttributeConDisCon {
	return irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}
}

// studentCardOrMijnOverheidDisclosure returns a disclosure with choice between student card and MijnOverheid
func studentCardOrMijnOverheidDisclosure() irma.AttributeConDisCon {
	return irma.AttributeConDisCon{
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
}

// requireSessionState validates common session fields in a single call
func requireSessionState(
	t *testing.T,
	session client.SessionState,
	id int,
	sessionType client.SessionType,
	status client.SessionStatus,
) {
	t.Helper()
	require.Equal(t, id, session.Id)
	require.Equal(t, sessionType, session.Type)
	require.Equal(t, status, session.Status)
}

// requireRequestorInfo validates the standard test requestor info
func requireRequestorInfo(t *testing.T, session client.SessionState) {
	t.Helper()
	require.Equal(t, "test-requestors.test-requestor", session.Requestor.Id)
	require.Equal(t, client.TranslatedString{"nl": "Lokale IRMA server", "en": "Local IRMA server"}, session.Requestor.Name)
	require.True(t, session.Requestor.Verified)
}

// grantPermission sends a permission granted interaction with optional disclosure choices
func grantPermission(t *testing.T, c *client.Client, sessionId int, choices ...client.DisclosureDisconSelection) {
	t.Helper()
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: sessionId,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted:           true,
			DisclosureChoices: choices,
		},
	})
}

// denyPermission sends a permission denied interaction
func denyPermission(t *testing.T, c *client.Client, sessionId int) {
	t.Helper()
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: sessionId,
		Type:      client.UI_Permission,
		Payload: client.SessionPermissionInteractionPayload{
			Granted: false,
		},
	})
}

// makeDisclosureChoice creates a disclosure selection from an owned option
func makeDisclosureChoice(option *client.SelectableCredentialInstance, attributeIds ...string) client.DisclosureDisconSelection {
	paths := make([][]any, len(attributeIds))
	for i, id := range attributeIds {
		paths[i] = []any{id}
	}
	return client.DisclosureDisconSelection{
		Credentials: []client.SelectedCredential{
			{
				CredentialId:   option.CredentialId,
				CredentialHash: option.Hash,
				AttributePaths: paths,
			},
		},
	}
}

// expectedPickOne describes the expected shape of a DisclosurePickOne entry.
type expectedPickOne struct {
	optional   bool
	owned      int
	obtainable int
}

// requireIssuanceSteps checks plan.IssueDuringDislosure.Steps.
// Each optionCount argument gives the expected number of Options for that step,
// and the total number of arguments must equal the expected number of steps.
func requireIssuanceSteps(t *testing.T, plan *client.DisclosurePlan, optionCounts ...int) {
	t.Helper()
	require.NotNil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.IssueDuringDislosure.Steps, len(optionCounts))
	for i, count := range optionCounts {
		require.Len(t, plan.IssueDuringDislosure.Steps[i].Options, count)
	}
}

// requireDisclosureChoices checks plan.DisclosureChoicesOverview against expected values.
func requireDisclosureChoices(t *testing.T, plan *client.DisclosurePlan, expected ...expectedPickOne) {
	t.Helper()
	require.Len(t, plan.DisclosureChoicesOverview, len(expected))
	for i, exp := range expected {
		got := plan.DisclosureChoicesOverview[i]
		require.Equal(t, exp.optional, got.Optional)
		require.Len(t, got.OwnedOptions, exp.owned)
		require.Len(t, got.ObtainableOptions, exp.obtainable)
	}
}

// startOpenID4VPSession starts an OpenID4VP session with DCQL and returns the initial session state
func startOpenID4VPSession(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	dcql string,
) client.SessionState {
	t.Helper()
	return startOpenID4VPSessionWithAuthRequest(t, c, sessionHandler, createAuthRequestRequestWithDcql(dcql))
}

// startOpenID4VPSessionWithAuthRequest starts an OpenID4VP session with an auth request JSON string and returns the initial session state
func startOpenID4VPSessionWithAuthRequest(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	authRequestJson string,
) client.SessionState {
	t.Helper()
	sessionLink, err := irmaclient.StartTestSessionAtEudiVerifier(testdata.OpenID4VP_DirectPostJwt_Host, authRequestJson)
	require.NoError(t, err)
	sessionRequest := client.SessionRequestData{
		Qr: irma.Qr{
			Type: irma.ActionDisclosing,
			URL:  sessionLink,
		},
		Protocol: irmaclient.Protocol_OpenID4VP,
	}
	sessionJson, err := json.Marshal(sessionRequest)
	require.NoError(t, err)

	c.NewNewSession(string(sessionJson))
	return awaitSessionState(t, sessionHandler)
}

func printSession(s client.SessionState) {
	j, _ := json.MarshalIndent(s, "", "    ")
	fmt.Println("-----------------------------")
	fmt.Println(string(j))
	fmt.Println("-----------------------------")
}
