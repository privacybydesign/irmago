package sessiontest

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

func testSessionHandlerForIrmaIssuance(t *testing.T) {
	runSessionTest(t,
		"requestor info correct",
		testIrmaIssuanceRequestorInfoCorrect,
	)

	runSessionTest(t,
		"trusted party logo paths not empty during issuance",
		testIssuanceTrustedPartyLogoPaths,
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

	runSessionTest(t,
		"random blind attributes excluded from offered credentials",
		testRandomBlindAttributesExcludedFromOfferedCredentials,
	)

	runSessionTest(t,
		"trusted party logo paths in issuance and disclosure logs",
		testTrustedPartyLogoPathsInLogs,
	)

	runSessionTest(t,
		"attributes are ordered by displayIndex",
		testAttributesOrderedByDisplayIndex,
	)

	t.Run("revocation attributes excluded from credentials", func(t *testing.T) {
		revServer := startRevocationServer(t, true, "postgres")
		defer revServer.Stop()

		conf := IrmaServerConfigurationWithTempStorage(t)
		irmaServer := StartIrmaServer(t, conf)
		defer irmaServer.Stop()

		keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
		defer keyshareServer.Stop()

		c, sessionHandler := createClient(t)
		defer c.Close()

		testRevocationAttributesExcludedFromCredentials(t, irmaServer, revServer, c, sessionHandler)
	})
}

func testIrmaIssuanceRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, createEmailIssuanceRequest()))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	requireRequestorInfo(t, session)
}

func testIssuanceTrustedPartyLogoPaths(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, createEmailIssuanceRequest()))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	// Requestor should have a logo
	require.NotNil(t, session.Requestor.Image, "requestor Image should not be nil")
	require.NotEmpty(t, session.Requestor.Image.Base64, "requestor Image should have base64 data")

	// Each offered credential's issuer should have a logo and be verified
	require.NotEmpty(t, session.OfferedCredentials, "expected at least one offered credential")
	for _, cred := range session.OfferedCredentials {
		require.NotNil(t, cred.Issuer.Image, "issuer Image for %s should not be nil", cred.CredentialId)
		require.NotEmpty(t, cred.Issuer.Image.Base64, "issuer Image for %s should have base64 data", cred.CredentialId)
		require.True(t, cred.Issuer.Verified, "issuer for %s should be verified", cred.CredentialId)
	}
}

func testIssuancePermissionNotGranted_SessionDismissed(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, createEmailIssuanceRequest()))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.Len(t, session.OfferedCredentials, 1)

	denyPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
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

	sessionJson, issuanceToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(1, sessionJson)
	session := awaitSessionState(t, sessionHandler)

	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	require.Len(t, session.OfferedCredentials, 1)
	plan := session.DisclosurePlan
	require.Len(t, plan.IssueDuringDisclosure.Steps, 1)
	require.Len(t, plan.IssueDuringDisclosure.Steps[0].Options, 2)
	require.Empty(t, plan.IssueDuringDisclosure.IssuedCredentialIds)
	require.Nil(t, plan.DisclosureChoicesOverview)

	// issue MijnOverheid
	issue(t, irmaServer, c, sessionHandler, 2, createMijnOverheidIssuanceRequest())

	session = awaitSessionState(t, sessionHandler)
	// updated the first session with new disclosure options
	require.Equal(t, 1, session.Id)

	require.Len(t, session.OfferedCredentials, 1)
	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDisclosure.Steps, 1)
	require.Len(t, plan.IssueDuringDisclosure.Steps[0].Options, 2)
	require.Equal(t,
		map[string]struct{}{"irma-demo.MijnOverheid.fullName": {}},
		plan.IssueDuringDisclosure.IssuedCredentialIds,
	)

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]

	// give permission to disclose the MijnOverheid credential
	grantPermission(t, c, session.Id,
		makeDisclosureChoice(cred),
	)

	// finish issuance session for missing credential
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// finish first issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, issuanceToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "irma-demo.MijnOverheid.fullName.firstnames", Value: "Barry"},
			{Identifier: "irma-demo.MijnOverheid.fullName.familyname", Value: "Batsbak"},
		},
	})
}

func testSingleCredentialIssuance(t *testing.T, irmaServer *IrmaServer, c *client.Client, sessionHandler *MockSessionHandler) {
	schemalessPerformIrmaIssuanceSession(
		t,
		c,
		sessionHandler,
		irmaServer,
		1,
		createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"),
	)
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

	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.Len(t, session.OfferedCredentials, 2)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

func testIssuanceClientReturnUrl(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := createEmailIssuanceRequest()
	request.ClientReturnURL = "https://yivi.app"

	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	require.Equal(t, "https://yivi.app", session.ClientReturnUrl)
}

func testRandomBlindAttributesExcludedFromOfferedCredentials(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Issue a credential with a random blind attribute (irma-demo.stemmen.stempas)
	issueRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas"),
		Attributes: map[string]string{
			"election": "plantsoen",
		},
	}})

	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, issueRequest))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	// The OfferedCredentials should not include the random blind attribute "votingnumber"
	require.Len(t, session.OfferedCredentials, 1)
	offered := session.OfferedCredentials[0]
	require.Equal(t, "irma-demo.stemmen.stempas", offered.CredentialId)
	requireNoAttr(t, attributeMap(offered.Attributes), []any{"votingnumber"})
	requireAttrsInOrder(t, offered.Attributes, expectedAttr{
		Path:        []any{"election"},
		DisplayName: new("Election"),
		Value:       strVal("plantsoen"),
	})

	// Accept the issuance
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_Permission,
		Payload:   clientmodels.SessionPermissionInteractionPayload{Granted: true},
	})
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// GetCredentials SHOULD include the random blind attribute (it has a value after issuance)
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	var stempasCred *clientmodels.Credential
	for _, cred := range creds {
		if cred.CredentialId == "irma-demo.stemmen.stempas" {
			stempasCred = cred
			break
		}
	}
	require.NotNil(t, stempasCred, "should have irma-demo.stemmen.stempas credential")
	require.Len(t, stempasCred.Attributes, 2, "GetCredentials should include both election and votingnumber")
	stempassAttrs := attributeMap(stempasCred.Attributes)
	requireAttr(t, stempassAttrs, []any{"election"}, "plantsoen")
	_, hasVotingnumber := stempassAttrs[pk("votingnumber")]
	require.True(t, hasVotingnumber, "should have votingnumber attribute")

	// Start a disclosure session for the election attribute
	disclosureRequest := irma.NewDisclosureRequest()
	disclosureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.stemmen.stempas.election"),
			},
		},
	}
	c.NewSession(2, startSameDeviceIrmaSessionAtServer(t, irmaServer, disclosureRequest))
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The owned option shows only the requested attribute (election)
	plan := session.DisclosurePlan
	require.NotNil(t, plan.DisclosureChoicesOverview)
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 1)
	require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions[0].Credentials, 1)
	owned := plan.DisclosureChoicesOverview[0].OwnedOptions[0].Credentials[0]
	require.Equal(t, "irma-demo.stemmen.stempas", owned.CredentialId)
	requireAttrsInOrder(t, owned.Attributes, expectedAttr{
		Path:        []any{"election"},
		DisplayName: new("Election"),
		Value:       strVal("plantsoen"),
	})

	// Now request the votingnumber attribute directly — it should be disclosable
	disclosureRequest2 := irma.NewDisclosureRequest()
	disclosureRequest2.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.stemmen.stempas.votingnumber"),
			},
		},
	}
	c.NewSession(3, startSameDeviceIrmaSessionAtServer(t, irmaServer, disclosureRequest2))
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The random blind attribute should appear as an owned option when requested
	plan = session.DisclosurePlan
	require.NotNil(t, plan.DisclosureChoicesOverview)
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 1)
	require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions[0].Credentials, 1)
	owned = plan.DisclosureChoicesOverview[0].OwnedOptions[0].Credentials[0]
	require.Equal(t, "irma-demo.stemmen.stempas", owned.CredentialId)
	require.Len(t, owned.Attributes, 1)
	_, votingnumberFound := attributeMap(owned.Attributes)[pk("votingnumber")]
	require.True(t, votingnumberFound, "owned option should have votingnumber attribute")
}

func testTrustedPartyLogoPathsInLogs(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Issue a credential
	issue(t, irmaServer, c, sessionHandler, 1, createStudentCardIssuanceRequest())
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Do a disclosure session
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
			},
		},
	}
	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(2, sessionJson)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	for _, ownedCred := range choice.Credentials {
		require.True(t, ownedCred.Issuer.Verified,
			"owned disclosure credential %s should have a verified issuer", ownedCred.CredentialId)
	}

	grantPermission(t, c, 2, makeDisclosureChoice(choice))
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "irma-demo.RU.studentCard.university", Value: "University of the Arts"},
		},
	})

	// Load logs and verify logo paths
	logs, err := c.LoadNewestLogs(10)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(logs), 2)

	// Find the issuance and disclosure logs
	var issuanceLog *clientmodels.IssuanceLog
	var disclosureLog *clientmodels.DisclosureLog
	for i := range logs {
		if logs[i].IssuanceLog != nil {
			issuanceLog = logs[i].IssuanceLog
		}
		if logs[i].DisclosureLog != nil {
			disclosureLog = logs[i].DisclosureLog
		}
	}

	require.NotNil(t, issuanceLog, "should have an issuance log")
	require.NotNil(t, disclosureLog, "should have a disclosure log")

	// The credential issuer's image should be set and verified in the issuance log
	require.NotEmpty(t, issuanceLog.Credentials, "issuance log should have credentials")
	issuedCred := issuanceLog.Credentials[0]
	require.NotNil(t, issuedCred.Issuer.Image,
		"issued credential's issuer image should not be nil")
	require.NotEmpty(t, issuedCred.Issuer.Image.Base64,
		"issued credential's issuer image should have base64 data")
	require.True(t, issuedCred.Issuer.Verified,
		"issued credential's issuer should be verified")

	// The credential issuer's image should be set and verified in the disclosure log
	require.NotEmpty(t, disclosureLog.Credentials, "disclosure log should have credentials")
	disclosedCred := disclosureLog.Credentials[0]
	require.NotNil(t, disclosedCred.Issuer.Image,
		"disclosed credential's issuer image should not be nil")
	require.NotEmpty(t, disclosedCred.Issuer.Image.Base64,
		"disclosed credential's issuer image should have base64 data")
	require.True(t, disclosedCred.Issuer.Verified,
		"disclosed credential's issuer should be verified")
}

func testAttributesOrderedByDisplayIndex(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// irma-demo.RU.studentCard has displayIndex set:
	// university=3, studentCardNumber=2, studentID=1, level=0
	// So the expected display order is: level, studentID, studentCardNumber, university

	// Issue the credential
	issue(t, irmaServer, c, sessionHandler, 1, createStudentCardIssuanceRequest())
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Check GetCredentials returns attributes in displayIndex order
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	var studentCard *clientmodels.Credential
	for _, cred := range creds {
		if cred.CredentialId == "irma-demo.RU.studentCard" {
			studentCard = cred
			break
		}
	}
	require.NotNil(t, studentCard)
	studentCardExpectedAttrs := []expectedAttr{
		{
			Path:        []any{"level"},
			DisplayName: new("Type"),
			Value:       strVal("high"),
		},
		{
			Path:        []any{"studentID"},
			DisplayName: new("Student number"),
			Value:       strVal("67890"),
		},
		{
			Path:        []any{"studentCardNumber"},
			DisplayName: new("Student card number"),
			Value:       strVal("12345"),
		},
		{
			Path:        []any{"university"},
			DisplayName: new("University"),
			Value:       strVal("University of the Arts"),
		},
	}
	requireAttrsInOrder(t, studentCard.Attributes, studentCardExpectedAttrs...)

	// Check OfferedCredentials during issuance also respects displayIndex
	c.NewSession(2, startSameDeviceIrmaSessionAtServer(t, irmaServer, createStudentCardIssuanceRequest()))
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	require.Len(t, session.OfferedCredentials, 1)
	offered := session.OfferedCredentials[0]
	requireAttrsInOrder(t, offered.Attributes, studentCardExpectedAttrs...)
}

func testRevocationAttributesExcludedFromCredentials(
	t *testing.T,
	irmaServer *IrmaServer,
	revServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Issue a revocable credential (irma-demo.MijnOverheid.root with RevocationKey)
	issueRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
		RevocationKey:    "testkey",
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"),
		Attributes: map[string]string{
			"BSN": "299792458",
		},
	}})
	issue(t, irmaServer, c, sessionHandler, 1, issueRequest)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Get the credential via GetCredentials and check that the revocation attribute is present
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	var rootCred *clientmodels.Credential
	for _, cred := range creds {
		if cred.CredentialId == "irma-demo.MijnOverheid.root" {
			rootCred = cred
			break
		}
	}
	require.NotNil(t, rootCred, "should have irma-demo.MijnOverheid.root credential")

	// Prove that the revocation attribute (with empty ID) is not visible — only BSN should be present
	requireAttrsInOrder(t, rootCred.Attributes, expectedAttr{
		Path:        []any{"BSN"},
		DisplayName: new("BSN"),
		Value:       strVal("299792458"),
	})

	// Revoke the credential on the server
	revocationTestCred := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
	require.NoError(t, revServer.irma.Revoke(revocationTestCred, "testkey", time.Time{}))

	// Trigger a disclosure session with revocation check so the client syncs its revocation state
	bsnAttr := irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	disclosureRequest := irma.NewDisclosureRequest(bsnAttr)
	disclosureRequest.Revocation = irma.NonRevocationParameters{
		revocationTestCred: {},
	}
	c.NewSession(2, startSameDeviceIrmaSessionAtServer(t, revServer, disclosureRequest))
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 2, session.Id)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	// During disclosure permission, the owned option should show revocation status
	// and should not include the revocation attribute
	disclosurePlan := session.DisclosurePlan
	require.NotNil(t, disclosurePlan.DisclosureChoicesOverview)
	bundle := disclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Len(t, bundle.Credentials, 1)
	cred := bundle.Credentials[0]
	require.Equal(t, "irma-demo.MijnOverheid.root", cred.CredentialId)
	require.True(t, cred.Revoked, "owned option should show credential as revoked during disclosure permission")
	requireAttrsInOrder(t, cred.Attributes, expectedAttr{
		Path:        []any{"BSN"},
		DisplayName: new("BSN"),
		Value:       strVal("299792458"),
	})

	// Grant permission — the client will attempt to construct a proof and discover the revocation
	grantPermission(t, c, 2, makeDisclosureChoice(bundle))

	// The session should fail because the credential is revoked
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 2, session.Id)
	require.Equal(t, clientmodels.Status_Error, session.Status)

	// After the client has synced, GetCredentials should show the credential as revoked
	creds, err = c.GetCredentials()
	require.NoError(t, err)

	rootCred = nil
	for _, cred := range creds {
		if cred.CredentialId == "irma-demo.MijnOverheid.root" {
			rootCred = cred
			break
		}
	}
	require.NotNil(t, rootCred, "revoked credential should still be in GetCredentials")
	require.True(t, rootCred.Revoked, "credential should be marked as revoked")
}
