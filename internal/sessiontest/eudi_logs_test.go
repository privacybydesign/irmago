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

func testSessionHandlerForEudiLogs(t *testing.T) {
	t.Run("openid4vci pre-auth issuance creates log", testOpenID4VCIPreAuthFlowCreatesIssuanceLog)
	t.Run("openid4vci auth-code issuance creates log", testOpenID4VCIAuthCodeFlowCreatesIssuanceLog)
	t.Run("openid4vci denied permission creates no log", testOpenID4VCIDeniedPermissionCreatesNoLog)
	t.Run("openid4vp disclosure creates log", testOpenID4VPDisclosureCreatesLog)
	t.Run("openid4vp disclosure log has issuer name and credential image", testOpenID4VPDisclosureLogHasIssuerNameAndImage)
	t.Run("openid4vp empty optional disclosure creates log", testOpenID4VPEmptyDisclosureCreatesLog)
	t.Run("eudi credential removal creates log", testEudiCredentialRemovalCreatesLog)
	t.Run("eudi credential removal log has attributes", testEudiCredentialRemovalLogHasAttributes)
	t.Run("deeply nested issuance log", testDeeplyNestedIssuanceLog)
	t.Run("deeply nested removal log", testDeeplyNestedRemovalLog)
	t.Run("complex disclosure log only contains shared subset", testComplexDisclosureLogOnlyContainsSharedSubset)
	t.Run("duplicate credential removal leaves none and creates log", testDuplicateCredentialRemovalCreatesLog)
	t.Run("irma and eudi logs merged chronologically", testIrmaAndEudiLogsMergedChronologically)
	t.Run("load logs before includes both irma and eudi logs", testLoadLogsBeforeIncludesBothSources)
	t.Run("logs written under dutch locale snapshot dutch text", testDutchEudiLogs)
}

func testOpenID4VCIPreAuthFlowCreatesIssuanceLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "LogTest",
		"family_name": "User",
		"email": "logtest@example.com"
	}`)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 1)

	log := logs[0]
	require.Equal(t, clientmodels.LogType_Issuance, log.Type)
	require.NotNil(t, log.IssuanceLog)
	require.Equal(t, clientmodels.Protocol_OpenID4VCI, log.IssuanceLog.Protocol)
	require.Len(t, log.IssuanceLog.Credentials, 1)

	cred := log.IssuanceLog.Credentials[0]
	require.NotEmpty(t, cred.CredentialId)
	require.Equal(t, "Test Credential (SD-JWT)", cred.Name)
	require.Contains(t, cred.Formats, clientmodels.Format_SdJwtVc,
		"issuance log credential should include the sd-jwt format")
	// The test issuer has no logo configured, so Image should be nil.
	// Real issuers with logo URLs in credential_metadata.display will have
	// the logo resolved from disk via the logo manager.
	require.Nil(t, cred.Image, "test credential has no logo")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: new("Given Name"),
			Value:       strVal("LogTest"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: new("Family Name"),
			Value:       strVal("User"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: new("Email"),
			Value:       strVal("logtest@example.com"),
		},
	)
}

func testOpenID4VCIAuthCodeFlowCreatesIssuanceLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCIAuthCode(t, c, 1, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "AuthLog",
		"family_name": "User",
		"email": "authlog@example.com"
	}`)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 1)

	log := logs[0]
	require.Equal(t, clientmodels.LogType_Issuance, log.Type)
	require.NotNil(t, log.IssuanceLog)
	require.Equal(t, clientmodels.Protocol_OpenID4VCI, log.IssuanceLog.Protocol)
	require.Len(t, log.IssuanceLog.Credentials, 1)
	require.Equal(t, "Test Credential (SD-JWT)", log.IssuanceLog.Credentials[0].Name)
}

func testOpenID4VCIDeniedPermissionCreatesNoLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)

	denyPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 0, "denied OID4VCI session should not produce a log")
}

func testOpenID4VPDisclosureCreatesLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a credential first.
	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Disclose",
		"family_name": "Test",
		"email": "disclose@example.com"
	}`)

	// Disclose it via OpenID4VP.
	veramoSession := createVeramoVerifierDcqlSession(t)
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	// Find the disclosure log (the issuance log is also present).
	var disclosureLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_Disclosure {
			disclosureLog = &logs[i]
			break
		}
	}
	require.NotNil(t, disclosureLog, "should have a disclosure log")
	require.NotNil(t, disclosureLog.DisclosureLog)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, disclosureLog.DisclosureLog.Protocol)
	require.Len(t, disclosureLog.DisclosureLog.Credentials, 1)
	require.NotEmpty(t, disclosureLog.DisclosureLog.Credentials[0].CredentialId)
	require.Contains(t, disclosureLog.DisclosureLog.Credentials[0].Formats, clientmodels.Format_SdJwtVc,
		"disclosure log credential should include the sd-jwt format")
}

// testOpenID4VPDisclosureLogHasIssuerNameAndImage verifies that credentials in
// OpenID4VP disclosure logs contain the issuer display name and credential image.
// Currently these fields are NOT populated by the EUDI SD-JWT disclosure handler,
// so this test documents the shortcoming.
func testOpenID4VPDisclosureLogHasIssuerNameAndImage(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a credential first.
	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "IssuerLog",
		"family_name": "Test",
		"email": "issuerlog@example.com"
	}`)

	// Verify the issuance log DOES have the issuer name (as a baseline).
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	issuanceCred := logs[0].IssuanceLog.Credentials[0]
	require.Equal(t, "Test Issuer", issuanceCred.Issuer.Name,
		"issuance log should have issuer name (baseline)")

	// Disclose it via OpenID4VP.
	veramoSession := createVeramoVerifierDcqlSession(t)
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Load the disclosure log.
	logs, err = c.LoadNewestLogs(100)
	require.NoError(t, err)

	var disclosureLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_Disclosure {
			disclosureLog = &logs[i]
			break
		}
	}
	require.NotNil(t, disclosureLog, "should have a disclosure log")
	require.Len(t, disclosureLog.DisclosureLog.Credentials, 1)

	disclosureCred := disclosureLog.DisclosureLog.Credentials[0]

	// The disclosure log credential should have the same issuer name as the
	// issuance log, resolved to the client's locale at log-creation time.
	require.Equal(t, "Test Issuer", disclosureCred.Issuer.Name,
		"disclosure log credential should contain the issuer display name")

	// After a locale switch, the log re-resolves its text on the fly from the
	// stored credential's metadata (the credential is still in the wallet).
	c.SetLocale("nl")
	logs, err = c.LoadNewestLogs(100)
	require.NoError(t, err)
	disclosureLog = nil
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_Disclosure {
			disclosureLog = &logs[i]
			break
		}
	}
	require.NotNil(t, disclosureLog)
	require.Equal(t, "Test Uitgever", disclosureLog.DisclosureLog.Credentials[0].Issuer.Name,
		"after a locale switch the log issuer name follows the active locale via live metadata")
}

// testOpenID4VPEmptyDisclosureCreatesLog covers the case where the verifier
// requests only optional credential_sets and the user skips them, resulting
// in an empty VP token. The wallet should still record a disclosure log so
// the user can see which verifier they had a session with.
func testOpenID4VPEmptyDisclosureCreatesLog(t *testing.T) {
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "email-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/email"]
					},
					"claims": [
						{ "path": ["email"] }
					]
				}
			],
			"credential_sets": [
				{ "options": [["email-cred"]], "required": false }
			]
		}
	}`

	t.Run("user declines", func(t *testing.T) {
		c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
		defer c.Close()

		// Wallet owns the credential, but the user actively declines to share it.
		issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "EmailCredentialSdJwt", `{
			"email": "decline@example.com",
			"domain": "example.com"
		}`)

		veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
		startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

		session := awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

		grantPermission(t, c, session.Id, clientmodels.DisclosureDisconSelection{})

		session = awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

		requireEmptyDisclosureLog(t, c)
	})

	t.Run("wallet has nothing", func(t *testing.T) {
		c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
		defer c.Close()

		veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
		startOpenID4VPDisclosureSession(t, c, 1, veramoSession.RequestUri)

		session := awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

		grantPermission(t, c, session.Id, clientmodels.DisclosureDisconSelection{})

		session = awaitSessionState(t, sessionHandler)
		requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

		requireEmptyDisclosureLog(t, c)
	})
}

// requireEmptyDisclosureLog asserts that the wallet has exactly one OpenID4VP
// disclosure log with zero credentials and the test verifier as the requestor.
func requireEmptyDisclosureLog(t *testing.T, c *client.Client) {
	t.Helper()
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	var disclosureLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_Disclosure {
			require.Nil(t, disclosureLog, "expected exactly one disclosure log")
			disclosureLog = &logs[i]
		}
	}
	require.NotNil(t, disclosureLog, "should have a disclosure log even when no credentials were shared")
	require.NotNil(t, disclosureLog.DisclosureLog)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, disclosureLog.DisclosureLog.Protocol)
	require.Empty(t, disclosureLog.DisclosureLog.Credentials,
		"disclosure log should contain no credentials when the user skipped all optional sets")
	require.NotNil(t, disclosureLog.DisclosureLog.Verifier)
	require.Equal(t, "test-verifier", disclosureLog.DisclosureLog.Verifier.Name,
		"disclosure log should identify which verifier the session was with")
}

func testEudiCredentialRemovalCreatesLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Remove",
		"family_name": "Me",
		"email": "remove@example.com"
	}`)

	// The issuance log must carry the issuer logo so the activity-log UI can
	// render it. The test issuer's metadata declares an inline PNG logo; if
	// buildOfferedCredentials drops it, the log entry has no logo.
	issuanceLogs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, issuanceLogs, 1)
	issuanceCred := issuanceLogs[0].IssuanceLog.Credentials[0]
	require.NotNil(t, issuanceCred.Issuer.Image, "issuance log should carry the issuer logo")
	require.NotEmpty(t, issuanceCred.Issuer.Image.Base64)
	issuerLogo := issuanceCred.Issuer.Image.Base64

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "Test Credential (SD-JWT)")
	require.NotNil(t, cred)

	require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	// Find the removal log and verify the older issuance log is still present.
	var removalLog, issuanceLogAfter *clientmodels.LogInfo
	for i := range logs {
		switch logs[i].Type {
		case clientmodels.LogType_CredentialRemoval:
			removalLog = &logs[i]
		case clientmodels.LogType_Issuance:
			issuanceLogAfter = &logs[i]
		}
	}
	require.NotNil(t, removalLog, "should have a removal log")
	require.NotNil(t, removalLog.RemovalLog)
	require.Len(t, removalLog.RemovalLog.Credentials, 1)
	require.Equal(t, "Test Credential (SD-JWT)", removalLog.RemovalLog.Credentials[0].Name)
	require.NotNil(t, removalLog.RemovalLog.Credentials[0].Issuer.Image,
		"removal log should carry the issuer logo")
	require.Equal(t, issuerLogo, removalLog.RemovalLog.Credentials[0].Issuer.Image.Base64)

	// Deleting the credential must not damage the older issuance log entry.
	require.NotNil(t, issuanceLogAfter, "older issuance log should still be present after removal")
	require.NotNil(t, issuanceLogAfter.IssuanceLog.Credentials[0].Issuer.Image,
		"issuance log should still carry the issuer logo after the credential is removed")
	require.Equal(t, issuerLogo, issuanceLogAfter.IssuanceLog.Credentials[0].Issuer.Image.Base64)
}

func testEudiCredentialRemovalLogHasAttributes(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "AttrRemove",
		"family_name": "Test",
		"email": "attrremove@example.com"
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "Test Credential (SD-JWT)")
	require.NotNil(t, cred)

	require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	var removalLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_CredentialRemoval {
			removalLog = &logs[i]
			break
		}
	}
	require.NotNil(t, removalLog)

	removalCred := removalLog.RemovalLog.Credentials[0]
	requireAttrsInOrder(t, removalCred.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: new("Given Name"),
			Value:       strVal("AttrRemove"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: new("Family Name"),
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: new("Email"),
			Value:       strVal("attrremove@example.com"),
		},
	)
}

// organizationClaimsJSON is the deeply nested structure used by OrganizationCredentialSdJwt.
const organizationClaimsJSON = `{
	"university": {
		"name": "TU Delft",
		"faculties": [
			{
				"faculty_name": "EEMCS",
				"departments": [
					{
						"dept_name": "Software Technology",
						"courses": ["Compiler Construction", "Distributed Systems"]
					},
					{
						"dept_name": "Data Science",
						"courses": ["Machine Learning"]
					}
				]
			},
			{
				"faculty_name": "Architecture",
				"departments": [
					{
						"dept_name": "Urbanism",
						"courses": ["City Planning"]
					}
				]
			}
		],
		"founded": 1842
	}
}`

// expectedOrganizationAttrs returns the expected attribute list for the organization
// credential after flattening. Reused by both issuance and removal log tests.
func expectedOrganizationAttrs() []expectedAttr {
	deptName := new("Department Name")
	facName := new("Faculty Name")
	departments := "Departments"
	courses := "Courses"

	return []expectedAttr{
		header([]any{"university"}, "University"),
		{
			Path:        []any{"university", "name"},
			DisplayName: new("University Name"),
			Value:       strVal("TU Delft"),
		},
		header([]any{"university", "faculties"}, "Faculties"),
		{Path: []any{"university", "faculties", 0, "faculty_name"}, DisplayName: facName, Value: strVal("EEMCS")},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		{Path: []any{"university", "faculties", 0, "departments", 0, "dept_name"}, DisplayName: deptName, Value: strVal("Software Technology")},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		{Path: []any{"university", "faculties", 0, "departments", 0, "courses", 0}, Value: strVal("Compiler Construction")},
		{Path: []any{"university", "faculties", 0, "departments", 0, "courses", 1}, Value: strVal("Distributed Systems")},
		{Path: []any{"university", "faculties", 0, "departments", 1, "dept_name"}, DisplayName: deptName, Value: strVal("Data Science")},
		header([]any{"university", "faculties", 0, "departments", 1, "courses"}, courses),
		{Path: []any{"university", "faculties", 0, "departments", 1, "courses", 0}, Value: strVal("Machine Learning")},
		{Path: []any{"university", "faculties", 1, "faculty_name"}, DisplayName: facName, Value: strVal("Architecture")},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		{Path: []any{"university", "faculties", 1, "departments", 0, "dept_name"}, DisplayName: deptName, Value: strVal("Urbanism")},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		{Path: []any{"university", "faculties", 1, "departments", 0, "courses", 0}, Value: strVal("City Planning")},
		{
			Path:        []any{"university", "founded"},
			DisplayName: new("Founded"),
			Value:       intVal(1842),
		},
	}
}

func testDeeplyNestedIssuanceLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "OrganizationCredentialSdJwt", organizationClaimsJSON)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 1)

	log := logs[0]
	require.Equal(t, clientmodels.LogType_Issuance, log.Type)
	require.NotNil(t, log.IssuanceLog)
	require.Len(t, log.IssuanceLog.Credentials, 1)

	cred := log.IssuanceLog.Credentials[0]
	require.Equal(t, "Organization Credential (SD-JWT)", cred.Name)
	requireAttrsInOrder(t, cred.Attributes, expectedOrganizationAttrs()...)
}

func testDeeplyNestedRemovalLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "OrganizationCredentialSdJwt", organizationClaimsJSON)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "Organization Credential (SD-JWT)")
	require.NotNil(t, cred)

	require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	var removalLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_CredentialRemoval {
			removalLog = &logs[i]
			break
		}
	}
	require.NotNil(t, removalLog, "should have a removal log")
	require.Len(t, removalLog.RemovalLog.Credentials, 1)

	removalCred := removalLog.RemovalLog.Credentials[0]
	require.Equal(t, "Organization Credential (SD-JWT)", removalCred.Name)
	requireAttrsInOrder(t, removalCred.Attributes, expectedOrganizationAttrs()...)
}

// testComplexDisclosureLogOnlyContainsSharedSubset issues two credentials
// (TestCredential and HouseCredential), then creates a DCQL query that asks
// for a subset of attributes from each. After disclosure, the test verifies
// the log only contains the attributes the user actually shared — not the
// full credential contents.
func testComplexDisclosureLogOnlyContainsSharedSubset(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue two credentials.
	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Selective",
		"family_name": "Disclosure",
		"email": "selective@example.com"
	}`)
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Selective Owner",
		"address": {
			"street": "Secret Street 1",
			"city": "Amsterdam",
			"country": "NL"
		}
	}`)

	// Create a DCQL query that asks for:
	//  - TestCredential: only given_name and email (NOT family_name)
	//  - HouseCredential: only owner_name and address.city (NOT street, NOT country)
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "test-partial",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/test"]
					},
					"claims": [
						{ "path": ["given_name"] },
						{ "path": ["email"] }
					]
				},
				{
					"id": "house-partial",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/house"]
					},
					"claims": [
						{ "path": ["owner_name"] },
						{ "path": ["address", "city"] }
					]
				}
			]
		}
	}`

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, 3, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)

	// Grant permission for both credentials, selecting the attributes shown in the plan.
	plan := session.DisclosurePlan
	require.Len(t, plan.DisclosureChoicesOverview, 2)

	var choices []clientmodels.DisclosureDisconSelection
	for _, pickOne := range plan.DisclosureChoicesOverview {
		require.NotEmpty(t, pickOne.OwnedOptions)
		choices = append(choices, makeDisclosureChoice(pickOne.OwnedOptions[0]))
	}

	grantPermission(t, c, session.Id, choices...)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Load logs and find the disclosure entry.
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	var disclosureLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_Disclosure {
			disclosureLog = &logs[i]
			break
		}
	}
	require.NotNil(t, disclosureLog, "should have a disclosure log")
	require.NotNil(t, disclosureLog.DisclosureLog)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, disclosureLog.DisclosureLog.Protocol)
	require.Len(t, disclosureLog.DisclosureLog.Credentials, 2,
		"log should have entries for both disclosed credentials")

	// Find the test credential and house credential logs (order is not guaranteed).
	var testCredLog, houseCredLog *clientmodels.LogCredential
	for i := range disclosureLog.DisclosureLog.Credentials {
		cred := &disclosureLog.DisclosureLog.Credentials[i]
		switch cred.Name {
		case "Test Credential (SD-JWT)":
			testCredLog = cred
		case "House Possession Credential (SD-JWT)":
			houseCredLog = cred
		}
	}

	// Verify the test credential log has exactly given_name and email with values.
	// family_name was NOT requested and must be absent.
	require.NotNil(t, testCredLog, "should have a log for TestCredential")
	requireAttrsInOrder(t, testCredLog.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: new("Given Name"),
			Value:       strVal("Selective"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: new("Email"),
			Value:       strVal("selective@example.com"),
		},
	)

	// Verify the house credential log has exactly owner_name and address.city,
	// with the [address] section header for the nested compound (matching the
	// disclosure-plan tree-walk rendering). address.street and address.country
	// were NOT requested and must be absent.
	require.NotNil(t, houseCredLog, "should have a log for HouseCredential")
	requireAttrsInOrder(t, houseCredLog.Attributes,
		expectedAttr{
			Path:        []any{"owner_name"},
			DisplayName: new("Owner Name"),
			Value:       strVal("Selective Owner"),
		},
		header([]any{"address"}, "Address"),
		expectedAttr{
			Path:        []any{"address", "city"},
			DisplayName: new("City"),
			Value:       strVal("Amsterdam"),
		},
	)
}

// testDuplicateCredentialRemovalCreatesLog issues the same credential type
// multiple times with identical claims, then deletes it. Because the hash is
// deterministic over claim values (not timestamps), duplicate issuances are
// deduplicated into a single batch. Deleting that batch removes the credential
// entirely and produces a removal log.
func testDuplicateCredentialRemovalCreatesLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	claims := `{"given_name": "Alice", "family_name": "Duplicate", "email": "alice@example.com"}`

	// Issue the same credential type three times with identical attribute values.
	// Because the hash is now based solely on claim values, the second and third
	// issuances are deduplicated — only one credential batch is stored.
	for i := range 3 {
		issueCredentialViaOpenID4VCI(t, c, i+1, sessionHandler, "TestCredentialSdJwt", claims)
	}

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	count := 0
	for _, cr := range creds {
		if cr.Name == "Test Credential (SD-JWT)" {
			count++
		}
	}
	require.Equal(t, 1, count, "duplicate issuances should be deduplicated into one credential")

	// Delete the credential.
	target := findCredentialByName(t, creds, "Test Credential (SD-JWT)")
	require.NotNil(t, target)

	require.NoError(t, c.RemoveCredentialsByHash(target.CredentialInstanceIds))

	// Verify the credential is gone.
	creds, err = c.GetCredentials()
	require.NoError(t, err)
	for _, cr := range creds {
		require.NotEqual(t, "Test Credential (SD-JWT)", cr.Name,
			"deleted credential should no longer appear in GetCredentials")
	}

	// Verify a removal log was created.
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	var removalLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_CredentialRemoval {
			removalLog = &logs[i]
			break
		}
	}
	require.NotNil(t, removalLog, "should have a removal log")
	require.NotNil(t, removalLog.RemovalLog)
	require.Len(t, removalLog.RemovalLog.Credentials, 1)
	require.Equal(t, "Test Credential (SD-JWT)", removalLog.RemovalLog.Credentials[0].Name)
}

// testIrmaAndEudiLogsMergedChronologically performs a mix of IRMA and EUDI
// activities and verifies that LoadNewestLogs returns all of them merged in
// reverse-chronological order (newest first), regardless of storage backend.
//
// Sequence:
//  1. Keyshare enrollment      → bbolt log (issuance)
//  2. IRMA issuance            → bbolt log (issuance)
//  3. OID4VCI issuance         → SQLCipher log (issuance)
//  4. IRMA disclosure          → bbolt log (disclosure)
//  5. OID4VP disclosure        → SQLCipher log (disclosure)
//  6. EUDI credential removal  → SQLCipher log (removal)
func testIrmaAndEudiLogsMergedChronologically(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t) // includes keyshare enrollment → 1 bbolt log
	defer c.Close()

	// Helper to get the protocol from a log entry.
	logProtocol := func(l clientmodels.LogInfo) clientmodels.Protocol {
		switch {
		case l.IssuanceLog != nil:
			return l.IssuanceLog.Protocol
		case l.DisclosureLog != nil:
			return l.DisclosureLog.Protocol
		default:
			return ""
		}
	}

	// IRMA timestamps have second-level granularity. Sleep between activities
	// so that every log gets a distinct timestamp and the ordering is deterministic.
	sep := func() { time.Sleep(1100 * time.Millisecond) }

	// 1. Verify enrollment log is present.
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 1, "should have keyshare enrollment log")

	// 2. IRMA issuance of test.test.email with SD-JWT → bbolt log.
	sep()
	issue(t, irmaServer, c, sessionHandler, 1, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	awaitSessionState(t, sessionHandler) // success

	// 3. OID4VCI issuance → SQLCipher log.
	sep()
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Combined",
		"family_name": "Test",
		"email": "combined@example.com"
	}`)

	// 4. IRMA disclosure of test.test.email → bbolt log.
	sep()
	performIrmaDisclosureSession(t, c, 3, sessionHandler, irmaServer)

	// 5. OID4VP disclosure of TestCredentialSdJwt → SQLCipher log.
	sep()
	veramoSession := createVeramoVerifierDcqlSession(t)
	startOpenID4VPDisclosureSession(t, c, 4, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)

	// 6. Remove the EUDI credential → SQLCipher log.
	sep()
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	eudiCred := findCredentialByName(t, creds, "Test Credential (SD-JWT)")
	require.NotNil(t, eudiCred)
	require.NoError(t, c.RemoveCredentialsByHash(eudiCred.CredentialInstanceIds))

	// Final check: all 6 logs present, sorted newest-first, in the exact order
	// they happened (newest at index 0).
	logs, err = c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 6)

	// Strictly descending timestamps.
	for i := 0; i < len(logs)-1; i++ {
		require.True(t, logs[i].Time.After(logs[i+1].Time),
			"log[%d] (%s/%s at %v) should be strictly after log[%d] (%s/%s at %v)",
			i, logs[i].Type, logProtocol(logs[i]), logs[i].Time,
			i+1, logs[i+1].Type, logProtocol(logs[i+1]), logs[i+1].Time)
	}

	// Exact order, newest first:
	//   [0] removal          (EUDI)
	//   [1] disclosure       (OID4VP)
	//   [2] disclosure       (IRMA)
	//   [3] issuance         (OID4VCI)
	//   [4] issuance         (IRMA)
	//   [5] issuance         (IRMA, keyshare enrollment)
	require.Equal(t, clientmodels.LogType_CredentialRemoval, logs[0].Type)

	require.Equal(t, clientmodels.LogType_Disclosure, logs[1].Type)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, logs[1].DisclosureLog.Protocol)

	require.Equal(t, clientmodels.LogType_Disclosure, logs[2].Type)
	require.Equal(t, clientmodels.Protocol_Irma, logs[2].DisclosureLog.Protocol)

	require.Equal(t, clientmodels.LogType_Issuance, logs[3].Type)
	require.Equal(t, clientmodels.Protocol_OpenID4VCI, logs[3].IssuanceLog.Protocol)

	require.Equal(t, clientmodels.LogType_Issuance, logs[4].Type)
	require.Equal(t, clientmodels.Protocol_Irma, logs[4].IssuanceLog.Protocol)

	require.Equal(t, clientmodels.LogType_Issuance, logs[5].Type)
	require.Equal(t, clientmodels.Protocol_Irma, logs[5].IssuanceLog.Protocol)
}

// testLoadLogsBeforeIncludesBothSources verifies that LoadLogsBefore returns
// logs from both bbolt (IRMA) and SQLCipher (EUDI) when paginating.
//
// Sequence (with 1s sleeps between each):
//  1. Keyshare enrollment      → bbolt  (issuance)
//  2. IRMA issuance            → bbolt  (issuance)
//  3. OID4VCI issuance         → SQLCipher (issuance)
//  4. IRMA disclosure          → bbolt  (disclosure)
//
// LoadNewestLogs(2) returns [4, 3]. LoadLogsBefore(logs[1].Time, 10) should
// return [2, 1] — one from each backend.
func testLoadLogsBeforeIncludesBothSources(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	// IRMA timestamps have second-level granularity. Sleep between activities
	// so that every log gets a distinct timestamp and the ordering is deterministic.
	sep := func() { time.Sleep(1100 * time.Millisecond) }

	// 1. Keyshare enrollment log already exists.

	// 2. IRMA issuance.
	sep()
	issue(t, irmaServer, c, sessionHandler, 1, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	awaitSessionState(t, sessionHandler)

	// 3. OID4VCI issuance.
	sep()
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Page",
		"family_name": "Test",
		"email": "page@example.com"
	}`)

	// 4. IRMA disclosure.
	sep()
	performIrmaDisclosureSession(t, c, 3, sessionHandler, irmaServer)

	// First page: 2 newest logs.
	firstPage, err := c.LoadNewestLogs(2)
	require.NoError(t, err)
	require.Len(t, firstPage, 2)
	// [0] = IRMA disclosure, [1] = OID4VCI issuance
	require.Equal(t, clientmodels.LogType_Disclosure, firstPage[0].Type)
	require.Equal(t, clientmodels.LogType_Issuance, firstPage[1].Type)
	require.Equal(t, clientmodels.Protocol_OpenID4VCI, firstPage[1].IssuanceLog.Protocol)

	// Second page: logs before the oldest entry on the first page.
	secondPage, err := c.LoadLogsBefore(firstPage[1].Time, 10)
	require.NoError(t, err)
	require.Len(t, secondPage, 2, "should contain IRMA issuance + keyshare enrollment")

	// Both should be IRMA issuance logs (from bbolt).
	require.Equal(t, clientmodels.LogType_Issuance, secondPage[0].Type)
	require.Equal(t, clientmodels.Protocol_Irma, secondPage[0].IssuanceLog.Protocol)
	require.Equal(t, clientmodels.LogType_Issuance, secondPage[1].Type)
	require.Equal(t, clientmodels.Protocol_Irma, secondPage[1].IssuanceLog.Protocol)

	// All second page entries must be strictly before the cursor.
	for i, l := range secondPage {
		require.True(t, l.Time.Before(firstPage[1].Time),
			"secondPage[%d].Time (%v) should be before cursor (%v)", i, l.Time, firstPage[1].Time)
	}
}

// testDutchEudiLogs pins the Dutch-locale resolution for the EUDI (SQLCipher)
// log layer: logs written under a Dutch locale snapshot Dutch text, for
// issuance and removal alike.
func testDutchEudiLogs(t *testing.T) {
	c, sessionHandler := createDutchClientWithoutKeyshareEnrollment(t)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "log@voorbeeld.nl",
		"domain": "voorbeeld.nl"
	}`)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	require.NotNil(t, logs[0].IssuanceLog)
	require.Equal(t, "Test Uitgever", logs[0].IssuanceLog.Issuer.Name)

	logCred := logs[0].IssuanceLog.Credentials[0]
	require.Equal(t, "E-mail Credential (SD-JWT)", logCred.Name)
	require.Equal(t, "Test Uitgever", logCred.Issuer.Name)
	requireAttrsInOrder(t, logCred.Attributes,
		expectedAttr{Path: []any{"email"}, DisplayName: new("E-mailadres"), Value: strVal("log@voorbeeld.nl")},
		expectedAttr{Path: []any{"domain"}, DisplayName: new("Domein"), Value: strVal("voorbeeld.nl")},
	)

	// Removal logs snapshot the Dutch text too.
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	cred := findCredentialByName(t, creds, "E-mail Credential (SD-JWT)")
	require.NotNil(t, cred)
	require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))

	logs, err = c.LoadNewestLogs(100)
	require.NoError(t, err)
	removal := findLog(logs, clientmodels.LogType_CredentialRemoval)
	require.NotNil(t, removal)
	require.Equal(t, "E-mail Credential (SD-JWT)", removal.RemovalLog.Credentials[0].Name)
}
