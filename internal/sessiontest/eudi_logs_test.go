package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

func testSessionHandlerForEudiLogs(t *testing.T) {
	t.Run("oid4vci pre-auth issuance creates log", testOpenId4VciPreAuthFlowCreatesIssuanceLog)
	t.Run("oid4vci auth-code issuance creates log", testOpenId4VciAuthCodeFlowCreatesIssuanceLog)
	t.Run("oid4vci denied permission creates no log", testOpenId4VciDeniedPermissionCreatesNoLog)
	t.Run("oid4vp disclosure creates log", testOpenId4VpDisclosureCreatesLog)
	t.Run("eudi credential removal creates log", testEudiCredentialRemovalCreatesLog)
	t.Run("eudi credential removal log has attributes", testEudiCredentialRemovalLogHasAttributes)
	t.Run("deeply nested issuance log", testDeeplyNestedIssuanceLog)
	t.Run("deeply nested removal log", testDeeplyNestedRemovalLog)
}

func testOpenId4VciPreAuthFlowCreatesIssuanceLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "TestCredentialSdJwt", `{
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
	require.Equal(t, "Test Credential (SD-JWT)", cred.Name["en"])

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("LogTest"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("User"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("logtest@example.com"),
		},
	)
}

func testOpenId4VciAuthCodeFlowCreatesIssuanceLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4VciAuthCode(t, c, sessionHandler, "TestCredentialSdJwt", `{
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
	require.Equal(t, "Test Credential (SD-JWT, Auth Code)", log.IssuanceLog.Credentials[0].Name["en"])
}

func testOpenId4VciDeniedPermissionCreatesNoLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
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

func testOpenId4VpDisclosureCreatesLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a credential first.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Disclose",
		"family_name": "Test",
		"email": "disclose@example.com"
	}`)

	// Disclose it via OpenID4VP.
	veramoSession := createVeramoVerifierDcqlSession(t)
	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

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
}

func testEudiCredentialRemovalCreatesLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Remove",
		"family_name": "Me",
		"email": "remove@example.com"
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, cred)

	require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	// Find the removal log.
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
	require.Equal(t, "Test Credential (SD-JWT)", removalLog.RemovalLog.Credentials[0].Name["en"])
}

func testEudiCredentialRemovalLogHasAttributes(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "AttrRemove",
		"family_name": "Test",
		"email": "attrremove@example.com"
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
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
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("AttrRemove"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
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
	deptName := &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"}
	facName := &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"}
	departments := clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}
	courses := clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}

	return []expectedAttr{
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		{
			Path:        []any{"university", "name"},
			DisplayName: &clientmodels.TranslatedString{"en": "University Name", "nl": "Naam universiteit"},
			Value:       strVal("TU Delft"),
		},
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
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
			DisplayName: &clientmodels.TranslatedString{"en": "Founded", "nl": "Opgericht"},
			Value:       intVal(1842),
		},
	}
}

func testDeeplyNestedIssuanceLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "OrganizationCredentialSdJwt", organizationClaimsJSON)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 1)

	log := logs[0]
	require.Equal(t, clientmodels.LogType_Issuance, log.Type)
	require.NotNil(t, log.IssuanceLog)
	require.Len(t, log.IssuanceLog.Credentials, 1)

	cred := log.IssuanceLog.Credentials[0]
	require.Equal(t, "Organization Credential (SD-JWT)", cred.Name["en"])
	requireAttrsInOrder(t, cred.Attributes, expectedOrganizationAttrs()...)
}

func testDeeplyNestedRemovalLog(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "OrganizationCredentialSdJwt", organizationClaimsJSON)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Organization Credential (SD-JWT)")
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
	require.Equal(t, "Organization Credential (SD-JWT)", removalCred.Name["en"])
	requireAttrsInOrder(t, removalCred.Attributes, expectedOrganizationAttrs()...)
}
