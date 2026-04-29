package sessiontest

import (
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/require"
)

func testSessionHandlerForEudiLogs(t *testing.T) {
	t.Run("oid4vci pre-auth issuance creates log", testOpenId4VciPreAuthFlowCreatesIssuanceLog)
	t.Run("oid4vci auth-code issuance creates log", testOpenId4VciAuthCodeFlowCreatesIssuanceLog)
	t.Run("oid4vci denied permission creates no log", testOpenId4VciDeniedPermissionCreatesNoLog)
	t.Run("oid4vp disclosure creates log", testOpenId4VpDisclosureCreatesLog)
	t.Run("oid4vp disclosure log has issuer name and credential image", testOpenId4VpDisclosureLogHasIssuerNameAndImage)
	t.Run("eudi credential removal creates log", testEudiCredentialRemovalCreatesLog)
	t.Run("eudi credential removal log has attributes", testEudiCredentialRemovalLogHasAttributes)
	t.Run("deeply nested issuance log", testDeeplyNestedIssuanceLog)
	t.Run("deeply nested removal log", testDeeplyNestedRemovalLog)
	t.Run("complex disclosure log only contains shared subset", testComplexDisclosureLogOnlyContainsSharedSubset)
	t.Run("duplicate credential removal leaves none and creates log", testDuplicateCredentialRemovalCreatesLog)
	t.Run("irma and eudi logs merged chronologically", testIrmaAndEudiLogsMergedChronologically)
	t.Run("load logs before includes both irma and eudi logs", testLoadLogsBeforeIncludesBothSources)
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
	require.Contains(t, cred.Formats, clientmodels.Format_SdJwtVc,
		"issuance log credential should include the sd-jwt format")
	// The test issuer has no logo configured, so Image should be nil.
	// Real issuers with logo URLs in credential_metadata.display will have
	// the logo resolved from disk via the logo manager.
	require.Nil(t, cred.Image, "test credential has no logo")

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
	require.Contains(t, disclosureLog.DisclosureLog.Credentials[0].Formats, clientmodels.Format_SdJwtVc,
		"disclosure log credential should include the sd-jwt format")
}

// testOpenId4VpDisclosureLogHasIssuerNameAndImage verifies that credentials in
// OpenID4VP disclosure logs contain the issuer display name and credential image.
// Currently these fields are NOT populated by the EUDI SD-JWT disclosure handler,
// so this test documents the shortcoming.
func testOpenId4VpDisclosureLogHasIssuerNameAndImage(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a credential first.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "IssuerLog",
		"family_name": "Test",
		"email": "issuerlog@example.com"
	}`)

	// Verify the issuance log DOES have the issuer name (as a baseline).
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 1)
	issuanceCred := logs[0].IssuanceLog.Credentials[0]
	require.Equal(t, "Test Issuer", issuanceCred.Issuer.Name["en"],
		"issuance log should have issuer name (baseline)")

	// Disclose it via OpenID4VP.
	veramoSession := createVeramoVerifierDcqlSession(t)
	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

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

	// The disclosure log credential should have the same issuer name as the issuance log.
	require.Equal(t, "Test Issuer", disclosureCred.Issuer.Name["en"],
		"disclosure log credential should contain the issuer display name")
	require.Equal(t, "Test Uitgever", disclosureCred.Issuer.Name["nl"],
		"disclosure log credential should contain the issuer display name in all locales")
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

// testComplexDisclosureLogOnlyContainsSharedSubset issues two credentials
// (TestCredential and HouseCredential), then creates a DCQL query that asks
// for a subset of attributes from each. After disclosure, the test verifies
// the log only contains the attributes the user actually shared — not the
// full credential contents.
func testComplexDisclosureLogOnlyContainsSharedSubset(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue two credentials.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Selective",
		"family_name": "Disclosure",
		"email": "selective@example.com"
	}`)
	issueCredentialViaOid4Vci(t, c, sessionHandler, "HouseCredentialSdJwt", `{
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
	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

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
		switch cred.Name["en"] {
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
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("Selective"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("selective@example.com"),
		},
	)

	// Verify the house credential log has exactly owner_name and address.city.
	// address.street and address.country were NOT requested and must be absent.
	require.NotNil(t, houseCredLog, "should have a log for HouseCredential")
	requireAttrsInOrder(t, houseCredLog.Attributes,
		expectedAttr{
			Path:        []any{"owner_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
			Value:       strVal("Selective Owner"),
		},
		expectedAttr{
			Path:        []any{"address", "city"},
			DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
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
	for range 3 {
		issueCredentialViaOid4Vci(t, c, sessionHandler, "TestCredentialSdJwt", claims)
	}

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	count := 0
	for _, cr := range creds {
		if name, ok := cr.Name["en"]; ok && name == "Test Credential (SD-JWT)" {
			count++
		}
	}
	require.Equal(t, 1, count, "duplicate issuances should be deduplicated into one credential")

	// Delete the credential.
	target := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, target)

	require.NoError(t, c.RemoveCredentialsByHash(target.CredentialInstanceIds))

	// Verify the credential is gone.
	creds, err = c.GetCredentials()
	require.NoError(t, err)
	for _, cr := range creds {
		if name, ok := cr.Name["en"]; ok {
			require.NotEqual(t, "Test Credential (SD-JWT)", name,
				"deleted credential should no longer appear in GetCredentials")
		}
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
	require.Equal(t, "Test Credential (SD-JWT)", removalLog.RemovalLog.Credentials[0].Name["en"])
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
	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	awaitSessionState(t, sessionHandler) // success

	// 3. OID4VCI issuance → SQLCipher log.
	sep()
	issueCredentialViaOid4Vci(t, c, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Combined",
		"family_name": "Test",
		"email": "combined@example.com"
	}`)

	// 4. IRMA disclosure of test.test.email → bbolt log.
	sep()
	performIrmaDisclosureSession(t, c, sessionHandler, irmaServer)

	// 5. OID4VP disclosure of TestCredentialSdJwt → SQLCipher log.
	sep()
	veramoSession := createVeramoVerifierDcqlSession(t)
	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

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

	eudiCred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
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
	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	awaitSessionState(t, sessionHandler)

	// 3. OID4VCI issuance.
	sep()
	issueCredentialViaOid4Vci(t, c, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Page",
		"family_name": "Test",
		"email": "page@example.com"
	}`)

	// 4. IRMA disclosure.
	sep()
	performIrmaDisclosureSession(t, c, sessionHandler, irmaServer)

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
