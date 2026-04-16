package sessiontest

import (
	"fmt"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Pre-authorized code flow
// ========================================================================

func testSessionHandlerForOpenID4VCIPreAuth(t *testing.T) {
	t.Run("reaches permission request", testOpenId4VciPreAuthFlowReachesPermission)
	t.Run("grants permission and exchanges token", testOpenId4VciPreAuthFlowGrantsPermissionAndExchangesToken)
	t.Run("with tx_code grants permission and exchanges token", testOpenId4VciPreAuthFlowWithTxCode)
	t.Run("with wrong tx_code fails", testOpenId4VciPreAuthFlowWithWrongTxCode)
	t.Run("can be dismissed", testOpenId4VciPreAuthFlowCanBeDismissed)
	t.Run("issues credential with nested claims", testOpenId4VciPreAuthFlowNestedClaims)
	t.Run("issues multiple credential types", testOpenId4VciPreAuthFlowMultipleCredentialTypes)
	t.Run("issues credential with array claims", testOpenId4VciPreAuthFlowArrayClaims)
	t.Run("issues credential with mixed sd and non-sd claims", testOpenId4VciPreAuthFlowMixedSdNonSd)
	t.Run("issues eduid credential with boolean claims", testOpenId4VciPreAuthFlowEduIdCredential)
	t.Run("issues deeply nested credential", testOpenId4VciPreAuthFlowDeeplyNestedCredential)
	t.Run("issued credential can be deleted", testOpenId4VciPreAuthFlowCredentialDeletion)
}

func testOpenId4VciPreAuthFlowReachesPermission(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_OpenID4VCI, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)
}

func testOpenId4VciPreAuthFlowGrantsPermissionAndExchangesToken(t *testing.T) {
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

	// The test issuer uses did:web, so full credential verification should work.
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status,
		"server should have issued the credential via pre-authorized code flow")

	// Verify the credential appears in GetCredentials with correct attribute metadata.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, cred, "issued credential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("User"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("test@example.com"),
		},
	)
}

func testOpenId4VciPreAuthFlowWithTxCode(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOfferWithTxCode(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	require.NotNil(t, session.TransactionCodeParameters)
	require.Equal(t, "numeric", session.TransactionCodeParameters.InputMode)
	require.NotNil(t, session.TransactionCodeParameters.Length)
	require.Equal(t, 6, *session.TransactionCodeParameters.Length)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
			Proceed:         true,
			TransactionCode: &offer.TxCode,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status)

	// Verify the credential appears in GetCredentials with correct attribute metadata.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, cred, "issued credential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("TxCode"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("txcode@example.com"),
		},
	)
}

func testOpenId4VciPreAuthFlowWithWrongTxCode(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOfferWithTxCode(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	wrongCode := "000000"
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
			Proceed:         true,
			TransactionCode: &wrongCode,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Error)
}

func testOpenId4VciPreAuthFlowCanBeDismissed(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
}

func testOpenId4VciPreAuthFlowNestedClaims(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a HouseCredential with nested address claims.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Alice",
		"address": {
			"street": "123 Main St",
			"city": "Amsterdam",
			"country": "NL"
		}
	}`)

	// Verify the credential appears in GetCredentials with correct attributes.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "House Possession Credential (SD-JWT)")
	require.NotNil(t, cred, "issued HouseCredential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"owner_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
			Value:       strVal("Alice"),
		},
		header(
			[]any{"address"},
			clientmodels.TranslatedString{"en": "Address", "nl": "Adres"},
		),
		expectedAttr{
			Path:        []any{"address", "street"},
			DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
			Value:       strVal("123 Main St"),
		},
		expectedAttr{
			Path:        []any{"address", "city"},
			DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
			Value:       strVal("Amsterdam"),
		},
		expectedAttr{
			Path:        []any{"address", "country"},
			DisplayName: &clientmodels.TranslatedString{"en": "Country", "nl": "Land"},
			Value:       strVal("NL"),
		},
	)
}

func testOpenId4VciPreAuthFlowMultipleCredentialTypes(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue an EmailCredential.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "nested-test@example.com",
		"domain": "example.com"
	}`)

	// Issue a StudentCardCredential.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
		"university": "TU Delft",
		"level": "MSc",
		"student_id": "S12345"
	}`)

	// Issue a HouseCredential with nested claims.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Bob",
		"address": {
			"street": "456 Oak Ave",
			"city": "Rotterdam",
			"country": "NL"
		}
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	// Verify EmailCredential attributes.
	emailCred := findCredentialByName(t, creds, "en", "Email Credential (SD-JWT)")
	require.NotNil(t, emailCred, "EmailCredential should appear in GetCredentials")
	requireAttrsInOrder(t, emailCred.Attributes,
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("nested-test@example.com"),
		},
		expectedAttr{
			Path:        []any{"domain"},
			DisplayName: &clientmodels.TranslatedString{"en": "Domain", "nl": "Domein"},
			Value:       strVal("example.com"),
		},
	)

	// Verify StudentCardCredential attributes.
	studentCred := findCredentialByName(t, creds, "en", "Student Card Credential (SD-JWT)")
	require.NotNil(t, studentCred, "StudentCardCredential should appear in GetCredentials")
	requireAttrsInOrder(t, studentCred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("TU Delft"),
		},
		expectedAttr{
			Path:        []any{"level"},
			DisplayName: &clientmodels.TranslatedString{"en": "Level", "nl": "Niveau"},
			Value:       strVal("MSc"),
		},
		expectedAttr{
			Path:        []any{"student_id"},
			DisplayName: &clientmodels.TranslatedString{"en": "Student ID", "nl": "Studentnummer"},
			Value:       strVal("S12345"),
		},
		expectedAttr{
			Path:        []any{"courses"},
			DisplayName: &clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"},
			Value:       strVal(""), // not issued, falls back to empty
		},
	)

	// Verify HouseCredential attributes.
	houseCred := findCredentialByName(t, creds, "en", "House Possession Credential (SD-JWT)")
	require.NotNil(t, houseCred, "HouseCredential should appear in GetCredentials")
	requireAttrsInOrder(t, houseCred.Attributes,
		expectedAttr{
			Path:        []any{"owner_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
			Value:       strVal("Bob"),
		},
		header(
			[]any{"address"},
			clientmodels.TranslatedString{"en": "Address", "nl": "Adres"},
		),
		expectedAttr{
			Path:        []any{"address", "street"},
			DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
			Value:       strVal("456 Oak Ave"),
		},
		expectedAttr{
			Path:        []any{"address", "city"},
			DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
			Value:       strVal("Rotterdam"),
		},
		expectedAttr{
			Path:        []any{"address", "country"},
			DisplayName: &clientmodels.TranslatedString{"en": "Country", "nl": "Land"},
			Value:       strVal("NL"),
		},
	)
}

func testOpenId4VciPreAuthFlowArrayClaims(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
		"university": "TU Delft",
		"level": "MSc",
		"student_id": "S99999",
		"courses": ["Algorithms", "Databases", "Security"]
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Student Card Credential (SD-JWT)")
	require.NotNil(t, cred, "issued StudentCardCredential should appear in GetCredentials")

	// Array claims are flattened into indexed paths with a section header.
	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("TU Delft"),
		},
		expectedAttr{
			Path:        []any{"level"},
			DisplayName: &clientmodels.TranslatedString{"en": "Level", "nl": "Niveau"},
			Value:       strVal("MSc"),
		},
		expectedAttr{
			Path:        []any{"student_id"},
			DisplayName: &clientmodels.TranslatedString{"en": "Student ID", "nl": "Studentnummer"},
			Value:       strVal("S99999"),
		},
		header(
			[]any{"courses"},
			clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"},
		),
		expectedAttr{
			Path:  []any{"courses", 0},
			Value: strVal("Algorithms"),
		},
		expectedAttr{
			Path:  []any{"courses", 1},
			Value: strVal("Databases"),
		},
		expectedAttr{
			Path:  []any{"courses", 2},
			Value: strVal("Security"),
		},
	)
}

func testOpenId4VciPreAuthFlowMixedSdNonSd(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "MembershipCredentialSdJwt", `{
		"member_name": "Alice",
		"member_since": "2020-01-15",
		"membership_type": "gold"
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Membership Credential (SD-JWT)")
	require.NotNil(t, cred, "issued MembershipCredential should appear in GetCredentials")

	// member_name and membership_type are SD, member_since is non-SD.
	// All should appear in GetCredentials regardless.
	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"member_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Member Name", "nl": "Naam lid"},
			Value:       strVal("Alice"),
		},
		expectedAttr{
			Path:        []any{"member_since"},
			DisplayName: &clientmodels.TranslatedString{"en": "Member Since", "nl": "Lid sinds"},
			Value:       strVal("2020-01-15"),
		},
		expectedAttr{
			Path:        []any{"membership_type"},
			DisplayName: &clientmodels.TranslatedString{"en": "Membership Type", "nl": "Type lidmaatschap"},
			Value:       strVal("gold"),
		},
	)
}

func testOpenId4VciPreAuthFlowEduIdCredential(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "EduIdCredentialSdJwt", `{
		"schac_home_organization": "university.nl",
		"name": "Jan de Vries",
		"given_name": "Jan",
		"family_name": "de Vries",
		"email": "jan@university.nl",
		"eduperson_scoped_affiliation": "student@university.nl",
		"eduperson_assurance": "https://eduid.nl/assurance/low",
		"is_student": true,
		"is_faculty": false,
		"is_member": true,
		"is_staff": false,
		"is_alum": false,
		"is_affiliate": false,
		"is_employee": false,
		"is_library-walk-in": false
	}`)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "eduID")
	require.NotNil(t, cred, "issued EduIdCredential should appear in GetCredentials")

	// All 15 claims should be present. eduperson_assurance is non-SD.
	// Boolean values are stored as string "true"/"false" via NewAttributeValue.
	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"schac_home_organization"},
			DisplayName: &clientmodels.TranslatedString{"en": "Organization", "nl": "Instelling"},
			Value:       strVal("university.nl"),
		},
		expectedAttr{
			Path:        []any{"name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Name", "nl": "Naam"},
			Value:       strVal("Jan de Vries"),
		},
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given name", "nl": "Voornaam"},
			Value:       strVal("Jan"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
			Value:       strVal("de Vries"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "E-mail", "nl": "E-mail"},
			Value:       strVal("jan@university.nl"),
		},
		expectedAttr{
			Path:        []any{"eduperson_scoped_affiliation"},
			DisplayName: &clientmodels.TranslatedString{"en": "Affiliation (scoped)", "nl": "Betrekking (in relatie)"},
			Value:       strVal("student@university.nl"),
		},
		expectedAttr{
			Path:        []any{"eduperson_assurance"},
			DisplayName: &clientmodels.TranslatedString{"en": "Assurance", "nl": "Bevestiging"},
			Value:       strVal("https://eduid.nl/assurance/low"),
		},
		expectedAttr{
			Path:        []any{"is_student"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsStudent", "nl": "IsStudent"},
			Value:       boolVal(true),
		},
		expectedAttr{
			Path:        []any{"is_faculty"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsFaculty", "nl": "IsFaculteitslid"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_member"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsMember", "nl": "IsLid"},
			Value:       boolVal(true),
		},
		expectedAttr{
			Path:        []any{"is_staff"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsStaff", "nl": "IsStaf"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_alum"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsAlumnus", "nl": "IsAlumnus"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_affiliate"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsAffiliate", "nl": "IsVerbonden"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_employee"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsEmployee", "nl": "IsMedewerker"},
			Value:       boolVal(false),
		},
		expectedAttr{
			Path:        []any{"is_library-walk-in"},
			DisplayName: &clientmodels.TranslatedString{"en": "IsLibraryWalkIn", "nl": "IsBibliotheekBezoeker"},
			Value:       boolVal(false),
		},
	)
}

// testOpenId4VciPreAuthFlowDeeplyNestedCredential issues a credential with
// deeply nested structure: an object containing an array of objects, each
// containing an array of objects, each containing an array. This mirrors the
// structure in buildDeeplyNestedSdJwt from the SD-JWT presentation tests.
//
// Structure:
//
//	university (object):
//	  name: "TU Delft"
//	  faculties (array of objects):
//	    [0]:
//	      faculty_name: "EEMCS"
//	      departments (array of objects):
//	        [0]:
//	          dept_name: "Software Technology"
//	          courses: ["Compiler Construction", "Distributed Systems", "Intro to CS"]
//	        [1]:
//	          dept_name: "Data Science"
//	          courses: ["Machine Learning"]
//	    [1]:
//	      faculty_name: "Architecture"
//	      departments (array of objects):
//	        [0]:
//	          dept_name: "Urbanism"
//	          courses: ["City Planning"]
//	  founded: 1842
func testOpenId4VciPreAuthFlowDeeplyNestedCredential(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
		"university": {
			"name": "TU Delft",
			"faculties": [
				{
					"faculty_name": "EEMCS",
					"departments": [
						{
							"dept_name": "Software Technology",
							"courses": ["Compiler Construction", "Distributed Systems", "Intro to CS"]
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
	}`)

	// Verify the credential appears in GetCredentials.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Organization Credential (SD-JWT)")
	require.NotNil(t, cred, "issued OrganizationCredential should appear in GetCredentials")

	deptName := &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"}
	facName := &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"}
	departments := clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}
	courses := clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}

	requireAttrsInOrder(t, cred.Attributes,
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		expectedAttr{
			Path:        []any{"university", "name"},
			DisplayName: &clientmodels.TranslatedString{"en": "University Name", "nl": "Naam universiteit"},
			Value:       strVal("TU Delft"),
		},
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
		// Faculty 0 (EEMCS) — keys ordered by metadata: faculty_name, departments.
		expectedAttr{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		// Department 0 (Software Technology) — keys ordered by metadata: dept_name, courses.
		expectedAttr{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 1},
			Value: strVal("Distributed Systems"),
		},
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 2},
			Value: strVal("Intro to CS"),
		},
		// Department 1 (Data Science).
		expectedAttr{
			Path:        []any{"university", "faculties", 0, "departments", 1, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Data Science"),
		},
		header([]any{"university", "faculties", 0, "departments", 1, "courses"}, courses),
		expectedAttr{
			Path:  []any{"university", "faculties", 0, "departments", 1, "courses", 0},
			Value: strVal("Machine Learning"),
		},
		// Faculty 1 (Architecture).
		expectedAttr{
			Path:        []any{"university", "faculties", 1, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("Architecture"),
		},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		expectedAttr{
			Path:        []any{"university", "faculties", 1, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Urbanism"),
		},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		expectedAttr{
			Path:  []any{"university", "faculties", 1, "departments", 0, "courses", 0},
			Value: strVal("City Planning"),
		},
		expectedAttr{
			Path:        []any{"university", "founded"},
			DisplayName: &clientmodels.TranslatedString{"en": "Founded", "nl": "Opgericht"},
			Value:       intVal(1842),
		},
	)

	// Verify the credential can be disclosed over OpenID4VP.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "org-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/organization"]
					},
					"claims": [
						{ "path": ["university"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	cred2 := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred2))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Verify the verifier received the university claim as a nested object.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)

	// Check the deeply nested structure was preserved.
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "name"}, "TU Delft"),
		claim([]any{"university", "faculties", 0, "faculty_name"}, "EEMCS"),
		claim([]any{"university", "faculties", 0, "departments", 0, "dept_name"}, "Software Technology"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 0}, "Compiler Construction"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 1}, "Distributed Systems"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 2}, "Intro to CS"),
		claim([]any{"university", "faculties", 0, "departments", 1, "dept_name"}, "Data Science"),
		claim([]any{"university", "faculties", 0, "departments", 1, "courses", 0}, "Machine Learning"),
		claim([]any{"university", "faculties", 1, "faculty_name"}, "Architecture"),
		claim([]any{"university", "faculties", 1, "departments", 0, "dept_name"}, "Urbanism"),
		claim([]any{"university", "faculties", 1, "departments", 0, "courses", 0}, "City Planning"),
		claim([]any{"university", "founded"}, "1842"),
	)
}

// testOpenId4VciPreAuthFlowCredentialDeletion verifies that an EUDI SD-JWT credential
// issued via OID4VCI can be deleted. The credential only exists in the EUDI GORM storage
// (not in the IRMA BBolt storage), so its hash won't be found in getIrmaCredentialInfoList().
// This specifically guards against an index-out-of-range panic when the hash lookup returns -1.
func testOpenId4VciPreAuthFlowCredentialDeletion(t *testing.T) {
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
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Verify the credential was issued.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, cred, "issued credential should appear in GetCredentials")
	deletedHash := cred.Hash

	// Delete the EUDI credential using its own instance IDs.
	// This must not panic even though the hash is absent from the IRMA credential list.
	require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))

	// Verify the specific credential is gone by checking no credential has the deleted hash.
	creds, err = c.GetCredentials()
	require.NoError(t, err)
	for _, c := range creds {
		require.NotEqual(t, deletedHash, c.Hash, "deleted credential (hash %s) should no longer appear in GetCredentials", deletedHash)
	}
}

// ========================================================================
// Authorization code flow
// ========================================================================

func testSessionHandlerForOpenID4VCIAuthCode(t *testing.T) {
	t.Run("reaches auth request", testOpenId4VciAuthCodeFlowReachesAuthRequest)
	t.Run("grants permission and exchanges token", testOpenId4VciAuthCodeFlowGrantsPermissionAndExchangesToken)
	t.Run("can be dismissed", testOpenId4VciAuthCodeFlowCanBeDismissed)
	t.Run("issues credential with nested claims", testOpenId4VciAuthCodeFlowNestedClaims)
}

func testOpenId4VciAuthCodeFlowReachesAuthRequest(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_OpenID4VCI, session.Protocol)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestAuthorizationCode)
	require.NotEmpty(t, session.AuthorizationRequestUrl)
}

func testOpenId4VciAuthCodeFlowGrantsPermissionAndExchangesToken(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestAuthorizationCode)

	code := getAuthorizationCode(t, session.AuthorizationRequestUrl)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_AuthorizationCode,
		Payload: clientmodels.SessionAuthCodeInteractionPayload{
			Code:    &code,
			Proceed: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, authcodeIssuerURL, authcodeAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status,
		"server should have issued the credential via authorization code flow")

	// Verify the credential appears in GetCredentials with correct attribute metadata.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT, Auth Code)")
	require.NotNil(t, cred, "issued credential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       strVal("Test"),
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       strVal("AuthCode"),
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       strVal("authcode@example.com"),
		},
	)
}

func testOpenId4VciAuthCodeFlowCanBeDismissed(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestAuthorizationCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Dismissed)
}

func testOpenId4VciAuthCodeFlowNestedClaims(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a HouseCredential with nested address claims via authorization code flow.
	issueCredentialViaOid4VciAuthCode(t, c, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Charlie",
		"address": {
			"street": "789 Elm St",
			"city": "Utrecht",
			"country": "NL"
		}
	}`)

	// Verify the credential appears in GetCredentials with correct attributes.
	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", "House Possession Credential (SD-JWT, Auth Code)")
	require.NotNil(t, cred, "issued HouseCredential should appear in GetCredentials")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"owner_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
			Value:       strVal("Charlie"),
		},
		header(
			[]any{"address"},
			clientmodels.TranslatedString{"en": "Address", "nl": "Adres"},
		),
		expectedAttr{
			Path:        []any{"address", "street"},
			DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
			Value:       strVal("789 Elm St"),
		},
		expectedAttr{
			Path:        []any{"address", "city"},
			DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
			Value:       strVal("Utrecht"),
		},
		expectedAttr{
			Path:        []any{"address", "country"},
			DisplayName: &clientmodels.TranslatedString{"en": "Country", "nl": "Land"},
			Value:       strVal("NL"),
		},
	)
}

// issueCredentialViaOid4VciAuthCode issues a single credential through the
// veramo-agent OID4VCI authorization code flow.
func issueCredentialViaOid4VciAuthCode(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	credentialType string,
	claimsJSON string,
) {
	t.Helper()

	offerBody := fmt.Sprintf(`{
		"credentials": [%q],
		"grants": {
			"authorization_code": {
				"issuer_state": "generate"
			}
		},
		"credentialDataSupplierInput": %s
	}`, credentialType, claimsJSON)

	offer := postOffer(t, authcodeIssuerURL, authcodeAdminToken, offerBody)
	startOpenID4VCISession(t, c, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_RequestAuthorizationCode)

	code := getAuthorizationCode(t, session.AuthorizationRequestUrl)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_AuthorizationCode,
		Payload: clientmodels.SessionAuthCodeInteractionPayload{
			Code:    &code,
			Proceed: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, authcodeIssuerURL, authcodeAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status)
}
