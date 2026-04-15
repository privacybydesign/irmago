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
			DisplayName: clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       "Test",
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       "User",
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       "test@example.com",
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
			DisplayName: clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       "Test",
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       "TxCode",
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       "txcode@example.com",
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

	// Nested claims are resolved via their metadata paths. The credential service
	// iterates metadata claims in DB order (which may differ from config file order).
	// Use attributeMap for order-independent checks.
	am := attributeMap(cred.Attributes)
	require.Len(t, cred.Attributes, 4)
	requireAttrFull(t, am, expectedAttr{
		Path:        []any{"owner_name"},
		DisplayName: clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
		Value:       "Alice",
	})
	requireAttrFull(t, am, expectedAttr{
		Path:        []any{"address", "street"},
		DisplayName: clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
		Value:       "123 Main St",
	})
	requireAttrFull(t, am, expectedAttr{
		Path:        []any{"address", "city"},
		DisplayName: clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
		Value:       "Amsterdam",
	})
	requireAttrFull(t, am, expectedAttr{
		Path:        []any{"address", "country"},
		DisplayName: clientmodels.TranslatedString{"en": "Country", "nl": "Land"},
		Value:       "NL",
	})
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
			DisplayName: clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       "nested-test@example.com",
		},
		expectedAttr{
			Path:        []any{"domain"},
			DisplayName: clientmodels.TranslatedString{"en": "Domain", "nl": "Domein"},
			Value:       "example.com",
		},
	)

	// Verify StudentCardCredential attributes.
	studentCred := findCredentialByName(t, creds, "en", "Student Card Credential (SD-JWT)")
	require.NotNil(t, studentCred, "StudentCardCredential should appear in GetCredentials")
	requireAttrsInOrder(t, studentCred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       "TU Delft",
		},
		expectedAttr{
			Path:        []any{"level"},
			DisplayName: clientmodels.TranslatedString{"en": "Level", "nl": "Niveau"},
			Value:       "MSc",
		},
		expectedAttr{
			Path:        []any{"student_id"},
			DisplayName: clientmodels.TranslatedString{"en": "Student ID", "nl": "Studentnummer"},
			Value:       "S12345",
		},
		expectedAttr{
			Path:        []any{"courses"},
			DisplayName: clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"},
			Value:       "", // not issued, falls back to empty
		},
	)

	// Verify HouseCredential attributes.
	houseCred := findCredentialByName(t, creds, "en", "House Possession Credential (SD-JWT)")
	require.NotNil(t, houseCred, "HouseCredential should appear in GetCredentials")
	houseAttrs := attributeMap(houseCred.Attributes)
	require.Len(t, houseCred.Attributes, 4)
	requireAttrFull(t, houseAttrs, expectedAttr{
		Path:        []any{"owner_name"},
		DisplayName: clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
		Value:       "Bob",
	})
	requireAttrFull(t, houseAttrs, expectedAttr{
		Path:        []any{"address", "street"},
		DisplayName: clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
		Value:       "456 Oak Ave",
	})
	requireAttrFull(t, houseAttrs, expectedAttr{
		Path:        []any{"address", "city"},
		DisplayName: clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
		Value:       "Rotterdam",
	})
	requireAttrFull(t, houseAttrs, expectedAttr{
		Path:        []any{"address", "country"},
		DisplayName: clientmodels.TranslatedString{"en": "Country", "nl": "Land"},
		Value:       "NL",
	})
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

	// Array claims are flattened into indexed paths.
	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       "TU Delft",
		},
		expectedAttr{
			Path:        []any{"level"},
			DisplayName: clientmodels.TranslatedString{"en": "Level", "nl": "Niveau"},
			Value:       "MSc",
		},
		expectedAttr{
			Path:        []any{"student_id"},
			DisplayName: clientmodels.TranslatedString{"en": "Student ID", "nl": "Studentnummer"},
			Value:       "S99999",
		},
		expectedAttr{
			Path:        []any{"courses", 0},
			DisplayName: clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"},
			Value:       "Algorithms",
		},
		expectedAttr{
			Path:        []any{"courses", 1},
			DisplayName: clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"},
			Value:       "Databases",
		},
		expectedAttr{
			Path:        []any{"courses", 2},
			DisplayName: clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"},
			Value:       "Security",
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
			DisplayName: clientmodels.TranslatedString{"en": "Member Name", "nl": "Naam lid"},
			Value:       "Alice",
		},
		expectedAttr{
			Path:        []any{"member_since"},
			DisplayName: clientmodels.TranslatedString{"en": "Member Since", "nl": "Lid sinds"},
			Value:       "2020-01-15",
		},
		expectedAttr{
			Path:        []any{"membership_type"},
			DisplayName: clientmodels.TranslatedString{"en": "Membership Type", "nl": "Type lidmaatschap"},
			Value:       "gold",
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
			DisplayName: clientmodels.TranslatedString{"en": "Organization", "nl": "Instelling"},
			Value:       "university.nl",
		},
		expectedAttr{
			Path:        []any{"name"},
			DisplayName: clientmodels.TranslatedString{"en": "Name", "nl": "Naam"},
			Value:       "Jan de Vries",
		},
		expectedAttr{
			Path:        []any{"given_name"},
			DisplayName: clientmodels.TranslatedString{"en": "Given name", "nl": "Voornaam"},
			Value:       "Jan",
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
			Value:       "de Vries",
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: clientmodels.TranslatedString{"en": "E-mail", "nl": "E-mail"},
			Value:       "jan@university.nl",
		},
		expectedAttr{
			Path:        []any{"eduperson_scoped_affiliation"},
			DisplayName: clientmodels.TranslatedString{"en": "Affiliation (scoped)", "nl": "Betrekking (in relatie)"},
			Value:       "student@university.nl",
		},
		expectedAttr{
			Path:        []any{"eduperson_assurance"},
			DisplayName: clientmodels.TranslatedString{"en": "Assurance", "nl": "Bevestiging"},
			Value:       "https://eduid.nl/assurance/low",
		},
		expectedAttr{
			Path:        []any{"is_student"},
			DisplayName: clientmodels.TranslatedString{"en": "IsStudent", "nl": "IsStudent"},
			Value:       "true",
		},
		expectedAttr{
			Path:        []any{"is_faculty"},
			DisplayName: clientmodels.TranslatedString{"en": "IsFaculty", "nl": "IsFaculteitslid"},
			Value:       "false",
		},
		expectedAttr{
			Path:        []any{"is_member"},
			DisplayName: clientmodels.TranslatedString{"en": "IsMember", "nl": "IsLid"},
			Value:       "true",
		},
		expectedAttr{
			Path:        []any{"is_staff"},
			DisplayName: clientmodels.TranslatedString{"en": "IsStaff", "nl": "IsStaf"},
			Value:       "false",
		},
		expectedAttr{
			Path:        []any{"is_alum"},
			DisplayName: clientmodels.TranslatedString{"en": "IsAlumnus", "nl": "IsAlumnus"},
			Value:       "false",
		},
		expectedAttr{
			Path:        []any{"is_affiliate"},
			DisplayName: clientmodels.TranslatedString{"en": "IsAffiliate", "nl": "IsVerbonden"},
			Value:       "false",
		},
		expectedAttr{
			Path:        []any{"is_employee"},
			DisplayName: clientmodels.TranslatedString{"en": "IsEmployee", "nl": "IsMedewerker"},
			Value:       "false",
		},
		expectedAttr{
			Path:        []any{"is_library-walk-in"},
			DisplayName: clientmodels.TranslatedString{"en": "IsLibraryWalkIn", "nl": "IsBibliotheekBezoeker"},
			Value:       "false",
		},
	)
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
			DisplayName: clientmodels.TranslatedString{"en": "Given Name", "nl": "Voornaam"},
			Value:       "Test",
		},
		expectedAttr{
			Path:        []any{"family_name"},
			DisplayName: clientmodels.TranslatedString{"en": "Family Name", "nl": "Achternaam"},
			Value:       "AuthCode",
		},
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
			Value:       "authcode@example.com",
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

	am := attributeMap(cred.Attributes)
	require.Len(t, cred.Attributes, 4)
	requireAttrFull(t, am, expectedAttr{
		Path:        []any{"owner_name"},
		DisplayName: clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
		Value:       "Charlie",
	})
	requireAttrFull(t, am, expectedAttr{
		Path:        []any{"address", "street"},
		DisplayName: clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
		Value:       "789 Elm St",
	})
	requireAttrFull(t, am, expectedAttr{
		Path:        []any{"address", "city"},
		DisplayName: clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
		Value:       "Utrecht",
	})
	requireAttrFull(t, am, expectedAttr{
		Path:        []any{"address", "country"},
		DisplayName: clientmodels.TranslatedString{"en": "Country", "nl": "Land"},
		Value:       "NL",
	})
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
