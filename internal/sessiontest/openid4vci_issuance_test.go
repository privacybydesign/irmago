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

	attrMap := attributeMap(cred.Attributes)
	requireAttributeDisplayName(t, attrMap, "given_name", "en", "Given Name")
	requireAttributeDisplayName(t, attrMap, "family_name", "en", "Family Name")
	requireAttributeDisplayName(t, attrMap, "email", "en", "Email")
	requireAttributeStringValue(t, attrMap, "given_name", "Test")
	requireAttributeStringValue(t, attrMap, "family_name", "User")
	requireAttributeStringValue(t, attrMap, "email", "test@example.com")
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

	attrMap := attributeMap(cred.Attributes)
	requireAttributeDisplayName(t, attrMap, "given_name", "en", "Given Name")
	requireAttributeDisplayName(t, attrMap, "family_name", "en", "Family Name")
	requireAttributeDisplayName(t, attrMap, "email", "en", "Email")
	requireAttributeStringValue(t, attrMap, "given_name", "Test")
	requireAttributeStringValue(t, attrMap, "family_name", "TxCode")
	requireAttributeStringValue(t, attrMap, "email", "txcode@example.com")
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

	attrMap := attributeMap(cred.Attributes)

	// Top-level claim: owner_name
	requireAttributeDisplayName(t, attrMap, "owner_name", "en", "Owner Name")
	requireAttributeStringValue(t, attrMap, "owner_name", "Alice")

	// Nested claim: address is an object containing street, city, country
	attr, ok := attrMap["address"]
	require.True(t, ok, "attribute \"address\" should exist")
	require.NotNil(t, attr.Value, "attribute \"address\" should have a value")
	require.Equal(t, clientmodels.AttributeType_Object, attr.Value.Type, "address should be an object type")
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
	emailAttrs := attributeMap(emailCred.Attributes)
	requireAttributeDisplayName(t, emailAttrs, "email", "en", "Email")
	requireAttributeDisplayName(t, emailAttrs, "domain", "en", "Domain")
	requireAttributeStringValue(t, emailAttrs, "email", "nested-test@example.com")
	requireAttributeStringValue(t, emailAttrs, "domain", "example.com")

	// Verify StudentCardCredential attributes.
	studentCred := findCredentialByName(t, creds, "en", "Student Card Credential (SD-JWT)")
	require.NotNil(t, studentCred, "StudentCardCredential should appear in GetCredentials")
	studentAttrs := attributeMap(studentCred.Attributes)
	requireAttributeDisplayName(t, studentAttrs, "university", "en", "University")
	requireAttributeDisplayName(t, studentAttrs, "level", "en", "Level")
	requireAttributeDisplayName(t, studentAttrs, "student_id", "en", "Student ID")
	requireAttributeStringValue(t, studentAttrs, "university", "TU Delft")
	requireAttributeStringValue(t, studentAttrs, "level", "MSc")
	requireAttributeStringValue(t, studentAttrs, "student_id", "S12345")

	// Verify HouseCredential attributes.
	houseCred := findCredentialByName(t, creds, "en", "House Possession Credential (SD-JWT)")
	require.NotNil(t, houseCred, "HouseCredential should appear in GetCredentials")
	houseAttrs := attributeMap(houseCred.Attributes)
	requireAttributeDisplayName(t, houseAttrs, "owner_name", "en", "Owner Name")
	requireAttributeStringValue(t, houseAttrs, "owner_name", "Bob")

	// The nested address claim should be stored as an object.
	addrAttr, ok := houseAttrs["address"]
	require.True(t, ok, "attribute \"address\" should exist")
	require.NotNil(t, addrAttr.Value, "attribute \"address\" should have a value")
	require.Equal(t, clientmodels.AttributeType_Object, addrAttr.Value.Type, "address should be an object type")
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

	attrMap := attributeMap(cred.Attributes)
	requireAttributeDisplayName(t, attrMap, "given_name", "en", "Given Name")
	requireAttributeDisplayName(t, attrMap, "family_name", "en", "Family Name")
	requireAttributeDisplayName(t, attrMap, "email", "en", "Email")
	requireAttributeStringValue(t, attrMap, "given_name", "Test")
	requireAttributeStringValue(t, attrMap, "family_name", "AuthCode")
	requireAttributeStringValue(t, attrMap, "email", "authcode@example.com")
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

	attrMap := attributeMap(cred.Attributes)

	// Top-level claim: owner_name
	requireAttributeDisplayName(t, attrMap, "owner_name", "en", "Owner Name")
	requireAttributeStringValue(t, attrMap, "owner_name", "Charlie")

	// Nested claim: address is an object containing street, city, country
	addrAttr, ok := attrMap["address"]
	require.True(t, ok, "attribute \"address\" should exist")
	require.NotNil(t, addrAttr.Value, "attribute \"address\" should have a value")
	require.Equal(t, clientmodels.AttributeType_Object, addrAttr.Value.Type, "address should be an object type")
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
