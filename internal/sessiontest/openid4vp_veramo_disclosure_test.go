package sessiontest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/require"
)

const (
	veramoVerifierBaseURL    = "http://localhost:8891"
	veramoVerifierName       = "test-verifier"
	veramoVerifierAdminToken = "test-verifier-admin-token"
)

func testSessionHandlerForOpenId4VpWithSdJwtVcs(t *testing.T) {
	t.Run("issue via openid4vci and disclose via openid4vp", testIssueViaOid4VciAndDiscloseViaOid4Vp)
	t.Run("disclose single credential with multiple attributes", testDiscloseCredentialWithMultipleAttributes)
	t.Run("choice between two credential types", testChoiceBetweenTwoCredentialTypes)
	t.Run("multiple required credentials", testMultipleRequiredCredentials)
	t.Run("optional credential", testOptionalCredential)
	t.Run("credential with specific claim value", testCredentialWithSpecificClaimValue)
}

func testIssueViaOid4VciAndDiscloseViaOid4Vp(t *testing.T) {
	// Step 1: Issue an SD-JWT credential via the veramo-agent OID4VCI flow.
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

	status := checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status)

	// Step 2: Create a DCQL verification session at the veramo-verifier.
	veramoSession := createVeramoVerifierDcqlSession(t)
	require.NotEmpty(t, veramoSession.State)

	// Step 3: Start an OpenID4VP session in the client using the verifier's request URI.
	sessionReq, err := json.Marshal(client.SessionRequestData{
		Qr:       irma.Qr{URL: veramoSession.RequestUri},
		Protocol: clientmodels.Protocol_OpenID4VP,
	})
	require.NoError(t, err)
	c.NewSession(string(sessionReq))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// Step 4: Grant permission to disclose.
	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.NotEmpty(t, plan.DisclosureChoicesOverview)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions, "should have a credential to disclose")

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]

	// Verify attribute display names and values.
	attrMap := attributeMap(cred.Attributes)
	requireAttributeDisplayName(t, attrMap, "given_name", "en", "given_name")
	requireAttributeDisplayName(t, attrMap, "email", "en", "email")
	requireAttributeTranslatedValue(t, attrMap, "given_name", "en", "Test")
	requireAttributeTranslatedValue(t, attrMap, "email", "en", "test@example.com")

	attrIds := make([]string, len(cred.Attributes))
	for i, attr := range cred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Step 5: Verify the verifier received the VP token.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
}

// testDiscloseCredentialWithMultipleAttributes issues an EmailCredential and
// requests both email and domain claims in a single credential query.
func testDiscloseCredentialWithMultipleAttributes(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue an EmailCredential via OID4VCI.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "alice@example.com",
		"domain": "example.com"
	}`)

	// Create a DCQL session requesting both email and domain.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "email-cred",
					"format": "vc+sd-jwt",
					"claims": [
						{ "path": ["email"] },
						{ "path": ["domain"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	// Start OpenID4VP disclosure session.
	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.NotEmpty(t, plan.DisclosureChoicesOverview)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions)

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]

	// Verify both attributes are present with correct display names and values.
	require.GreaterOrEqual(t, len(cred.Attributes), 2, "credential should have at least email and domain attributes")
	attrMap := attributeMap(cred.Attributes)
	requireAttributeDisplayName(t, attrMap, "email", "en", "email")
	requireAttributeDisplayName(t, attrMap, "domain", "en", "domain")
	requireAttributeTranslatedValue(t, attrMap, "email", "en", "alice@example.com")
	requireAttributeTranslatedValue(t, attrMap, "domain", "en", "example.com")

	attrIds := make([]string, len(cred.Attributes))
	for i, attr := range cred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
}

// testChoiceBetweenTwoCredentialTypes issues both an EmailCredential and a
// PhoneCredential, then creates a DCQL query with credential_sets that accepts
// either one. The client should present both as options.
func testChoiceBetweenTwoCredentialTypes(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue EmailCredential.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "bob@example.com",
		"domain": "example.com"
	}`)

	// Issue PhoneCredential.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "PhoneCredentialSdJwt", `{
		"phone_number": "+31612345678"
	}`)

	// DCQL query: either email OR phone credential satisfies the request.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "email-cred",
					"format": "vc+sd-jwt",
					"claims": [
						{ "path": ["email"] }
					]
				},
				{
					"id": "phone-cred",
					"format": "vc+sd-jwt",
					"claims": [
						{ "path": ["phone_number"] }
					]
				}
			],
			"credential_sets": [
				{ "options": [["email-cred"], ["phone-cred"]] }
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.NotEmpty(t, plan.DisclosureChoicesOverview)

	// There should be one pick-one set with two owned options (email and phone).
	pickOne := plan.DisclosureChoicesOverview[0]
	require.GreaterOrEqual(t, len(pickOne.OwnedOptions), 2,
		"should have at least two credential options to choose from")

	// Verify that both options have the expected attributes.
	for _, opt := range pickOne.OwnedOptions {
		attrMap := attributeMap(opt.Attributes)
		// Each option should have at least one attribute with a display name.
		if _, hasEmail := attrMap["email"]; hasEmail {
			requireAttributeDisplayName(t, attrMap, "email", "en", "email")
			requireAttributeTranslatedValue(t, attrMap, "email", "en", "bob@example.com")
		}
		if _, hasPhone := attrMap["phone_number"]; hasPhone {
			requireAttributeDisplayName(t, attrMap, "phone_number", "en", "phone_number")
			requireAttributeTranslatedValue(t, attrMap, "phone_number", "en", "+31612345678")
		}
	}

	// Pick the first option (whichever it is) and disclose.
	chosen := pickOne.OwnedOptions[0]
	attrIds := make([]string, len(chosen.Attributes))
	for i, attr := range chosen.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(chosen, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
}

// testMultipleRequiredCredentials issues both an EmailCredential and a
// PhoneCredential, then creates a DCQL query that requires BOTH credentials
// (no credential_sets, just two separate credential queries).
func testMultipleRequiredCredentials(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue EmailCredential.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "carol@example.com",
		"domain": "example.com"
	}`)

	// Issue PhoneCredential.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "PhoneCredentialSdJwt", `{
		"phone_number": "+31687654321"
	}`)

	// DCQL query: both credentials are required (no credential_sets).
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "email-cred",
					"format": "vc+sd-jwt",
					"claims": [
						{ "path": ["email"] }
					]
				},
				{
					"id": "phone-cred",
					"format": "vc+sd-jwt",
					"claims": [
						{ "path": ["phone_number"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	// Two separate disclosure choices, one for each required credential.
	require.Len(t, plan.DisclosureChoicesOverview, 2,
		"should have two required credential choices")

	// Build choices for both credentials and verify attributes.
	choices := make([]clientmodels.DisclosureDisconSelection, 2)
	for i, pickOne := range plan.DisclosureChoicesOverview {
		require.NotEmpty(t, pickOne.OwnedOptions, "should own a matching credential for choice %d", i)
		cred := pickOne.OwnedOptions[0]

		// Verify attribute display names and values for each credential.
		attrMap := attributeMap(cred.Attributes)
		if _, hasEmail := attrMap["email"]; hasEmail {
			requireAttributeDisplayName(t, attrMap, "email", "en", "email")
			requireAttributeTranslatedValue(t, attrMap, "email", "en", "carol@example.com")
		}
		if _, hasPhone := attrMap["phone_number"]; hasPhone {
			requireAttributeDisplayName(t, attrMap, "phone_number", "en", "phone_number")
			requireAttributeTranslatedValue(t, attrMap, "phone_number", "en", "+31687654321")
		}

		attrIds := make([]string, len(cred.Attributes))
		for j, attr := range cred.Attributes {
			attrIds[j] = attr.Id
		}
		choices[i] = makeDisclosureChoice(cred, attrIds...)
	}
	grantPermission(t, c, session.Id, choices...)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
}

// testOptionalCredential issues only an EmailCredential. The DCQL query has
// credential_sets with email required and phone optional. The user can satisfy
// the request with just the email credential.
func testOptionalCredential(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue only EmailCredential.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "dave@example.com",
		"domain": "example.com"
	}`)

	// DCQL query: email is required, phone is optional.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "email-cred",
					"format": "vc+sd-jwt",
					"claims": [
						{ "path": ["email"] }
					]
				},
				{
					"id": "phone-cred",
					"format": "vc+sd-jwt",
					"claims": [
						{ "path": ["phone_number"] }
					]
				}
			],
			"credential_sets": [
				{ "options": [["email-cred"]] },
				{ "options": [["phone-cred"]], "required": false }
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.NotEmpty(t, plan.DisclosureChoicesOverview)

	// The required email credential should be owned.
	requiredChoice := plan.DisclosureChoicesOverview[0]
	require.NotEmpty(t, requiredChoice.OwnedOptions, "should own the email credential")

	emailCred := requiredChoice.OwnedOptions[0]

	// Verify email attribute display name and value.
	attrMap := attributeMap(emailCred.Attributes)
	requireAttributeDisplayName(t, attrMap, "email", "en", "email")
	requireAttributeTranslatedValue(t, attrMap, "email", "en", "dave@example.com")

	attrIds := make([]string, len(emailCred.Attributes))
	for i, attr := range emailCred.Attributes {
		attrIds[i] = attr.Id
	}

	// Grant permission with the required email credential; skip the optional phone with an empty selection.
	grantPermission(t, c, session.Id,
		makeDisclosureChoice(emailCred, attrIds...),
		clientmodels.DisclosureDisconSelection{},
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
}

// testCredentialWithSpecificClaimValue issues two EmailCredentials with
// different domains. The DCQL query requests email with a specific domain
// value. Only the matching credential should be selectable.
func testCredentialWithSpecificClaimValue(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue first EmailCredential with domain "example.com".
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "eve@example.com",
		"domain": "example.com"
	}`)

	// Issue second EmailCredential with domain "other.org".
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "eve@other.org",
		"domain": "other.org"
	}`)

	// DCQL query: request email credential with domain matching "example.com".
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "email-cred",
					"format": "vc+sd-jwt",
					"claims": [
						{ "path": ["email"] },
						{ "path": ["domain"], "values": ["example.com"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.NotEmpty(t, plan.DisclosureChoicesOverview)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions)

	// Only the credential with domain "example.com" should be selectable.
	// Verify that the owned options have the correct domain value.
	var matchingCred *clientmodels.SelectableCredentialInstance
	for _, opt := range plan.DisclosureChoicesOverview[0].OwnedOptions {
		for _, attr := range opt.Attributes {
			if attr.Id == "domain" && attr.Value != nil &&
				attr.Value.TranslatedString != nil {
				for _, val := range *attr.Value.TranslatedString {
					if val == "example.com" {
						matchingCred = opt
						break
					}
				}
			}
		}
		if matchingCred != nil {
			break
		}
	}
	require.NotNil(t, matchingCred, "should find a credential with domain example.com")

	// Verify attribute display names and values on the matching credential.
	attrMap := attributeMap(matchingCred.Attributes)
	requireAttributeDisplayName(t, attrMap, "email", "en", "email")
	requireAttributeDisplayName(t, attrMap, "domain", "en", "domain")
	requireAttributeTranslatedValue(t, attrMap, "email", "en", "eve@example.com")
	requireAttributeTranslatedValue(t, attrMap, "domain", "en", "example.com")

	attrIds := make([]string, len(matchingCred.Attributes))
	for i, attr := range matchingCred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(matchingCred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
}

// ---------------------------------------------------------------------------
// Veramo verifier helpers
// ---------------------------------------------------------------------------

type veramoVerifierSession struct {
	State      string `json:"state"`
	RequestUri string `json:"requestUri"`
	CheckUri   string `json:"checkUri"`
}

type veramoCheckResult struct {
	Status string `json:"status"`
	Result any    `json:"result"`
}

func createVeramoVerifierDcqlSession(t *testing.T) veramoVerifierSession {
	t.Helper()

	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "test-credential",
					"format": "vc+sd-jwt",
					"claims": [
						{ "path": ["given_name"] },
						{ "path": ["email"] }
					]
				}
			]
		}
	}`

	return createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
}

func createVeramoVerifierDcqlSessionWithQuery(t *testing.T, dcqlQuery string) veramoVerifierSession {
	t.Helper()

	apiURL := fmt.Sprintf("%s/%s/api/create-dcql-offer", veramoVerifierBaseURL, veramoVerifierName)
	req, err := http.NewRequest(http.MethodPost, apiURL, strings.NewReader(dcqlQuery))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+veramoVerifierAdminToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "create-dcql-offer should succeed")

	var result veramoVerifierSession
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.NotEmpty(t, result.State, "session state should not be empty")
	return result
}

func checkVeramoVerifierOfferStatus(t *testing.T, state string) veramoCheckResult {
	t.Helper()

	checkURL := fmt.Sprintf("%s/%s/api/check-offer/%s", veramoVerifierBaseURL, veramoVerifierName, state)
	req, err := http.NewRequest(http.MethodGet, checkURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+veramoVerifierAdminToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result veramoCheckResult
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

// ---------------------------------------------------------------------------
// OID4VCI issuance helper
// ---------------------------------------------------------------------------

// issueCredentialViaOid4Vci issues a single credential through the veramo-agent
// OID4VCI pre-authorized code flow. The credentialType identifies the credential
// configuration (e.g. "EmailCredentialSdJwt") and claimsJSON provides the claim
// values as a JSON object.
func issueCredentialViaOid4Vci(
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
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": %s
	}`, credentialType, claimsJSON)

	offer := postOffer(t, preAuthIssuerURL, preAuthAdminToken, offerBody)
	startOpenID4VCISession(t, c, offer.URI)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload:   clientmodels.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status)
}

// findCredentialByName returns the first credential whose Name contains the
// expected value for the given locale, or nil if none match.
func findCredentialByName(t *testing.T, creds []*clientmodels.Credential, locale, expected string) *clientmodels.Credential {
	t.Helper()
	for _, cred := range creds {
		if name, ok := cred.Name[locale]; ok && name == expected {
			return cred
		}
	}
	return nil
}

// attributeMap builds a map from attribute ID to Attribute for easy lookup.
func attributeMap(attrs []clientmodels.Attribute) map[string]clientmodels.Attribute {
	m := make(map[string]clientmodels.Attribute, len(attrs))
	for _, a := range attrs {
		m[a.Id] = a
	}
	return m
}

// requireAttributeDisplayName asserts that the attribute with the given ID has
// the expected display name for the given locale.
func requireAttributeDisplayName(t *testing.T, attrs map[string]clientmodels.Attribute, attrId, locale, expected string) {
	t.Helper()
	attr, ok := attrs[attrId]
	require.True(t, ok, "attribute %q should exist", attrId)
	actual, ok := attr.DisplayName[locale]
	require.True(t, ok, "attribute %q should have display name for locale %q", attrId, locale)
	require.Equal(t, expected, actual, "attribute %q display name mismatch", attrId)
}

// requireAttributeTranslatedValue asserts that the attribute with the given ID
// has a TranslatedString value matching the expected string for the given locale.
func requireAttributeTranslatedValue(t *testing.T, attrs map[string]clientmodels.Attribute, attrId, locale, expected string) {
	t.Helper()
	attr, ok := attrs[attrId]
	require.True(t, ok, "attribute %q should exist", attrId)
	require.NotNil(t, attr.Value, "attribute %q should have a value", attrId)
	require.NotNil(t, attr.Value.TranslatedString, "attribute %q value should be a TranslatedString", attrId)
	actual, ok := (*attr.Value.TranslatedString)[locale]
	require.True(t, ok, "attribute %q value should have locale %q", attrId, locale)
	require.Equal(t, expected, actual, "attribute %q value mismatch", attrId)
}

// requireAttributeStringValue asserts that the attribute with the given ID has
// a plain String value matching the expected string.
func requireAttributeStringValue(t *testing.T, attrs map[string]clientmodels.Attribute, attrId, expected string) {
	t.Helper()
	attr, ok := attrs[attrId]
	require.True(t, ok, "attribute %q should exist", attrId)
	require.NotNil(t, attr.Value, "attribute %q should have a value", attrId)
	require.NotNil(t, attr.Value.String, "attribute %q value should be a String", attrId)
	require.Equal(t, expected, *attr.Value.String, "attribute %q value mismatch", attrId)
}

// startOpenID4VPDisclosureSession starts an OpenID4VP disclosure session in the
// client using the given verifier request URI.
func startOpenID4VPDisclosureSession(t *testing.T, c *client.Client, requestUri string) {
	t.Helper()

	sessionReq, err := json.Marshal(client.SessionRequestData{
		Qr:       irma.Qr{URL: requestUri},
		Protocol: clientmodels.Protocol_OpenID4VP,
	})
	require.NoError(t, err)
	c.NewSession(string(sessionReq))
}
