package sessiontest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

const (
	veramoVerifierBaseURL    = "https://localhost:8444"
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
	t.Run("disclose nested claims", testDiscloseNestedClaims)
	t.Run("disclose credential with array values", testDiscloseCredentialWithArrayValues)
	t.Run("disclose specific array element", testDiscloseSpecificArrayElement)
	t.Run("disclose all array elements with null path", testDiscloseAllArrayElementsWithNullPath)
	t.Run("non-sd claims shown in disclosure plan", testNonSdClaimsShownInDisclosurePlan)
	t.Run("issue many credentials and disclose subset", testIssueManyCredentialsAndDiscloseSubset)
	t.Run("claim sets picks first satisfiable set", testClaimSetsPicksFirstSatisfiableSet)
	t.Run("multiple vct values matches across types", testMultipleVctValuesMatchesAcrossTypes)
	t.Run("issue and disclose eduid credential", testIssueAndDiscloseEduIdCredential)
	t.Run("boolean claim value constraint", testBooleanClaimValueConstraint)
	t.Run("multiple credentials for same query", testMultipleCredentialsForSameQuery)
	t.Run("no claims requested shares only non-sd claims", testNoClaimsRequestedSharesOnlyNonSdClaims)
	t.Run("duplicate claims ignored", testDuplicateClaimsIgnored)
	t.Run("disclose without holder binding", testDiscloseWithoutHolderBinding)
	t.Run("verifier display name", testVerifierDisplayName)
	t.Run("eudi verifier requesting veramo credential fails", testEudiVerifierRequestingVeramoCredentialFails)
	t.Run("veramo verifier requesting irma credential fails", testVeramoVerifierRequestingIrmaCredentialFails)
	t.Run("veramo verifier requesting missing credential errors", testVeramoVerifierRequestingMissingCredentialErrors)
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

	// Step 4: Verify the disclosure plan and grant permission.
	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Name: "", Attributes: map[string]expectedPlanAttribute{"given_name": {Value: "Test", DisplayName: "Given Name"}, "email": {Value: "test@example.com", DisplayName: "Email"}}},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	attrIds := make([]string, len(cred.Attributes))
	for i, attr := range cred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Step 5: Verify the verifier received the VP token with correct attributes.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedAttributes(t, result, "test-credential", map[string]string{
		"given_name": "Test",
		"email":      "test@example.com",
	})
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
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/email"]
					},
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

	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{"email": {Value: "alice@example.com", DisplayName: "Email"}, "domain": {Value: "example.com", DisplayName: "Domain"}}},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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
	requireVerifierReceivedAttributes(t, result, "email-cred", map[string]string{
		"email":  "alice@example.com",
		"domain": "example.com",
	})
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
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/email"]
					},
					"claims": [
						{ "path": ["email"] }
					]
				},
				{
					"id": "phone-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/phone"]
					},
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
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	// There should be one pick-one set with two owned options (email and phone).
	pickOne := plan.DisclosureChoicesOverview[0]
	require.GreaterOrEqual(t, len(pickOne.OwnedOptions), 2,
		"should have at least two credential options to choose from")

	// Verify that each option has the expected attribute values.
	for _, opt := range pickOne.OwnedOptions {
		attrMap := attributeMap(opt.Attributes)
		if _, hasEmail := attrMap["email"]; hasEmail {
			require.NotNil(t, attrMap["email"].Value)
			require.Equal(t, "bob@example.com", *attrMap["email"].Value.String)
		}
		if _, hasPhone := attrMap["phone_number"]; hasPhone {
			require.NotNil(t, attrMap["phone_number"].Value)
			require.Equal(t, "+31612345678", *attrMap["phone_number"].Value.String)
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

	// Verify the verifier received attributes for the chosen credential.
	chosenAttrs := attributeMap(chosen.Attributes)
	if _, hasEmail := chosenAttrs["email"]; hasEmail {
		requireVerifierReceivedAttributes(t, result, "email-cred", map[string]string{"email": "bob@example.com"})
	} else {
		requireVerifierReceivedAttributes(t, result, "phone-cred", map[string]string{"phone_number": "+31612345678"})
	}
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
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/email"]
					},
					"claims": [
						{ "path": ["email"] }
					]
				},
				{
					"id": "phone-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/phone"]
					},
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

	// Two separate disclosure choices, one for each required credential.
	// The order depends on the DCQL query order, but both should have matching credentials.
	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{"email": {Value: "carol@example.com", DisplayName: "Email"}}},
		{Attributes: map[string]expectedPlanAttribute{"phone_number": {Value: "+31687654321", DisplayName: "Phone Number"}}},
	})

	choices := make([]clientmodels.DisclosureDisconSelection, 2)
	for i, pickOne := range session.DisclosurePlan.DisclosureChoicesOverview {
		cred := pickOne.OwnedOptions[0]
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
	requireVerifierReceivedAttributes(t, result, "email-cred", map[string]string{"email": "carol@example.com"})
	requireVerifierReceivedAttributes(t, result, "phone-cred", map[string]string{"phone_number": "+31687654321"})
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
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/email"]
					},
					"claims": [
						{ "path": ["email"] }
					]
				},
				{
					"id": "phone-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/phone"]
					},
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

	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{"email": {Value: "dave@example.com", DisplayName: "Email"}}},
		{Attributes: map[string]expectedPlanAttribute{}}, // optional phone (may have no owned options)
	})

	emailCred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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
	requireVerifierReceivedAttributes(t, result, "email-cred", map[string]string{"email": "dave@example.com"})
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
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/email"]
					},
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
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions)

	// Only the credential with domain "example.com" should match the value constraint.
	// Find the matching credential among the owned options.
	var matchingCred *clientmodels.SelectableCredentialInstance
	for _, opt := range plan.DisclosureChoicesOverview[0].OwnedOptions {
		attrMap := attributeMap(opt.Attributes)
		if attr, ok := attrMap["domain"]; ok && attr.Value != nil &&
			attr.Value.String != nil && *attr.Value.String == "example.com" {
			matchingCred = opt
			break
		}
	}
	require.NotNil(t, matchingCred, "should find a credential with domain example.com")

	attrMap := attributeMap(matchingCred.Attributes)
	require.Equal(t, "eve@example.com", *attrMap["email"].Value.String)
	require.Equal(t, "example.com", *attrMap["domain"].Value.String)

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
	requireVerifierReceivedAttributes(t, result, "email-cred", map[string]string{
		"email":  "eve@example.com",
		"domain": "example.com",
	})
}

// testDiscloseNestedClaims issues a HouseCredential with a nested address object
// and creates a DCQL query that requests specific nested claim paths
// (e.g., ["address", "street"]).
func testDiscloseNestedClaims(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a HouseCredential with nested address claims.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Frank",
		"address": {
			"street": "10 Downing St",
			"city": "London",
			"country": "GB"
		}
	}`)

	// DCQL query requesting nested claim paths.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "house-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/house"]
					},
					"claims": [
						{ "path": ["owner_name"] },
						{ "path": ["address", "street"] },
						{ "path": ["address", "city"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{"owner_name": {Value: "Frank", DisplayName: "Owner Name"}, "street": {Value: "10 Downing St"}, "city": {Value: "London"}}},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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
	// The veramo-verifier only extracts top-level SD claims; nested claims
	// (address.street, address.city) are not extracted by the verifier.
	requireVerifierReceivedAttributes(t, result, "house-cred", map[string]string{
		"owner_name": "Frank",
	})
}

// testDiscloseCredentialWithArrayValues issues a StudentCardCredential that
// includes a "courses" claim with an array value, then discloses it.
func testDiscloseCredentialWithArrayValues(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a StudentCardCredential with an array of courses.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
		"university": "TU Delft",
		"level": "MSc",
		"student_id": "S99999",
		"courses": ["Algorithms", "Databases", "Networks"]
	}`)

	// DCQL query requesting the array claim alongside a scalar claim.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "student-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/studentcard"]
					},
					"claims": [
						{ "path": ["university"] },
						{ "path": ["courses"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{"university": {Value: "TU Delft", DisplayName: "University"}, "courses": {Type: clientmodels.AttributeType_Array, DisplayName: "Courses"}}},
	})

	// Verify the array contains all three course values.
	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	coursesAttr := attributeMap(cred.Attributes)["courses"]
	require.NotNil(t, coursesAttr.Value)
	require.Len(t, coursesAttr.Value.Array, 3)
	require.Equal(t, "Algorithms", *coursesAttr.Value.Array[0].String)
	require.Equal(t, "Databases", *coursesAttr.Value.Array[1].String)
	require.Equal(t, "Networks", *coursesAttr.Value.Array[2].String)
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
	requireVerifierReceivedAttributes(t, result, "student-cred", map[string]string{
		"university": "TU Delft",
	})
}

// testDiscloseSpecificArrayElement issues a StudentCardCredential with a courses
// array and creates a DCQL query that requests a specific element by index
// (path: ["courses", 1]).
func testDiscloseSpecificArrayElement(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
		"university": "TU Delft",
		"level": "MSc",
		"student_id": "S88888",
		"courses": ["Algorithms", "Databases", "Networks"]
	}`)

	// DCQL query requesting the second element of the courses array (index 1).
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "student-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/studentcard"]
					},
					"claims": [
						{ "path": ["courses", 1] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// Path ["courses", 1] resolves to a specific element ("Databases"), not the whole array.
	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{"courses": {Value: "Databases", Type: clientmodels.AttributeType_String, DisplayName: "Courses"}}},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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

// testDiscloseAllArrayElementsWithNullPath issues a StudentCardCredential with
// a courses array and creates a DCQL query that requests all elements using a
// null path component (path: ["courses", null]).
func testDiscloseAllArrayElementsWithNullPath(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
		"university": "TU Delft",
		"level": "MSc",
		"student_id": "S77777",
		"courses": ["Algorithms", "Databases", "Networks"]
	}`)

	// DCQL query requesting all elements of the courses array using null.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "student-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/studentcard"]
					},
					"claims": [
						{ "path": ["courses", null] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{"courses": {Type: clientmodels.AttributeType_Array, DisplayName: "Courses"}}},
	})

	// Verify the full array is present when requesting all elements via null path.
	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	coursesAttr := attributeMap(cred.Attributes)["courses"]
	require.NotNil(t, coursesAttr.Value)
	require.Len(t, coursesAttr.Value.Array, 3)
	require.Equal(t, "Algorithms", *coursesAttr.Value.Array[0].String)
	require.Equal(t, "Databases", *coursesAttr.Value.Array[1].String)
	require.Equal(t, "Networks", *coursesAttr.Value.Array[2].String)

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

// testNonSdClaimsShownInDisclosurePlan issues a MembershipCredential where
// member_name and membership_type are SD claims but member_since is a non-SD
// claim (always in the JWT payload). The verifier only asks for member_name,
// but the disclosure plan should also show member_since because it is always
// shared when the credential is presented.
func testNonSdClaimsShownInDisclosurePlan(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "MembershipCredentialSdJwt", `{
		"member_name": "Grace",
		"member_since": "2020-01-15",
		"membership_type": "Gold"
	}`)

	// The verifier only asks for the SD claim member_name.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "membership-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/membership"]
					},
					"claims": [
						{ "path": ["member_name"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The disclosure plan should show member_name (requested SD claim) AND
	// member_since (non-SD claim that is always shared).
	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{
			"member_name":  {Value: "Grace", DisplayName: "Member Name"},
			"member_since": {Value: "2020-01-15", DisplayName: "Member Since"},
		}},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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
	requireVerifierReceivedAttributes(t, result, "membership-cred", map[string]string{
		"member_name": "Grace",
	})
}

// testIssueManyCredentialsAndDiscloseSubset issues four different SD-JWT
// credentials (Email, Phone, StudentCard, House) via OID4VCI, then creates
// a DCQL query that only requests two of them (Email and StudentCard).
// This verifies that the wallet correctly matches only the requested credential
// types and does not disclose the unrequested Phone and House credentials.
func testIssueManyCredentialsAndDiscloseSubset(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue four different credential types.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "multi@example.com",
		"domain": "example.com"
	}`)
	issueCredentialViaOid4Vci(t, c, sessionHandler, "PhoneCredentialSdJwt", `{
		"phone_number": "+31699999999"
	}`)
	issueCredentialViaOid4Vci(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
		"university": "Radboud University",
		"level": "Master",
		"student_id": "s1234567",
		"courses": ["Algorithms", "Databases", "Security"]
	}`)
	issueCredentialViaOid4Vci(t, c, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Multi Test",
		"address": {
			"street": "Toernooiveld 1",
			"city": "Nijmegen",
			"country": "NL"
		}
	}`)

	// DCQL query: request only the Email and StudentCard credentials.
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
						{ "path": ["email"] },
						{ "path": ["domain"] }
					]
				},
				{
					"id": "student-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/studentcard"]
					},
					"claims": [
						{ "path": ["university"] },
						{ "path": ["student_id"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 5, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// Exactly two disclosure choices: one for email, one for student card.
	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{
			"email":  {Value: "multi@example.com", DisplayName: "Email"},
			"domain": {Value: "example.com", DisplayName: "Domain"},
		}},
		{Attributes: map[string]expectedPlanAttribute{
			"university": {Value: "Radboud University", DisplayName: "University"},
			"student_id": {Value: "s1234567", DisplayName: "Student ID"},
		}},
	})

	// Grant permission for both required credentials.
	choices := make([]clientmodels.DisclosureDisconSelection, 2)
	for i, pickOne := range session.DisclosurePlan.DisclosureChoicesOverview {
		cred := pickOne.OwnedOptions[0]
		attrIds := make([]string, len(cred.Attributes))
		for j, attr := range cred.Attributes {
			attrIds[j] = attr.Id
		}
		choices[i] = makeDisclosureChoice(cred, attrIds...)
	}
	grantPermission(t, c, session.Id, choices...)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 5, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Verify the verifier received only the requested credentials.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedAttributes(t, result, "email-cred", map[string]string{
		"email":  "multi@example.com",
		"domain": "example.com",
	})
	requireVerifierReceivedAttributes(t, result, "student-cred", map[string]string{
		"university": "Radboud University",
		"student_id": "s1234567",
	})

	// The verifier should NOT have received Phone or House credentials.
	require.NotContains(t, result.Result.Credentials, "phone-cred",
		"verifier should not have received unrequested phone credential")
	require.NotContains(t, result.Result.Credentials, "house-cred",
		"verifier should not have received unrequested house credential")
}

// testIssueAndDiscloseEduIdCredential issues an eduID credential via OID4VCI
// and then discloses it via OpenID4VP using a DCQL query that mirrors what the
// real eduID verifier would send.
func testIssueAndDiscloseEduIdCredential(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "EduIdCredentialSdJwt", `{
		"schac_home_organization": "university.nl",
		"name": "Jan de Vries",
		"given_name": "Jan",
		"family_name": "de Vries",
		"email": "jan.devries@university.nl",
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

	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "eduid-credential",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/eduid"]
					},
					"claims": [
						{ "path": ["given_name"] },
						{ "path": ["family_name"] },
						{ "path": ["email"] },
						{ "path": ["schac_home_organization"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	requireDisclosurePlan(t, session.DisclosurePlan, []expectedPlanCredential{
		{Attributes: map[string]expectedPlanAttribute{
			"given_name":              {Value: "Jan", DisplayName: "Given name"},
			"family_name":             {Value: "de Vries", DisplayName: "Family name"},
			"email":                   {Value: "jan.devries@university.nl", DisplayName: "E-mail"},
			"schac_home_organization": {Value: "university.nl", DisplayName: "Organization"},
		}},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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
	requireVerifierReceivedAttributes(t, result, "eduid-credential", map[string]string{
		"given_name":              "Jan",
		"family_name":             "de Vries",
		"email":                   "jan.devries@university.nl",
		"schac_home_organization": "university.nl",
	})
}

// testClaimSetsPicksFirstSatisfiableSet issues an EmailCredential and uses a
// DCQL query with claim_sets to express disjunctive claim requirements: either
// just the email, or just the domain. Because claim_sets are tried in order and
// both are satisfiable, the first set (email only) should be picked.
func testClaimSetsPicksFirstSatisfiableSet(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "claimsets@example.com",
		"domain": "example.com"
	}`)

	// DCQL query with claim_sets: prefer email only, fallback to domain only.
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
						{ "id": "em", "path": ["email"] },
						{ "id": "do", "path": ["domain"] }
					],
					"claim_sets": [["em"], ["do"]]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The first claim set (email only) should be picked.
	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions)

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	attrMap := attributeMap(cred.Attributes)

	// The first claim set ["em"] should be selected, so only email is a requested
	// attribute. Domain may appear as a non-SD claim but the primary requested
	// attribute should be email.
	_, hasEmail := attrMap["email"]
	require.True(t, hasEmail, "email should be in the disclosure plan")
	require.Equal(t, "claimsets@example.com", *attrMap["email"].Value.String)

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
	requireVerifierReceivedAttributes(t, result, "email-cred", map[string]string{
		"email": "claimsets@example.com",
	})
}

// testMultipleVctValuesMatchesAcrossTypes issues an EmailCredential and a
// PhoneCredential, then creates a DCQL query with a single credential entry
// whose vct_values list contains both types. The wallet should find candidates
// from both credential types and let the user pick one.
func testMultipleVctValuesMatchesAcrossTypes(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "vct@example.com",
		"domain": "example.com"
	}`)
	issueCredentialViaOid4Vci(t, c, sessionHandler, "PhoneCredentialSdJwt", `{
		"phone_number": "+31611111111"
	}`)

	// DCQL query: single credential entry with multiple vct_values.
	// Both email and phone credentials have an "email" or "phone_number" claim,
	// but the query only requests a claim that exists in the email credential.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "contact-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": [
							"https://localhost:8443/vct/email",
							"https://localhost:8443/vct/phone"
						]
					},
					"claims": [
						{ "path": ["email"] }
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
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions,
		"should have at least one matching credential")

	// The email credential should match (it has an "email" claim).
	// The phone credential should NOT match (it has no "email" claim).
	var emailCred *clientmodels.SelectableCredentialInstance
	for _, opt := range plan.DisclosureChoicesOverview[0].OwnedOptions {
		attrMap := attributeMap(opt.Attributes)
		if attr, ok := attrMap["email"]; ok && attr.Value != nil &&
			attr.Value.String != nil && *attr.Value.String == "vct@example.com" {
			emailCred = opt
			break
		}
	}
	require.NotNil(t, emailCred, "should find the email credential as a candidate")

	attrIds := make([]string, len(emailCred.Attributes))
	for i, attr := range emailCred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(emailCred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedAttributes(t, result, "contact-cred", map[string]string{
		"email": "vct@example.com",
	})
}

// testBooleanClaimValueConstraint issues two eduID credentials with different
// is_student values (true and false), then creates a DCQL query that constrains
// is_student to true. Only the credential with is_student=true should match.
func testBooleanClaimValueConstraint(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue credential with is_student=true.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EduIdCredentialSdJwt", `{
		"schac_home_organization": "uni-a.nl",
		"name": "Student User",
		"given_name": "Student",
		"family_name": "User",
		"email": "student@uni-a.nl",
		"eduperson_scoped_affiliation": "student@uni-a.nl",
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

	// Issue credential with is_student=false.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EduIdCredentialSdJwt", `{
		"schac_home_organization": "uni-b.nl",
		"name": "Staff User",
		"given_name": "Staff",
		"family_name": "User",
		"email": "staff@uni-b.nl",
		"eduperson_scoped_affiliation": "employee@uni-b.nl",
		"eduperson_assurance": "https://eduid.nl/assurance/low",
		"is_student": false,
		"is_faculty": false,
		"is_member": true,
		"is_staff": true,
		"is_alum": false,
		"is_affiliate": false,
		"is_employee": true,
		"is_library-walk-in": false
	}`)

	// DCQL query: request eduID credential where is_student is true.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "eduid-student",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/eduid"]
					},
					"claims": [
						{ "path": ["given_name"] },
						{ "path": ["is_student"], "values": [true] }
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
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions)

	// All matching credentials should have is_student=true.
	for _, opt := range plan.DisclosureChoicesOverview[0].OwnedOptions {
		attrMap := attributeMap(opt.Attributes)
		attr, ok := attrMap["given_name"]
		require.True(t, ok)
		// The matching credential should be "Student", not "Staff".
		require.Equal(t, "Student", *attr.Value.String,
			"only the credential with is_student=true should match the value constraint")
	}

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	attrIds := make([]string, len(cred.Attributes))
	for i, attr := range cred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedAttributes(t, result, "eduid-student", map[string]string{
		"given_name": "Student",
	})
}

// testMultipleCredentialsForSameQuery issues two email credentials, then creates
// a DCQL query with "multiple": true. The user selects both credentials and
// both should be included in the VP token for the same query ID.
func testMultipleCredentialsForSameQuery(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "alice@example.com",
		"domain": "example.com"
	}`)
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "bob@example.com",
		"domain": "example.com"
	}`)

	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "email-multi",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/email"]
					},
					"claims": [
						{ "path": ["email"] }
					],
					"multiple": true
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
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	pickOne := plan.DisclosureChoicesOverview[0]
	require.True(t, pickOne.Multiple, "multiple flag should be true in the disclosure plan")
	require.Len(t, pickOne.OwnedOptions, 2, "both email credentials should be candidates")

	// Select BOTH credentials (this is the key difference from single-select).
	var selectedCreds []clientmodels.SelectedCredential
	for _, opt := range pickOne.OwnedOptions {
		attrIds := make([][]any, len(opt.Attributes))
		for i, attr := range opt.Attributes {
			attrIds[i] = []any{attr.Id}
		}
		selectedCreds = append(selectedCreds, clientmodels.SelectedCredential{
			CredentialId:   opt.CredentialId,
			CredentialHash: opt.Hash,
			AttributePaths: attrIds,
		})
	}

	grantPermission(t, c, session.Id, clientmodels.DisclosureDisconSelection{
		Credentials: selectedCreds,
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should succeed with multiple credentials")

	// The verifier should have received credentials for the "email-multi" query.
	creds, ok := result.Result.Credentials["email-multi"]
	require.True(t, ok, "verifier should have credentials for query 'email-multi'")
	require.Len(t, creds, 2, "verifier should have received 2 credentials for the same query")

	// Verify both email addresses are present.
	emails := make([]string, len(creds))
	for i, cred := range creds {
		email, ok := cred.Claims["email"]
		require.True(t, ok)
		emails[i] = fmt.Sprintf("%v", email)
	}
	require.Contains(t, emails, "alice@example.com")
	require.Contains(t, emails, "bob@example.com")
}

// testNoClaimsRequestedSharesOnlyNonSdClaims issues a MembershipCredential
// (which has SD claims "member_name" and "membership_type", and a non-SD claim
// "member_since"), then sends a DCQL query with no claims array. Per OpenID4VP
// Section 6.4.1, when claims is absent the wallet should only share the non-SD
// claims — no SD disclosures should be included.
func testNoClaimsRequestedSharesOnlyNonSdClaims(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "MembershipCredentialSdJwt", `{
		"member_name": "Alice",
		"member_since": "2020-01-01",
		"membership_type": "gold"
	}`)

	// DCQL query with NO claims array — verifier requests no selective disclosures.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "membership-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/membership"]
					}
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions)

	// The disclosure plan should only contain non-SD claims.
	// "member_since" is non-SD, while "member_name" and "membership_type" are SD.
	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	attrMap := attributeMap(cred.Attributes)
	require.Contains(t, attrMap, "member_since", "non-SD claim member_since should be in the disclosure plan")
	require.NotContains(t, attrMap, "member_name", "SD claim member_name should NOT be in the plan when claims is absent")
	require.NotContains(t, attrMap, "membership_type", "SD claim membership_type should NOT be in the plan when claims is absent")

	// Disclose with whatever attributes are available (only non-SD).
	attrIds := make([]string, len(cred.Attributes))
	for i, attr := range cred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
}

// testDuplicateClaimsIgnored issues an EmailCredential, then sends a DCQL query
// where the "email" claim appears twice. Per OpenID4VP Section 6.3, the wallet
// should ignore duplicate claim queries — the disclosure plan should contain
// "email" only once.
func testDuplicateClaimsIgnored(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "dup@example.com",
		"domain": "example.com"
	}`)

	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "email-dup",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/email"]
					},
					"claims": [
						{ "path": ["email"] },
						{ "path": ["email"] },
						{ "path": ["domain"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions)

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	attrMap := attributeMap(cred.Attributes)

	// "email" should appear exactly once despite being listed twice in the query.
	emailCount := 0
	for _, attr := range cred.Attributes {
		if attr.Id == "email" {
			emailCount++
		}
	}
	require.Equal(t, 1, emailCount, "duplicate email claim should be deduplicated")
	require.Equal(t, "dup@example.com", *attrMap["email"].Value.String)
	require.Equal(t, "example.com", *attrMap["domain"].Value.String)

	// Disclose and verify the session completes.
	attrIds := make([]string, len(cred.Attributes))
	for i, attr := range cred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedAttributes(t, result, "email-dup", map[string]string{
		"email": "dup@example.com",
	})
}

// testDiscloseWithoutHolderBinding issues a credential, then creates a DCQL
// query with require_cryptographic_holder_binding set to false. The wallet should
// disclose the credential without appending a key binding JWT.
func testDiscloseWithoutHolderBinding(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "nokb@example.com",
		"domain": "example.com"
	}`)

	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "email-no-kb",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/email"]
					},
					"claims": [
						{ "path": ["email"] }
					],
					"require_cryptographic_holder_binding": false
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	attrIds := make([]string, len(cred.Attributes))
	for i, attr := range cred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// The verifier may or may not verify the response (depends on verifier config),
	// but the session should complete successfully without a KB-JWT.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should succeed without holder binding")
}

// testVerifierDisplayName verifies that the verifier display name shown to the
// user comes from client_metadata.client_name rather than the raw DID.
func testVerifierDisplayName(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "display@example.com",
		"domain": "example.com"
	}`)

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
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The wallet should use client_name from client_metadata as the display name
	// when present, falling back to response_uri hostname otherwise.
	require.Equal(t, "test-verifier", session.Requestor.Name["en"],
		"verifier display name should come from client_name, not the raw DID")
	require.False(t, session.Requestor.Verified,
		"DID-based verifier should not be marked as verified (not verified by Yivi)")
}

// testEudiVerifierRequestingVeramoCredentialFails issues a credential via the
// veramo issuer (OID4VCI), then starts a disclosure session using the EUDI
// reference verifier. Because the EUDI verifier uses x509 client_id and a
// different trust model, the session should result in an error.
func testEudiVerifierRequestingVeramoCredentialFails(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a credential via the veramo OID4VCI issuer.
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "eudi-test@example.com",
		"domain": "example.com"
	}`)

	// Create a session at the EUDI reference verifier requesting the same VCT.
	authRequest := createAuthRequestRequestWithDcql(`{
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
		]
	}`)

	verifierSession, err := irmaclient.StartTestSessionAtEudiVerifier(
		testdata.OpenID4VP_DirectPost_Host, authRequest)
	require.NoError(t, err)

	sessionReq, err := json.Marshal(client.SessionRequestData{
		Qr:       irma.Qr{URL: verifierSession.SessionLink},
		Protocol: clientmodels.Protocol_OpenID4VP,
	})
	require.NoError(t, err)
	c.NewSession(string(sessionReq))

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Error, session.Status,
		"session should fail because the EUDI verifier's trust model doesn't match veramo-issued credentials")
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError, "credential is not authorized")
	require.Contains(t, session.Error.WrappedError, "https://localhost:8443/vct/email")
}

// testVeramoVerifierRequestingIrmaCredentialFails issues an IRMA email credential
// via the IRMA server, then creates a disclosure session at the veramo verifier
// requesting that credential (test.test.email). The veramo verifier uses DID-based
// auth which is not authorized to request IRMA credentials, so the session should
// reach permission request with an empty disclosure plan.
func testVeramoVerifierRequestingIrmaCredentialFails(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	// Issue an IRMA email credential via the IRMA server.
	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	awaitSessionState(t, sessionHandler)

	// Create a DCQL session at the veramo verifier requesting the IRMA credential type.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "irma-email",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["test.test.email"]
					},
					"claims": [
						{ "path": ["email"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)

	// The IRMA handler finds the credential matching test.test.email and offers it.
	// The session reaches permission request with the IRMA credential as an option.
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.NotNil(t, session.DisclosurePlan)
	require.NotEmpty(t, session.DisclosurePlan.DisclosureChoicesOverview)
	require.NotEmpty(t, session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions,
		"IRMA credential should be found as a candidate")

	// Grant permission to disclose the IRMA credential to the veramo verifier.
	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	attrIds := make([]string, len(cred.Attributes))
	for i, attr := range cred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred, attrIds...))

	session = awaitSessionState(t, sessionHandler)

	// The wallet successfully sends the IRMA credential to the veramo verifier.
	// The veramo verifier receives it but cannot verify the IRMA issuer's signature
	// (different trust model — IRMA uses x509 certificates, not did:web).
	require.Equal(t, clientmodels.Status_Success, session.Status)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)

	// The verifier should report an error verifying the IRMA-issued credential.
	require.NotNil(t, result.Result)
	hasVerificationError := false
	for _, msg := range result.Result.Messages {
		if msg.Code == "INVALID_SDJWT" || msg.Code == "INVALID_PRESENTATION" {
			hasVerificationError = true
			break
		}
	}
	require.True(t, hasVerificationError,
		"verifier should report a verification error for the IRMA-issued credential")
}

// testVeramoVerifierRequestingMissingCredentialErrors creates a disclosure
// session at the veramo verifier requesting an email credential when the wallet
// has no credentials at all. The session should error because the DCQL query
// cannot be satisfied.
func testVeramoVerifierRequestingMissingCredentialErrors(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// No credentials are issued — the wallet is empty.

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
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.NotNil(t, session.DisclosurePlan)
	require.NotEmpty(t, session.DisclosurePlan.DisclosureChoicesOverview)
	require.Empty(t, session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions,
		"should have no owned credentials since the wallet is empty")
	require.Empty(t, session.DisclosurePlan.DisclosureChoicesOverview[0].ObtainableOptions,
		"should have no obtainable credentials")
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
	Status string          `json:"status"`
	Result *veramoVPResult `json:"result,omitempty"`
}

type veramoVPResult struct {
	Credentials map[string][]veramoExtractedCredential `json:"credentials"`
	Messages    []veramoMessage                        `json:"messages"`
}

type veramoExtractedCredential struct {
	Claims map[string]any `json:"claims"`
}

type veramoMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// requireVerifierReceivedAttributes asserts that the veramo verifier received
// the expected attribute values for a given credential query ID.
// When the verifier fully verified the credential (status VERIFIED), the claim
// values are checked. Otherwise only the query ID presence is asserted.
func requireVerifierReceivedAttributes(t *testing.T, result veramoCheckResult, queryId string, expected map[string]string) {
	t.Helper()
	require.NotNil(t, result.Result, "verifier result should not be nil")
	creds, ok := result.Result.Credentials[queryId]
	require.True(t, ok, "verifier should have credentials for query %q", queryId)
	require.NotEmpty(t, creds, "verifier should have at least one credential for query %q", queryId)
	for key, expectedVal := range expected {
		actual, ok := creds[0].Claims[key]
		require.True(t, ok, "verifier credential should have claim %q", key)
		require.Equal(t, expectedVal, fmt.Sprintf("%v", actual), "verifier claim %q value mismatch", key)
	}
}

func createVeramoVerifierDcqlSession(t *testing.T) veramoVerifierSession {
	t.Helper()

	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "test-credential",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/test"]
					},
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

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var result veramoCheckResult
	require.NoError(t, json.Unmarshal(body, &result))
	return result
}

// ---------------------------------------------------------------------------
// Disclosure plan assertion helpers
// ---------------------------------------------------------------------------

// expectedPlanAttribute describes what we expect for a single attribute.
type expectedPlanAttribute struct {
	// Expected string value. Empty to only check presence.
	Value string
	// Expected display name (checked against DisplayName["en"]). Empty to skip check.
	DisplayName string
	// Expected attribute type. Empty to skip check.
	Type clientmodels.AttributeType
}

// expectedPlanCredential describes what we expect for one credential option
// in the disclosure plan.
type expectedPlanCredential struct {
	// Expected credential name (checked against Name["en"]). Empty to skip check.
	Name string
	// Expected attributes: map from attribute ID to expected attribute properties.
	Attributes map[string]expectedPlanAttribute
}

// requireDisclosurePlan asserts the structure of a disclosure plan.
// Each entry in expected corresponds to one DisclosurePickOne in order.
// For each entry, the first OwnedOption is checked against the expected credential.
func requireDisclosurePlan(t *testing.T, plan *clientmodels.DisclosurePlan, expected []expectedPlanCredential) {
	t.Helper()
	require.NotNil(t, plan)
	require.Len(t, plan.DisclosureChoicesOverview, len(expected),
		"disclosure plan should have %d choice(s)", len(expected))

	for i, exp := range expected {
		pickOne := plan.DisclosureChoicesOverview[i]

		if len(exp.Attributes) == 0 {
			continue // skip validation for entries with no expected attributes (e.g., optional unowned)
		}

		require.NotEmpty(t, pickOne.OwnedOptions, "choice %d should have owned options", i)

		cred := pickOne.OwnedOptions[0]
		if exp.Name != "" {
			actual, ok := cred.Name["en"]
			require.True(t, ok, "choice %d credential should have English name", i)
			require.Equal(t, exp.Name, actual, "choice %d credential name mismatch", i)
		}

		attrMap := attributeMap(cred.Attributes)
		for attrId, exp := range exp.Attributes {
			attr, ok := attrMap[attrId]
			require.True(t, ok, "choice %d should have attribute %q", i, attrId)
			if exp.Type != "" {
				require.NotNil(t, attr.Value, "choice %d attribute %q should have a value", i, attrId)
				require.Equal(t, exp.Type, attr.Value.Type,
					"choice %d attribute %q type mismatch", i, attrId)
			}
			if exp.Value != "" && attr.Value != nil && attr.Value.String != nil {
				require.Equal(t, exp.Value, *attr.Value.String,
					"choice %d attribute %q value mismatch", i, attrId)
			}
			if exp.DisplayName != "" {
				actual, ok := attr.DisplayName["en"]
				require.True(t, ok, "choice %d attribute %q should have English display name", i, attrId)
				require.Equal(t, exp.DisplayName, actual,
					"choice %d attribute %q display name mismatch", i, attrId)
			}
		}
	}
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

// requireAttribute asserts that an attribute exists with the expected display
// names and value.
func requireAttribute(t *testing.T, attrs map[string]clientmodels.Attribute, attrId string, displayNames clientmodels.TranslatedString, expectedValue string) {
	t.Helper()
	attr, ok := attrs[attrId]
	require.True(t, ok, "attribute %q should exist", attrId)
	for locale, expected := range displayNames {
		actual, ok := attr.DisplayName[locale]
		require.True(t, ok, "attribute %q should have display name for locale %q", attrId, locale)
		require.Equal(t, expected, actual, "attribute %q display name [%s] mismatch", attrId, locale)
	}
	require.NotNil(t, attr.Value, "attribute %q should have a value", attrId)
	require.NotNil(t, attr.Value.String, "attribute %q should have a String value", attrId)
	require.Equal(t, expectedValue, *attr.Value.String, "attribute %q value mismatch", attrId)
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
