package sessiontest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
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

	batch2IssuerURL   = "https://localhost:8443/batch2-issuer"
	batch2AdminToken  = "test-admin-token"
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
	t.Run("duplicate nested claims ignored", testDuplicateNestedClaimsIgnored)
	t.Run("requireDisclosurePlan only checks first option", testRequireDisclosurePlanOnlyChecksFirstOption)
	t.Run("disclose without holder binding", testDiscloseWithoutHolderBinding)
	t.Run("verifier display name", testVerifierDisplayName)
	t.Run("batch of one credential remains usable after disclosure", testBatchOfOneCredentialRemainsUsableAfterDisclosure)
	t.Run("batch of two credential is exhausted after two disclosures", testBatchOfTwoCredentialExhaustedAfterTwoDisclosures)
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
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"given_name"}, Value: strVal("Test"), DisplayName: &clientmodels.TranslatedString{"en": "Given Name"}},
					{Path: []any{"email"}, Value: strVal("test@example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Email"}},
				}},
			}},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Step 5: Verify the verifier received the VP token with correct attributes.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "test-credential",
		claim([]any{"given_name"}, "Test"),
		claim([]any{"email"}, "test@example.com"),
	)
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

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"email"}, Value: strVal("alice@example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Email"}},
					{Path: []any{"domain"}, Value: strVal("example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Domain"}},
				}},
			}},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "email-cred",
		claim([]any{"email"}, "alice@example.com"),
		claim([]any{"domain"}, "example.com"),
	)
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
		if _, hasEmail := attrMap[pk("email")]; hasEmail {
			requireAttr(t, attrMap, []any{"email"}, "bob@example.com")
		}
		if _, hasPhone := attrMap[pk("phone_number")]; hasPhone {
			requireAttr(t, attrMap, []any{"phone_number"}, "+31612345678")
		}
	}

	// Pick the first option (whichever it is) and disclose.
	chosen := pickOne.OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(chosen))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")

	// Verify the verifier received attributes for the chosen credential.
	chosenAttrs := attributeMap(chosen.Attributes)
	if _, hasEmail := chosenAttrs[pk("email")]; hasEmail {
		requireVerifierReceivedClaims(t, result, "email-cred", claim([]any{"email"}, "bob@example.com"))
	} else {
		requireVerifierReceivedClaims(t, result, "phone-cred", claim([]any{"phone_number"}, "+31612345678"))
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
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"email"}, Value: strVal("carol@example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Email"}},
				}},
			}},
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"phone_number"}, Value: strVal("+31687654321"), DisplayName: &clientmodels.TranslatedString{"en": "Phone Number"}},
				}},
			}},
		},
	})

	choices := make([]clientmodels.DisclosureDisconSelection, 2)
	for i, pickOne := range session.DisclosurePlan.DisclosureChoicesOverview {
		cred := pickOne.OwnedOptions[0]
		choices[i] = makeDisclosureChoice(cred)
	}
	grantPermission(t, c, session.Id, choices...)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "email-cred", claim([]any{"email"}, "carol@example.com"))
	requireVerifierReceivedClaims(t, result, "phone-cred", claim([]any{"phone_number"}, "+31687654321"))
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

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"email"}, Value: strVal("dave@example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Email"}},
				}},
			}},
			{Optional: true}, // optional phone (may have no owned options)
		},
	})

	emailCred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]

	// Grant permission with the required email credential; skip the optional phone with an empty selection.
	grantPermission(t, c, session.Id,
		makeDisclosureChoice(emailCred),
		clientmodels.DisclosureDisconSelection{},
	)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "email-cred", claim([]any{"email"}, "dave@example.com"))
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
		if attr, ok := attrMap[pk("domain")]; ok && attr.Value != nil &&
			attr.Value.String != nil && *attr.Value.String == "example.com" {
			matchingCred = opt
			break
		}
	}
	require.NotNil(t, matchingCred, "should find a credential with domain example.com")

	attrMap := attributeMap(matchingCred.Attributes)
	requireAttr(t, attrMap, []any{"email"}, "eve@example.com")
	requireAttr(t, attrMap, []any{"domain"}, "example.com")

	grantPermission(t, c, session.Id, makeDisclosureChoice(matchingCred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "email-cred",
		claim([]any{"email"}, "eve@example.com"),
		claim([]any{"domain"}, "example.com"),
	)
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

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"owner_name"}, Value: strVal("Frank"), DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"}},
					{Path: []any{"address", "street"}, Value: strVal("10 Downing St"), DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"}},
					{Path: []any{"address", "city"}, Value: strVal("London"), DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"}},
				}},
			}},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "house-cred",
		claim([]any{"owner_name"}, "Frank"),
		claim([]any{"address", "street"}, "10 Downing St"),
		claim([]any{"address", "city"}, "London"),
	)
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

	// Arrays are expanded into individual elements with indexed paths.
	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("TU Delft"),
		},
		header([]any{"courses"}, clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}),
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
			Value: strVal("Networks"),
		},
	)

	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "student-cred",
		claim([]any{"university"}, "TU Delft"),
		claim([]any{"courses"}, "[Algorithms Databases Networks]"),
	)
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
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"courses", 1}, Value: strVal("Databases")},
				}},
			}},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	// The verifier receives the full courses array even when a specific element
	// was requested, because the SD-JWT disclosure reveals the whole array.
	requireVerifierReceivedClaims(t, result, "student-cred",
		claim([]any{"courses"}, "[Algorithms Databases Networks]"),
	)
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

	// Null path expands into individual elements with indexed paths.
	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	requireAttrsInOrder(t, cred.Attributes,
		header([]any{"courses"}, clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}),
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
			Value: strVal("Networks"),
		},
	)

	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "student-cred",
		claim([]any{"courses"}, "[Algorithms Databases Networks]"),
	)
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
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"member_name"}, Value: strVal("Grace"), DisplayName: &clientmodels.TranslatedString{"en": "Member Name"}},
					{Path: []any{"member_since"}, Value: strVal("2020-01-15"), DisplayName: &clientmodels.TranslatedString{"en": "Member Since"}},
				}},
			}},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "membership-cred",
		claim([]any{"member_name"}, "Grace"),
		claim([]any{"member_since"}, "2020-01-15"),
	)
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
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"email"}, Value: strVal("multi@example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Email"}},
					{Path: []any{"domain"}, Value: strVal("example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Domain"}},
				}},
			}},
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"university"}, Value: strVal("Radboud University"), DisplayName: &clientmodels.TranslatedString{"en": "University"}},
					{Path: []any{"student_id"}, Value: strVal("s1234567"), DisplayName: &clientmodels.TranslatedString{"en": "Student ID"}},
				}},
			}},
		},
	})

	// Grant permission for both required credentials.
	choices := make([]clientmodels.DisclosureDisconSelection, 2)
	for i, pickOne := range session.DisclosurePlan.DisclosureChoicesOverview {
		cred := pickOne.OwnedOptions[0]
		choices[i] = makeDisclosureChoice(cred)
	}
	grantPermission(t, c, session.Id, choices...)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 5, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Verify the verifier received only the requested credentials.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "email-cred",
		claim([]any{"email"}, "multi@example.com"),
		claim([]any{"domain"}, "example.com"),
	)
	requireVerifierReceivedClaims(t, result, "student-cred",
		claim([]any{"university"}, "Radboud University"),
		claim([]any{"student_id"}, "s1234567"),
	)

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

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"given_name"}, Value: strVal("Jan"), DisplayName: &clientmodels.TranslatedString{"en": "Given name"}},
					{Path: []any{"family_name"}, Value: strVal("de Vries"), DisplayName: &clientmodels.TranslatedString{"en": "Family name"}},
					{Path: []any{"email"}, Value: strVal("jan.devries@university.nl"), DisplayName: &clientmodels.TranslatedString{"en": "E-mail"}},
					{Path: []any{"schac_home_organization"}, Value: strVal("university.nl"), DisplayName: &clientmodels.TranslatedString{"en": "Organization"}},
				}},
			}},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "eduid-credential",
		claim([]any{"given_name"}, "Jan"),
		claim([]any{"family_name"}, "de Vries"),
		claim([]any{"email"}, "jan.devries@university.nl"),
		claim([]any{"schac_home_organization"}, "university.nl"),
		claim([]any{"eduperson_assurance"}, "https://eduid.nl/assurance/low"), // non-SD, always shared
	)
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
	requireAttr(t, attrMap, []any{"email"}, "claimsets@example.com")

	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "email-cred",
		claim([]any{"email"}, "claimsets@example.com"),
	)
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
		if attr, ok := attrMap[pk("email")]; ok && attr.Value != nil &&
			attr.Value.String != nil && *attr.Value.String == "vct@example.com" {
			emailCred = opt
			break
		}
	}
	require.NotNil(t, emailCred, "should find the email credential as a candidate")

	grantPermission(t, c, session.Id, makeDisclosureChoice(emailCred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "contact-cred",
		claim([]any{"email"}, "vct@example.com"),
	)
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
		// The matching credential should be "Student", not "Staff".
		requireAttr(t, attrMap, []any{"given_name"}, "Student")
	}

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "eduid-student",
		claim([]any{"given_name"}, "Student"),
		claim([]any{"is_student"}, "true"),
		claim([]any{"eduperson_assurance"}, "https://eduid.nl/assurance/low"), // non-SD, always shared
	)
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
			attrIds[i] = attr.ClaimPath
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
	require.Contains(t, attrMap, pk("member_since"), "non-SD claim member_since should be in the disclosure plan")
	requireNoAttr(t, attrMap, []any{"member_name"})
	requireNoAttr(t, attrMap, []any{"membership_type"})

	// Disclose with whatever attributes are available (only non-SD).
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

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

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"email"}, Value: strVal("dup@example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"}},
					{Path: []any{"domain"}, Value: strVal("example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Domain", "nl": "Domein"}},
				}},
			}},
		},
	})

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	attrMap := attributeMap(cred.Attributes)

	// "email" should appear exactly once despite being listed twice in the query.
	emailCount := 0
	for _, attr := range cred.Attributes {
		if clientmodels.ClaimPathKey(attr.ClaimPath) == pk("email") {
			emailCount++
		}
	}
	require.Equal(t, 1, emailCount, "duplicate email claim should be deduplicated")
	requireAttr(t, attrMap, []any{"email"}, "dup@example.com")
	requireAttr(t, attrMap, []any{"domain"}, "example.com")

	// Disclose and verify the session completes.
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "email-dup",
		claim([]any{"email"}, "dup@example.com"),
		claim([]any{"domain"}, "example.com"),
	)
}

// testDuplicateNestedClaimsIgnored issues a HouseCredential with nested address
// claims, then sends a DCQL query where ["address", "street"] appears twice and
// ["address", "city"] appears once. The wallet should deduplicate ["address", "street"]
// while keeping ["address", "city"] as a separate claim.
func testDuplicateNestedClaimsIgnored(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOid4Vci(t, c, sessionHandler, "HouseCredentialSdJwt", `{
		"owner_name": "Duplicate Tester",
		"address": {
			"street": "Kalverstraat 1",
			"city": "Amsterdam",
			"country": "NL"
		}
	}`)

	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "house-dup",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/house"]
					},
					"claims": [
						{ "path": ["owner_name"] },
						{ "path": ["address", "street"] },
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

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions)

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"owner_name"}, Value: strVal("Duplicate Tester"), DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"}},
					{Path: []any{"address", "street"}, Value: strVal("Kalverstraat 1"), DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"}},
					{Path: []any{"address", "city"}, Value: strVal("Amsterdam"), DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"}},
				}},
			}},
		},
	})

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]

	// Count occurrences of "street" — should be exactly 1 despite the duplicate.
	streetCount := 0
	cityCount := 0
	for _, attr := range cred.Attributes {
		if clientmodels.ClaimPathKey(attr.ClaimPath) == pk("address", "street") {
			streetCount++
		}
		if clientmodels.ClaimPathKey(attr.ClaimPath) == pk("address", "city") {
			cityCount++
		}
	}
	require.Equal(t, 1, streetCount, "duplicate ['address','street'] should be deduplicated to one")
	require.Equal(t, 1, cityCount, "['address','city'] should appear once")

	attrMap := attributeMap(cred.Attributes)
	requireAttr(t, attrMap, []any{"owner_name"}, "Duplicate Tester")
	requireAttr(t, attrMap, []any{"address", "street"}, "Kalverstraat 1")
	requireAttr(t, attrMap, []any{"address", "city"}, "Amsterdam")

	// Disclose and verify success.
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "house-dup",
		claim([]any{"owner_name"}, "Duplicate Tester"),
		claim([]any{"address", "street"}, "Kalverstraat 1"),
		claim([]any{"address", "city"}, "Amsterdam"),
	)
}

// testRequireDisclosurePlanOnlyChecksFirstOption demonstrates that
// requireDisclosurePlan only validates OwnedOptions[0] and ignores the rest.
// This test issues two email credentials, but requireDisclosurePlan only sees
// the first one — it doesn't verify the count or the second credential.
func testRequireDisclosurePlanOnlyChecksFirstOption(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue two email credentials with different addresses.
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
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Len(t, plan.DisclosureChoicesOverview, 1)

	// There should be 2 owned options (alice and bob).
	require.Len(t, plan.DisclosureChoicesOverview[0].OwnedOptions, 2,
		"both email credentials should be candidates")

	// BUG: requireDisclosurePlan only checks OwnedOptions[0] (alice).
	// Asserting bob's email value should fail because the helper never looks at OwnedOptions[1].
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"email"}, Value: strVal("bob@example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"}},
				}},
			}},
		},
	})

	// Disclose the first option and verify the verifier received data.
	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "email-cred",
		claim([]any{"email"}, "alice@example.com"),
	)
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

	plan := session.DisclosurePlan
	require.NotNil(t, plan)
	require.Len(t, plan.DisclosureChoicesOverview, 1)
	require.NotEmpty(t, plan.DisclosureChoicesOverview[0].OwnedOptions)

	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{
				{Attributes: []expectedAttr{
					{Path: []any{"email"}, Value: strVal("nokb@example.com"), DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"}},
				}},
			}},
		},
	})

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// The verifier may or may not verify the response (depends on verifier config),
	// but the session should complete successfully without a KB-JWT.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should succeed without holder binding")
	requireVerifierReceivedClaims(t, result, "email-no-kb",
		claim([]any{"email"}, "nokb@example.com"),
	)
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

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "email-cred",
		claim([]any{"email"}, "display@example.com"),
	)
}

// testEudiVerifierRequestingVeramoCredentialFails issues a credential via the
// veramo issuer (OID4VCI), then starts a disclosure session using the EUDI
// reference verifier. Because the EUDI verifier uses x509 client_id and a
// testBatchOfOneCredentialRemainsUsableAfterDisclosure issues a credential via
// OID4VCI with the default test-issuer (no batch_credential_issuance → batch of 1)
// and discloses it twice, verifying that the credential remains usable.
func testBatchOfOneCredentialRemainsUsableAfterDisclosure(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	dcqlQuery := `{
		"dcql": {
			"credentials": [{
				"id": "test-credential",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["https://localhost:8443/vct/email"] },
				"claims": [{ "path": ["email"] }]
			}]
		}
	}`

	// Step 1: Issue a credential via OID4VCI (batch of 1, test-issuer default).
	issueCredentialViaOid4Vci(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "batch1@example.com",
		"domain": "example.com"
	}`)

	// Step 2: First disclosure — should succeed.
	veramoSession1 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession1.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status, "first disclosure should succeed")

	result1 := checkVeramoVerifierOfferStatus(t, veramoSession1.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result1.Status)
	requireVerifierReceivedClaims(t, result1, "test-credential",
		claim([]any{"email"}, "batch1@example.com"),
	)

	// Step 3: Second disclosure — must also succeed (single instance stays reusable).
	veramoSession2 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession2.RequestUri)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status,
		"batch-of-1 credential should still be available for a second disclosure")

	cred = session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status,
		"second disclosure of batch-of-1 credential should succeed")

	result2 := checkVeramoVerifierOfferStatus(t, veramoSession2.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result2.Status)
	requireVerifierReceivedClaims(t, result2, "test-credential",
		claim([]any{"email"}, "batch1@example.com"),
	)
}

// testBatchOfTwoCredentialExhaustedAfterTwoDisclosures issues a credential via
// the batch2-issuer (batch_credential_issuance.batch_size = 2) and verifies that
// it can be disclosed exactly twice. A third disclosure attempt should fail
// because all instances have been used.
func testBatchOfTwoCredentialExhaustedAfterTwoDisclosures(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	dcqlQuery := `{
		"dcql": {
			"credentials": [{
				"id": "test-credential",
				"format": "dc+sd-jwt",
				"meta": { "vct_values": ["https://localhost:8443/vct/email"] },
				"claims": [{ "path": ["email"] }]
			}]
		}
	}`

	// Step 1: Issue a credential via the batch2-issuer (batch of 2).
	issueCredentialViaOid4VciFromIssuer(t, c, sessionHandler, batch2IssuerURL, batch2AdminToken,
		"EmailCredentialSdJwt", `{"email": "batch2@example.com", "domain": "example.com"}`)

	// Step 2: First disclosure — uses first instance.
	veramoSession1 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession1.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status, "first disclosure should succeed")

	result1 := checkVeramoVerifierOfferStatus(t, veramoSession1.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result1.Status)
	requireVerifierReceivedClaims(t, result1, "test-credential",
		claim([]any{"email"}, "batch2@example.com"),
	)

	// Step 3: Second disclosure — uses last instance.
	veramoSession2 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession2.RequestUri)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	cred = session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status, "second disclosure should succeed")

	result2 := checkVeramoVerifierOfferStatus(t, veramoSession2.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result2.Status)
	requireVerifierReceivedClaims(t, result2, "test-credential",
		claim([]any{"email"}, "batch2@example.com"),
	)

	// Step 4: Third disclosure — all instances exhausted, should fail.
	veramoSession3 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession3.RequestUri)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Error, session.Status,
		"third disclosure should fail because all batch instances are exhausted")
}

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
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

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

// expectedClaim is a claim path with its expected value.
type expectedClaim struct {
	Path  []any
	Value string
}

// claim builds an expectedClaim from a path and value.
func claim(path []any, value string) expectedClaim {
	return expectedClaim{Path: path, Value: value}
}

// requireVerifierReceivedClaims asserts that the veramo verifier received exactly
// the expected claims for a given credential query ID — no more, no less. Each
// expected claim is identified by its full path (navigating into nested objects
// and arrays) and matched against the stringified value.
//
// The function also rejects unexpected top-level claims (ignoring standard JWT
// claims like vct, iss, iat, etc.). This means non-SD claims that are always
// present in the JWT payload (e.g., eduperson_assurance) must be explicitly
// included in the expected list, even if they weren't requested by the verifier.
//
// Example:
//
//	requireVerifierReceivedClaims(t, result, "house-cred",
//	    claim([]any{"owner_name"}, "Frank"),
//	    claim([]any{"address", "street"}, "10 Downing St"),
//	    claim([]any{"address", "city"}, "London"),
//	)
func requireVerifierReceivedClaims(t *testing.T, result veramoCheckResult, queryId string, expected ...expectedClaim) {
	t.Helper()
	require.NotNil(t, result.Result, "verifier result should not be nil")
	creds, ok := result.Result.Credentials[queryId]
	require.True(t, ok, "verifier should have credentials for query %q", queryId)
	require.NotEmpty(t, creds, "verifier should have at least one credential for query %q", queryId)

	claims := creds[0].Claims

	// Check each expected claim exists with the right value.
	for _, exp := range expected {
		actual := navigateClaims(t, claims, exp.Path)
		require.Equal(t, exp.Value, fmt.Sprintf("%v", actual),
			"verifier claim at path %v value mismatch", exp.Path)
	}

	// Check no unexpected top-level claims exist (ignoring standard JWT claims).
	standardClaims := map[string]struct{}{
		"vct": {}, "iss": {}, "iat": {}, "exp": {}, "nbf": {}, "sub": {},
		"cnf": {}, "_sd_alg": {}, "status": {},
	}
	expectedTopLevel := make(map[string]struct{})
	for _, exp := range expected {
		if len(exp.Path) > 0 {
			if key, ok := exp.Path[0].(string); ok {
				expectedTopLevel[key] = struct{}{}
			}
		}
	}
	for key := range claims {
		if _, isStandard := standardClaims[key]; isStandard {
			continue
		}
		_, isExpected := expectedTopLevel[key]
		require.True(t, isExpected,
			"verifier received unexpected claim %q for query %q", key, queryId)
	}
}

// navigateClaims follows a claim path into a nested claims map.
func navigateClaims(t *testing.T, claims map[string]any, path []any) any {
	t.Helper()
	var current any = claims
	for i, component := range path {
		switch key := component.(type) {
		case string:
			m, ok := current.(map[string]any)
			require.True(t, ok, "expected object at path %v (step %d), got %T", path[:i], i, current)
			current, ok = m[key]
			require.True(t, ok, "claim %q not found at path %v", key, path[:i+1])
		case int:
			arr, ok := current.([]any)
			require.True(t, ok, "expected array at path %v (step %d), got %T", path[:i], i, current)
			require.True(t, key >= 0 && key < len(arr),
				"index %d out of range at path %v (len=%d)", key, path[:i+1], len(arr))
			current = arr[key]
		default:
			t.Fatalf("unsupported path component type %T at path %v", component, path[:i+1])
		}
	}
	return current
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

// expectedDisclosurePlan describes the complete expected disclosure plan.
type expectedDisclosurePlan struct {
	// Expected issuance steps. Nil to skip check.
	IssuanceSteps []expectedIssuanceStep
	// Expected issued credential ids. Nil to skip check.
	IssuedCredentialIds map[string]struct{}
	// Expected wrong credential issued. Nil to skip check entirely.
	// Use &expectedCredentialDescriptor{} to assert it's non-nil.
	WrongCredentialIssued *expectedCredentialDescriptor
	// If true, assert that WrongCredentialIssued is nil.
	WrongCredentialIssuedNil bool
	// Expected disclosure choices (one per DisclosurePickOne). Nil to assert nil choices.
	Choices []expectedPickOneChoice
}

// expectedIssuanceStep describes one step in IssueDuringDislosure.Steps.
type expectedIssuanceStep struct {
	Options []expectedCredentialDescriptor
}

// expectedCredentialDescriptor describes an expected CredentialDescriptor
// (used for obtainable options and issuance step options).
type expectedCredentialDescriptor struct {
	CredentialId string
	Name         *clientmodels.TranslatedString // nil to skip check
	Attributes   []expectedAttr
}

// expectedPickOneChoice describes one DisclosurePickOne entry.
type expectedPickOneChoice struct {
	Optional   bool
	Owned      []expectedPlanCredential
	Obtainable []expectedCredentialDescriptor
}

// expectedPlanCredential describes an expected owned credential instance.
type expectedPlanCredential struct {
	CredentialId string
	Name         *clientmodels.TranslatedString // nil to skip check
	Attributes   []expectedAttr
}

// requireDisclosurePlan asserts the complete structure of a disclosure plan:
// issuance steps, issued credential ids, wrong credential, and disclosure choices
// (owned + obtainable options).
func requireDisclosurePlan(t testingT, plan *clientmodels.DisclosurePlan, expected expectedDisclosurePlan) {
	t.Helper()
	require.NotNil(t, plan)

	// --- Issuance steps ---
	if expected.IssuanceSteps != nil {
		require.NotNil(t, plan.IssueDuringDislosure, "plan should have IssueDuringDislosure")
		require.Len(t, plan.IssueDuringDislosure.Steps, len(expected.IssuanceSteps),
			"issuance step count mismatch")
		for i, expStep := range expected.IssuanceSteps {
			actualStep := plan.IssueDuringDislosure.Steps[i]
			require.Len(t, actualStep.Options, len(expStep.Options),
				"issuance step %d option count mismatch", i)
			for j, expOpt := range expStep.Options {
				actualOpt := actualStep.Options[j]
				requireCredentialDescriptor(t, actualOpt, expOpt,
					fmt.Sprintf("issuance step %d option %d", i, j))
			}
		}
	}

	// --- Issued credential ids ---
	if expected.IssuedCredentialIds != nil {
		require.NotNil(t, plan.IssueDuringDislosure, "plan should have IssueDuringDislosure")
		require.Equal(t, expected.IssuedCredentialIds, plan.IssueDuringDislosure.IssuedCredentialIds,
			"issued credential ids mismatch")
	}

	// --- Wrong credential issued ---
	if expected.WrongCredentialIssuedNil {
		require.NotNil(t, plan.IssueDuringDislosure, "plan should have IssueDuringDislosure")
		require.Nil(t, plan.IssueDuringDislosure.WrongCredentialIssued,
			"wrong credential issued should be nil")
	}
	if expected.WrongCredentialIssued != nil {
		require.NotNil(t, plan.IssueDuringDislosure, "plan should have IssueDuringDislosure")
		require.NotNil(t, plan.IssueDuringDislosure.WrongCredentialIssued,
			"wrong credential issued should not be nil")
		wrong := plan.IssueDuringDislosure.WrongCredentialIssued
		if expected.WrongCredentialIssued.CredentialId != "" {
			require.Equal(t, expected.WrongCredentialIssued.CredentialId, wrong.CredentialId,
				"wrong credential id mismatch")
		}
		if len(expected.WrongCredentialIssued.Attributes) > 0 {
			requireAttrsInOrder(t, wrong.Attributes, expected.WrongCredentialIssued.Attributes...)
		}
	}

	// --- Disclosure choices ---
	if expected.Choices == nil {
		require.Nil(t, plan.DisclosureChoicesOverview, "disclosure choices should be nil")
		return
	}

	require.Len(t, plan.DisclosureChoicesOverview, len(expected.Choices),
		"disclosure choice count mismatch")

	for i, expChoice := range expected.Choices {
		pickOne := plan.DisclosureChoicesOverview[i]
		require.Equal(t, expChoice.Optional, pickOne.Optional,
			"choice %d Optional mismatch", i)

		// --- Owned options ---
		require.Len(t, pickOne.OwnedOptions, len(expChoice.Owned),
			"choice %d owned option count mismatch", i)

		for j, expOwned := range expChoice.Owned {
			// Find a matching credential in OwnedOptions.
			var matched *clientmodels.SelectableCredentialInstance
			for _, cred := range pickOne.OwnedOptions {
				if credMatchesExpected(cred, expOwned) {
					matched = cred
					break
				}
			}
			require.NotNil(t, matched,
				"choice %d owned %d: no option matches expected %v", i, j, expectedPlanSummary(expOwned))

			// Full assertions on the matched credential.
			if expOwned.CredentialId != "" {
				require.Equal(t, expOwned.CredentialId, matched.CredentialId,
					"choice %d owned %d credential id mismatch", i, j)
			}
			if expOwned.Name != nil {
				require.Equal(t, clientmodels.TranslatedString(*expOwned.Name), matched.Name,
					"choice %d owned %d credential name mismatch", i, j)
			}
			if len(expOwned.Attributes) > 0 {
				requireAttrsInOrder(t, matched.Attributes, expOwned.Attributes...)
			}
		}

		// --- Obtainable options ---
		require.Len(t, pickOne.ObtainableOptions, len(expChoice.Obtainable),
			"choice %d obtainable option count mismatch", i)

		for j, expObt := range expChoice.Obtainable {
			requireCredentialDescriptor(t, pickOne.ObtainableOptions[j], expObt,
				fmt.Sprintf("choice %d obtainable %d", i, j))
		}
	}
}

// requireCredentialDescriptor asserts a CredentialDescriptor matches expectations.
func requireCredentialDescriptor(t testingT, actual *clientmodels.CredentialDescriptor, expected expectedCredentialDescriptor, context string) {
	t.Helper()
	if expected.CredentialId != "" {
		require.Equal(t, expected.CredentialId, actual.CredentialId,
			"%s credential id mismatch", context)
	}
	if expected.Name != nil {
		require.Equal(t, clientmodels.TranslatedString(*expected.Name), actual.Name,
			"%s credential name mismatch", context)
	}
	if len(expected.Attributes) > 0 {
		requireAttrsInOrder(t, actual.Attributes, expected.Attributes...)
	}
}

// credMatchesExpected returns true if the credential has all expected attributes
// with matching paths and values (order-aware).
func credMatchesExpected(cred *clientmodels.SelectableCredentialInstance, exp expectedPlanCredential) bool {
	if exp.CredentialId != "" && cred.CredentialId != exp.CredentialId {
		return false
	}
	if exp.Name != nil {
		if !reflect.DeepEqual(clientmodels.TranslatedString(*exp.Name), cred.Name) {
			return false
		}
	}
	if len(cred.Attributes) != len(exp.Attributes) {
		return false
	}
	for i, expAttr := range exp.Attributes {
		actual := cred.Attributes[i]
		if clientmodels.ClaimPathKey(expAttr.Path) != clientmodels.ClaimPathKey(actual.ClaimPath) {
			return false
		}
		if expAttr.Value != nil {
			if actual.Value == nil || !reflect.DeepEqual(expAttr.Value, actual.Value) {
				return false
			}
		}
	}
	return true
}

// expectedPlanSummary returns a readable summary of an expected credential for error messages.
func expectedPlanSummary(exp expectedPlanCredential) string {
	parts := make([]string, 0, len(exp.Attributes))
	if exp.CredentialId != "" {
		parts = append(parts, fmt.Sprintf("id=%q", exp.CredentialId))
	}
	for _, attr := range exp.Attributes {
		pathKey := clientmodels.ClaimPathKey(attr.Path)
		if attr.Value != nil && attr.Value.String != nil {
			parts = append(parts, fmt.Sprintf("%s=%q", pathKey, *attr.Value.String))
		} else {
			parts = append(parts, pathKey)
		}
	}
	return strings.Join(parts, ", ")
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

// issueCredentialViaOid4VciFromIssuer is like issueCredentialViaOid4Vci but
// allows specifying a custom issuer URL and admin token.
func issueCredentialViaOid4VciFromIssuer(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	issuerURL string,
	adminToken string,
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

	offer := postOffer(t, issuerURL, adminToken, offerBody)
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

	status := checkOfferStatus(t, issuerURL, adminToken, offer.ID)
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
