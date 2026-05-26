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
	"github.com/privacybydesign/irmago/eudi/credentials/sdjwtvc"
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

	batch2IssuerURL  = "https://localhost:8443/batch2-issuer"
	batch2AdminToken = "test-admin-token"
)

func testSessionHandlerForOpenID4VPWithSdJwtVcs(t *testing.T) {
	t.Run("issue via openid4vci and disclose via openid4vp", testIssueViaOpenID4VCIAndDiscloseViaOpenID4VP)
	t.Run("payload-only claim surfaces in all UI flows", testPayloadOnlyClaimAcrossLifecycle)
	t.Run("disclose single credential with multiple attributes", testDiscloseCredentialWithMultipleAttributes)
	t.Run("choice between two credential types", testChoiceBetweenTwoCredentialTypes)
	t.Run("multiple required credentials", testMultipleRequiredCredentials)
	t.Run("optional credential", testOptionalCredential)
	t.Run("empty optional disclosure", testEmptyOptionalDisclosure)
	t.Run("credential with specific claim value", testCredentialWithSpecificClaimValue)
	t.Run("disclose nested claims", testDiscloseNestedClaims)
	t.Run("disclose credential with array values", testDiscloseCredentialWithArrayValues)
	t.Run("disclose specific array element", testDiscloseSpecificArrayElement)
	t.Run("disclose all array elements with null path", testDiscloseAllArrayElementsWithNullPath)
	t.Run("non-sd claims shown in disclosure plan", testNonSdClaimsShownInDisclosurePlan)
	t.Run("non-sd array claims flattened in disclosure plan", testNonSdArrayClaimsFlattenedInDisclosurePlan)
	t.Run("non-sd single item array flattened in disclosure plan", testNonSdSingleItemArrayFlattenedInDisclosurePlan)
	t.Run("issue many credentials and disclose subset", testIssueManyCredentialsAndDiscloseSubset)
	t.Run("claim sets picks first satisfiable set", testClaimSetsPicksFirstSatisfiableSet)
	t.Run("multiple vct values matches across types", testMultipleVctValuesMatchesAcrossTypes)
	t.Run("issue and disclose eduid credential", testIssueAndDiscloseEduIdCredential)
	t.Run("boolean claim value constraint", testBooleanClaimValueConstraint)
	t.Run("multiple credentials for same query", testMultipleCredentialsForSameQuery)
	t.Run("no claims requested shares only non-sd claims", testNoClaimsRequestedSharesOnlyNonSdClaims)
	t.Run("duplicate claims ignored", testDuplicateClaimsIgnored)
	t.Run("duplicate nested claims ignored", testDuplicateNestedClaimsIgnored)
	t.Run("disclose deeply nested organization credential", testDiscloseDeeplyNestedOrganizationCredential)
	t.Run("disclose specific nested array element from organization", testDiscloseSpecificNestedArrayElement)
	t.Run("disclose nested array with null path from organization", testDiscloseNestedArrayWithNullPath)
	t.Run("disclose single deep leaf shows ancestry", testDiscloseSingleDeepLeafShowsAncestry)
	t.Run("disclose sibling leaves share ancestry", testDiscloseSiblingLeavesShareAncestry)
	t.Run("disclose leaf with single wildcard", testDiscloseLeafWithSingleWildcard)
	t.Run("disclose leaf with double wildcard", testDiscloseLeafWithDoubleWildcard)
	t.Run("disclose null then fixed index logs only selected", testDiscloseNullThenFixedIndexLogsOnlySelected)
	t.Run("disclose shallow leaf shows single header", testDiscloseShallowLeafShowsSingleHeader)
	t.Run("disclose without holder binding", testDiscloseWithoutHolderBinding)
	t.Run("verifier display name", testVerifierDisplayName)
	t.Run("batch of one credential remains usable after disclosure", testBatchOfOneCredentialRemainsUsableAfterDisclosure)
	t.Run("batch of two credential is exhausted after two disclosures", testBatchOfTwoCredentialExhaustedAfterTwoDisclosures)
	t.Run("eudi verifier requesting veramo credential fails", testEudiVerifierRequestingVeramoCredentialFails)
	t.Run("veramo verifier requesting irma credential fails", testVeramoVerifierRequestingIrmaCredentialFails)
	t.Run("veramo verifier requesting missing credential surfaces it", testVeramoVerifierRequestingMissingCredentialSurfacesIt)
	t.Run("veramo verifier requesting unknown vct uses url-only fallback", testVeramoVerifierRequestingUnknownVctUsesUrlOnlyFallback)
	t.Run("veramo verifier multi-vct first missing second matched", testVeramoVerifierMultiVctFirstMissingSecondMatched)
}

func testIssueViaOpenID4VCIAndDiscloseViaOpenID4VP(t *testing.T) {
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
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.NotEmpty(t, session.OfferedCredentials)

	grantPermission(t, c, session.Id)

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
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/test",
						Name:         clientmodels.TranslatedString{"en": "Test Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"given_name"},
								DisplayName: &clientmodels.TranslatedString{"en": "Given Name"},
								Value:       strVal("Test"),
							},
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("test@example.com"),
							},
						},
					},
				},
			},
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

// testPayloadOnlyClaimAcrossLifecycle exercises the payload-driven attribute system
// across every UI surface that consumes it: the issuance preview
// (SessionState.OfferedCredentials), the stored credential list (GetCredentials),
// the issuance log, the disclosure plan (DisclosureChoicesOverview), and the
// disclosure log. The credential is issued with an "extra_note" field that the
// issuer metadata does NOT declare; it must appear at every surface with
// DisplayName: nil and sorted after the metadata-declared claims.
//
// If the test issuer drops unknown payload fields, the early assertions fail with
// "attribute count mismatch" — that signals the issuer config needs to widen its
// credentialDataSupplierInput pass-through.
func testPayloadOnlyClaimAcrossLifecycle(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Inline the issuance so we can intercept session.OfferedCredentials between
	// the permission request and the grant — the helper would have moved past it.
	offerBody := `{
		"credentials": ["StudentCardCredentialSdJwt"],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": {
			"university": "TU Delft",
			"level": "MSc",
			"student_id": "S77777",
			"extra_note": "payload-only"
		}
	}`
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
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	expectedAttrs := []expectedAttr{
		{
			Path:        []any{"university"},
			DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("TU Delft"),
		},
		{
			Path:        []any{"level"},
			DisplayName: &clientmodels.TranslatedString{"en": "Level", "nl": "Niveau"},
			Value:       strVal("MSc"),
		},
		{
			Path:        []any{"student_id"},
			DisplayName: &clientmodels.TranslatedString{"en": "Student ID", "nl": "Studentnummer"},
			Value:       strVal("S77777"),
		},
		{
			Path:  []any{"extra_note"},
			Value: strVal("payload-only"),
			// DisplayName nil: not declared in metadata.
		},
	}

	// Surface A: issuance preview (SessionState.OfferedCredentials.Attributes).
	requireAttrsInOrder(t, session.OfferedCredentials[0].Attributes, expectedAttrs...)

	grantPermission(t, c, session.Id)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// Surface "GetCredentials": stored credential.
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	stored := findCredentialByName(t, creds, "en", "Student Card Credential (SD-JWT)")
	require.NotNil(t, stored, "issued StudentCardCredential should appear in GetCredentials")
	requireAttrsInOrder(t, stored.Attributes, expectedAttrs...)

	// Surface C-issuance: issuance log.
	logs, err := c.LoadNewestLogs(10)
	require.NoError(t, err)
	var issuanceLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_Issuance {
			issuanceLog = &logs[i]
			break
		}
	}
	require.NotNil(t, issuanceLog, "issuance log should be recorded")
	require.NotNil(t, issuanceLog.IssuanceLog)
	require.Len(t, issuanceLog.IssuanceLog.Credentials, 1)
	requireAttrsInOrder(t, issuanceLog.IssuanceLog.Credentials[0].Attributes, expectedAttrs...)

	// Surface B: disclosure plan. Ask the verifier for university + extra_note so
	// the disclosure walks both a metadata-declared and a payload-only path.
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
						{ "path": ["extra_note"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/studentcard",
						Name:         clientmodels.TranslatedString{"en": "Student Card Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"university"},
								DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								Value:       strVal("TU Delft"),
							},
							{
								Path:  []any{"extra_note"},
								Value: strVal("payload-only"),
								// DisplayName nil: not declared in metadata.
							},
						},
					},
				},
			},
		},
	})

	chosen := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(chosen))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Surface C-disclosure: disclosure log records the same payload-only field.
	logs, err = c.LoadNewestLogs(10)
	require.NoError(t, err)
	var disclosureLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_Disclosure {
			disclosureLog = &logs[i]
			break
		}
	}
	require.NotNil(t, disclosureLog, "disclosure log should be recorded")
	require.NotNil(t, disclosureLog.DisclosureLog)
	require.Len(t, disclosureLog.DisclosureLog.Credentials, 1)
	requireAttrsInOrder(t, disclosureLog.DisclosureLog.Credentials[0].Attributes,
		expectedAttr{
			Path:        []any{"university"},
			DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
			Value:       strVal("TU Delft"),
		},
		expectedAttr{
			Path:  []any{"extra_note"},
			Value: strVal("payload-only"),
		},
	)
}

// testDiscloseCredentialWithMultipleAttributes issues an EmailCredential and
// requests both email and domain claims in a single credential query.
func testDiscloseCredentialWithMultipleAttributes(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue an EmailCredential via OID4VCI.
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
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
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("alice@example.com"),
							},
							{
								Path:        []any{"domain"},
								DisplayName: &clientmodels.TranslatedString{"en": "Domain"},
								Value:       strVal("example.com"),
							},
						},
					},
				},
			},
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
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "bob@example.com",
		"domain": "example.com"
	}`)

	// Issue PhoneCredential.
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "PhoneCredentialSdJwt", `{
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

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("bob@example.com"),
							},
						},
					},
					{
						CredentialId: "https://localhost:8443/vct/phone",
						Name:         clientmodels.TranslatedString{"en": "Phone Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"phone_number"},
								DisplayName: &clientmodels.TranslatedString{"en": "Phone Number"},
								Value:       strVal("+31612345678"),
							},
						},
					},
				},
			},
		},
	})

	// Pick the first option (whichever it is) and disclose.
	chosen := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Len(t, chosen.Credentials, 1)
	chosenCred := chosen.Credentials[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(chosen))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")

	// Verify the verifier received attributes for the chosen credential.
	if chosenCred.CredentialId == "https://localhost:8443/vct/email" {
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
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "carol@example.com",
		"domain": "example.com"
	}`)

	// Issue PhoneCredential.
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "PhoneCredentialSdJwt", `{
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
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("carol@example.com"),
							},
						},
					},
				},
			},
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/phone",
						Name:         clientmodels.TranslatedString{"en": "Phone Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"phone_number"},
								DisplayName: &clientmodels.TranslatedString{"en": "Phone Number"},
								Value:       strVal("+31687654321"),
							},
						},
					},
				},
			},
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
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
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
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("dave@example.com"),
							},
						},
					},
				},
			},
			{
				Optional: true,
				// The wallet has no phone credential, so the missing-credentials
				// feature surfaces a single unobtainable descriptor (empty
				// IssueURL). Since the pickOne is optional, it stays in
				// DisclosureChoicesOverview rather than being promoted to
				// IssueDuringDisclosure.Steps — the user can simply skip it.
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "https://localhost:8443/vct/phone",
						Name:         &clientmodels.TranslatedString{"en": "Phone Credential (SD-JWT)"},
						IssuerName:   &clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{Path: []any{"phone_number"}},
						},
					},
				},
			},
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

// testEmptyOptionalDisclosure covers the case where the verifier requests only
// optional credential_sets and the user owns the credential but declines to
// share it. The wallet POSTs an empty VP, the verifier accepts it, and the
// wallet records a disclosure log so the user can see which verifier they had
// a session with.
func testEmptyOptionalDisclosure(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "skip@example.com",
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
			],
			"credential_sets": [
				{ "options": [["email-cred"]], "required": false }
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// Skip the single optional pickOne by passing an empty selection.
	grantPermission(t, c, session.Id, clientmodels.DisclosureDisconSelection{})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the empty response")
	if result.Result != nil {
		require.Empty(t, result.Result.Credentials,
			"verifier should have received no credentials")
	}

	// Simple log check: an OpenID4VP disclosure log exists for this session,
	// even though no credentials were shared.
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	var disclosureLog *clientmodels.LogInfo
	for i := range logs {
		if logs[i].Type == clientmodels.LogType_Disclosure {
			disclosureLog = &logs[i]
			break
		}
	}
	require.NotNil(t, disclosureLog, "should have a disclosure log even when no credentials were shared")
	require.Equal(t, clientmodels.Protocol_OpenID4VP, disclosureLog.DisclosureLog.Protocol)
	require.Empty(t, disclosureLog.DisclosureLog.Credentials)
}

// testCredentialWithSpecificClaimValue issues two EmailCredentials with
// different domains. The DCQL query requests email with a specific domain
// value. Only the matching credential should be selectable.
func testCredentialWithSpecificClaimValue(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue first EmailCredential with domain "example.com".
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "eve@example.com",
		"domain": "example.com"
	}`)

	// Issue second EmailCredential with domain "other.org".
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
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

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("eve@example.com"),
							},
							{
								Path:           []any{"domain"},
								DisplayName:    &clientmodels.TranslatedString{"en": "Domain"},
								Value:          strVal("example.com"),
								RequestedValue: strVal("example.com"),
							},
						},
					},
				},
			},
		},
	})

	matchingCred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "HouseCredentialSdJwt", `{
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

	expectedAttrs := []expectedAttr{
		{
			Path:        []any{"owner_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
			Value:       strVal("Frank"),
		},
		header([]any{"address"}, clientmodels.TranslatedString{"en": "Address", "nl": "Adres"}),
		{
			Path:        []any{"address", "street"},
			DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
			Value:       strVal("10 Downing St"),
		},
		{
			Path:        []any{"address", "city"},
			DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
			Value:       strVal("London"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/house",
						Name:         clientmodels.TranslatedString{"en": "House Possession Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
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
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/house", expectedAttrs)
}

// testDiscloseCredentialWithArrayValues issues a StudentCardCredential that
// includes a "courses" claim with an array value, then discloses it.
func testDiscloseCredentialWithArrayValues(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a StudentCardCredential with an array of courses.
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
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
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/studentcard",
						Name:         clientmodels.TranslatedString{"en": "Student Card Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"university"},
								DisplayName: &clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"},
								Value:       strVal("TU Delft"),
							},
							header([]any{"courses"}, clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}),
							{
								Path:  []any{"courses", 0},
								Value: strVal("Algorithms"),
							},
							{
								Path:  []any{"courses", 1},
								Value: strVal("Databases"),
							},
							{
								Path:  []any{"courses", 2},
								Value: strVal("Networks"),
							},
						},
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "student-cred",
		claim([]any{"university"}, "TU Delft"),
		claim([]any{"courses", 0}, "Algorithms"),
		claim([]any{"courses", 1}, "Databases"),
		claim([]any{"courses", 2}, "Networks"),
	)
}

// testDiscloseSpecificArrayElement issues a StudentCardCredential with a courses
// array and creates a DCQL query that requests a specific element by index
// (path: ["courses", 1]).
func testDiscloseSpecificArrayElement(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
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

	// DCQL requested courses[1] only, but the issuer bundled the whole
	// `courses` array into a single SD disclosure — so disclosing the
	// requested element unavoidably reveals the rest. The plan shows the
	// bundled siblings up front so the user can see what they'll actually
	// share.
	expectedAttrs := []expectedAttr{
		header([]any{"courses"}, clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}),
		{
			Path:  []any{"courses", 0},
			Value: strVal("Algorithms"),
		},
		{
			Path:  []any{"courses", 1},
			Value: strVal("Databases"),
		},
		{
			Path:  []any{"courses", 2},
			Value: strVal("Networks"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/studentcard",
						Name:         clientmodels.TranslatedString{"en": "Student Card Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
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
		claim([]any{"courses", 0}, "Algorithms"),
		claim([]any{"courses", 1}, "Databases"),
		claim([]any{"courses", 2}, "Networks"),
	)
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/studentcard", expectedAttrs)
}

// testDiscloseAllArrayElementsWithNullPath issues a StudentCardCredential with
// a courses array and creates a DCQL query that requests all elements using a
// null path component (path: ["courses", null]).
func testDiscloseAllArrayElementsWithNullPath(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
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
	expectedAttrs := []expectedAttr{
		header([]any{"courses"}, clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}),
		{
			Path:  []any{"courses", 0},
			Value: strVal("Algorithms"),
		},
		{
			Path:  []any{"courses", 1},
			Value: strVal("Databases"),
		},
		{
			Path:  []any{"courses", 2},
			Value: strVal("Networks"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/studentcard",
						Name:         clientmodels.TranslatedString{"en": "Student Card Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should have received or verified the response")
	requireVerifierReceivedClaims(t, result, "student-cred",
		claim([]any{"courses", 0}, "Algorithms"),
		claim([]any{"courses", 1}, "Databases"),
		claim([]any{"courses", 2}, "Networks"),
	)
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/studentcard", expectedAttrs)
}

// testNonSdClaimsShownInDisclosurePlan issues a MembershipCredential where
// member_name and membership_type are SD claims but member_since is a non-SD
// claim (always in the JWT payload). The verifier only asks for member_name,
// but the disclosure plan should also show member_since because it is always
// shared when the credential is presented.
func testNonSdClaimsShownInDisclosurePlan(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "MembershipCredentialSdJwt", `{
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
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/membership",
						Name:         clientmodels.TranslatedString{"en": "Membership Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"member_name"},
								DisplayName: &clientmodels.TranslatedString{"en": "Member Name"},
								Value:       strVal("Grace"),
							},
							{
								Path:        []any{"member_since"},
								DisplayName: &clientmodels.TranslatedString{"en": "Member Since"},
								Value:       strVal("2020-01-15"),
							},
						},
					},
				},
			},
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

// testNonSdArrayClaimsFlattenedInDisclosurePlan issues a MembershipCredential
// with a non-SD "benefits" claim that has an array value, then verifies that the
// disclosure plan correctly flattens the array into indexed attributes instead of
// stringifying it into a single value.
func testNonSdArrayClaimsFlattenedInDisclosurePlan(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "MembershipCredentialSdJwt", `{
		"member_name": "Grace",
		"member_since": "2020-01-15",
		"membership_type": "Gold",
		"benefits": ["Lounge access", "Free parking", "Priority support"]
	}`)

	// The verifier only asks for the SD claim member_name. The non-SD claims
	// (member_since and benefits) should be included automatically.
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

	// The verifier asked for member_name only. Non-SD top-level claims
	// (member_since and benefits) are always present in the JWT payload, so
	// they appear in the verifier-side view and therefore in the plan.
	// `benefits` itself has no metadata header in this batch — only its
	// elements show up.
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/membership",
						Name:         clientmodels.TranslatedString{"en": "Membership Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"member_name"},
								DisplayName: &clientmodels.TranslatedString{"en": "Member Name"},
								Value:       strVal("Grace"),
							},
							{
								Path:        []any{"member_since"},
								DisplayName: &clientmodels.TranslatedString{"en": "Member Since"},
								Value:       strVal("2020-01-15"),
							},
							{
								Path:  []any{"benefits", 0},
								Value: strVal("Lounge access"),
							},
							{
								Path:  []any{"benefits", 1},
								Value: strVal("Free parking"),
							},
							{
								Path:  []any{"benefits", 2},
								Value: strVal("Priority support"),
							},
						},
					},
				},
			},
		},
	})
}

// testNonSdSingleItemArrayFlattenedInDisclosurePlan verifies that a non-SD
// claim containing a single-element array is correctly flattened into a section
// header and one indexed attribute instead of being stringified.
func testNonSdSingleItemArrayFlattenedInDisclosurePlan(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "MembershipCredentialSdJwt", `{
		"member_name": "Alice",
		"member_since": "2023-06-01",
		"membership_type": "Silver",
		"benefits": ["Early access"]
	}`)

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

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/membership",
						Name:         clientmodels.TranslatedString{"en": "Membership Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"member_name"},
								DisplayName: &clientmodels.TranslatedString{"en": "Member Name"},
								Value:       strVal("Alice"),
							},
							{
								Path:        []any{"member_since"},
								DisplayName: &clientmodels.TranslatedString{"en": "Member Since"},
								Value:       strVal("2023-06-01"),
							},
							{
								Path:  []any{"benefits", 0},
								Value: strVal("Early access"),
							},
						},
					},
				},
			},
		},
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
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "multi@example.com",
		"domain": "example.com"
	}`)
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "PhoneCredentialSdJwt", `{
		"phone_number": "+31699999999"
	}`)
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "StudentCardCredentialSdJwt", `{
		"university": "Radboud University",
		"level": "Master",
		"student_id": "s1234567",
		"courses": ["Algorithms", "Databases", "Security"]
	}`)
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "HouseCredentialSdJwt", `{
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
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("multi@example.com"),
							},
							{
								Path:        []any{"domain"},
								DisplayName: &clientmodels.TranslatedString{"en": "Domain"},
								Value:       strVal("example.com"),
							},
						},
					},
				},
			},
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/studentcard",
						Name:         clientmodels.TranslatedString{"en": "Student Card Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"university"},
								DisplayName: &clientmodels.TranslatedString{"en": "University"},
								Value:       strVal("Radboud University"),
							},
							{
								Path:        []any{"student_id"},
								DisplayName: &clientmodels.TranslatedString{"en": "Student ID"},
								Value:       strVal("s1234567"),
							},
						},
					},
				},
			},
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

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EduIdCredentialSdJwt", `{
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

	expectedAttrs := []expectedAttr{
		// Tree-walk order follows metadata declaration:
		// schac_home_organization, given_name, family_name, email.
		{
			Path:        []any{"schac_home_organization"},
			DisplayName: &clientmodels.TranslatedString{"en": "Organization"},
			Value:       strVal("university.nl"),
		},
		{
			Path:        []any{"given_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Given name"},
			Value:       strVal("Jan"),
		},
		{
			Path:        []any{"family_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family name"},
			Value:       strVal("de Vries"),
		},
		{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "E-mail"},
			Value:       strVal("jan.devries@university.nl"),
		},
		// eduperson_assurance has sd:"never" in the VCT: always disclosed, never selectively hidden.
		{
			Path:        []any{"eduperson_assurance"},
			DisplayName: &clientmodels.TranslatedString{"en": "Assurance"},
			Value:       strVal("https://eduid.nl/assurance/low"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/eduid",
						Name:         clientmodels.TranslatedString{"en": "eduID"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
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
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/eduid", expectedAttrs)
}

// testClaimSetsPicksFirstSatisfiableSet issues an EmailCredential and uses a
// DCQL query with claim_sets to express disjunctive claim requirements: either
// just the email, or just the domain. Because claim_sets are tried in order and
// both are satisfiable, the first set (email only) should be picked.
func testClaimSetsPicksFirstSatisfiableSet(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
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

	// The first claim set ["em"] should be selected, so only email is a requested
	// attribute.
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("claimsets@example.com"),
							},
						},
					},
				},
			},
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

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "vct@example.com",
		"domain": "example.com"
	}`)
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "PhoneCredentialSdJwt", `{
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

	// The email credential should match (it has an "email" claim).
	// The phone credential should NOT match (it has no "email" claim).
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("vct@example.com"),
							},
						},
					},
				},
			},
		},
	})

	emailCred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EduIdCredentialSdJwt", `{
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
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EduIdCredentialSdJwt", `{
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
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/eduid",
						Name:         clientmodels.TranslatedString{"en": "eduID"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						// Order is metadata-declared: given_name (idx 2),
						// eduperson_assurance (idx 6), is_student (idx 7).
						Attributes: []expectedAttr{
							{
								Path:        []any{"given_name"},
								DisplayName: &clientmodels.TranslatedString{"en": "Given name", "nl": "Voornaam"},
								Value:       strVal("Student"),
							},
							{
								Path:        []any{"eduperson_assurance"},
								DisplayName: &clientmodels.TranslatedString{"en": "Assurance", "nl": "Bevestiging"},
								Value:       strVal("https://eduid.nl/assurance/low"),
							},
							{
								Path:           []any{"is_student"},
								DisplayName:    &clientmodels.TranslatedString{"en": "IsStudent", "nl": "IsStudent"},
								Value:          boolVal(true),
								RequestedValue: boolVal(true),
							},
						},
					},
				},
			},
		},
	})

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

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "alice@example.com",
		"domain": "example.com"
	}`)
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
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
	requireDisclosurePlan(t, plan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("alice@example.com"),
							},
						},
					},
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("bob@example.com"),
							},
						},
					},
				},
			},
		},
	})

	pickOne := plan.DisclosureChoicesOverview[0]
	require.True(t, pickOne.Multiple, "multiple flag should be true in the disclosure plan")

	// Select BOTH bundles (this is the key difference from single-select).
	var selectedCreds []clientmodels.SelectedCredential
	for _, bundle := range pickOne.OwnedOptions {
		for _, opt := range bundle.Credentials {
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

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "MembershipCredentialSdJwt", `{
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

	// The disclosure plan should only contain non-SD claims.
	// "member_since" is non-SD, while "member_name" and "membership_type" are SD.
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/membership",
						Name:         clientmodels.TranslatedString{"en": "Membership Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"member_since"},
								DisplayName: &clientmodels.TranslatedString{"en": "Member Since"},
								Value:       strVal("2020-01-01"),
							},
						},
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "membership-cred",
		claim([]any{"member_since"}, "2020-01-01"),
	)
}

// testDuplicateClaimsIgnored issues an EmailCredential, then sends a DCQL query
// where the "email" claim appears twice. Per OpenID4VP Section 6.3, the wallet
// should ignore duplicate claim queries — the disclosure plan should contain
// "email" only once.
func testDuplicateClaimsIgnored(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
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

	// The requireDisclosurePlan call below asserts exactly 2 attributes (email + domain),
	// proving that the duplicate "email" claim was deduplicated to one.
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email"},
								Value:       strVal("dup@example.com"),
							},
							{
								Path:        []any{"domain"},
								DisplayName: &clientmodels.TranslatedString{"en": "Domain"},
								Value:       strVal("example.com"),
							},
						},
					},
				},
			},
		},
	})

	// Disclose and verify the session completes.
	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "HouseCredentialSdJwt", `{
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

	// The requireDisclosurePlan call below asserts exactly 3 attributes (owner_name,
	// address/street, address/city), proving that the duplicate address/street was
	// deduplicated to one.
	expectedAttrs := []expectedAttr{
		{
			Path:        []any{"owner_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Owner Name", "nl": "Eigenaar"},
			Value:       strVal("Duplicate Tester"),
		},
		header([]any{"address"}, clientmodels.TranslatedString{"en": "Address", "nl": "Adres"}),
		{
			Path:        []any{"address", "street"},
			DisplayName: &clientmodels.TranslatedString{"en": "Street", "nl": "Straat"},
			Value:       strVal("Kalverstraat 1"),
		},
		{
			Path:        []any{"address", "city"},
			DisplayName: &clientmodels.TranslatedString{"en": "City", "nl": "Stad"},
			Value:       strVal("Amsterdam"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/house",
						Name:         clientmodels.TranslatedString{"en": "House Possession Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	// Disclose and verify success.
	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
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
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/house", expectedAttrs)
}

// testDiscloseWithoutHolderBinding issues a credential, then creates a DCQL
// query with require_cryptographic_holder_binding set to false. The wallet should
// disclose the credential without appending a key binding JWT.
func testDiscloseWithoutHolderBinding(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
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
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/email",
						Name:         clientmodels.TranslatedString{"en": "Email Credential (SD-JWT)", "nl": "E-mail Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email", "nl": "E-mailadres"},
								Value:       strVal("nokb@example.com"),
							},
						},
					},
				},
			},
		},
	})

	cred := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// The session should complete successfully without a KB-JWT because
	// require_cryptographic_holder_binding was set to false in the DCQL query.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status,
		"verifier session should succeed without holder binding")
	requireVerifierReceivedClaims(t, result, "email-no-kb",
		claim([]any{"email"}, "nokb@example.com"),
	)
	// Verify the verifier did not report any holder binding verification.
	// The veramo API does not expose the raw KB-JWT directly, but if holder binding
	// had been required and was missing, the verifier would report an error.
	// We verify indirectly: the query set require_cryptographic_holder_binding=false,
	// so success here means no KB-JWT was expected or verified.
	require.NotNil(t, result.Result)
	for _, msg := range result.Result.Messages {
		require.NotContains(t, msg.Message, "holder binding",
			"verifier should not report holder binding issues when it was not required")
	}
}

// testVerifierDisplayName verifies that the verifier display name shown to the
// user comes from client_metadata.client_name rather than the raw DID.
func testVerifierDisplayName(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
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
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
		"email": "batch1@example.com",
		"domain": "example.com"
	}`)

	// Batch-of-1 credentials are infinitely reusable, so the remaining count
	// should be nil (not a pointer to 1) to signal "unlimited" to the UI.
	requireBatchRemaining(t, c, "Email Credential (SD-JWT)", nil)

	// Step 2: First disclosure — should succeed.
	veramoSession1 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession1.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	bundle := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Len(t, bundle.Credentials, 1)
	require.Nil(t, bundle.Credentials[0].BatchInstanceCountRemaining,
		"batch-of-1 credential should have nil remaining in disclosure plan")
	grantPermission(t, c, session.Id, makeDisclosureChoice(bundle))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status, "first disclosure should succeed")

	result1 := checkVeramoVerifierOfferStatus(t, veramoSession1.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result1.Status)
	requireVerifierReceivedClaims(t, result1, "test-credential",
		claim([]any{"email"}, "batch1@example.com"),
	)

	// Remaining count should still be nil after disclosure.
	requireBatchRemaining(t, c, "Email Credential (SD-JWT)", nil)

	// Step 3: Second disclosure — must also succeed (single instance stays reusable).
	veramoSession2 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession2.RequestUri)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status,
		"batch-of-1 credential should still be available for a second disclosure")

	bundle = session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Len(t, bundle.Credentials, 1)
	require.Nil(t, bundle.Credentials[0].BatchInstanceCountRemaining,
		"batch-of-1 credential should still have nil remaining after first disclosure")
	grantPermission(t, c, session.Id, makeDisclosureChoice(bundle))

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
	issueCredentialViaOpenID4VCIFromIssuer(t, c, sessionHandler, batch2IssuerURL, batch2AdminToken,
		"EmailCredentialSdJwt", `{"email": "batch2@example.com", "domain": "example.com"}`)

	// Batch-of-2 should have a non-nil remaining count of 2.
	requireBatchRemaining(t, c, "Email Credential (SD-JWT, Batch 2)", uintPtr(2))

	// Step 2: First disclosure — uses first instance.
	veramoSession1 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession1.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	bundle := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Len(t, bundle.Credentials, 1)
	require.NotNil(t, bundle.Credentials[0].BatchInstanceCountRemaining,
		"batch-of-2 credential should have non-nil remaining in disclosure plan")
	require.Equal(t, uint(2), *bundle.Credentials[0].BatchInstanceCountRemaining,
		"batch-of-2 credential should have 2 remaining before first disclosure")
	grantPermission(t, c, session.Id, makeDisclosureChoice(bundle))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status, "first disclosure should succeed")

	result1 := checkVeramoVerifierOfferStatus(t, veramoSession1.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result1.Status)
	requireVerifierReceivedClaims(t, result1, "test-credential",
		claim([]any{"email"}, "batch2@example.com"),
	)

	// After first disclosure, remaining should be 1.
	requireBatchRemaining(t, c, "Email Credential (SD-JWT, Batch 2)", uintPtr(1))

	// Step 3: Second disclosure — uses last instance.
	veramoSession2 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession2.RequestUri)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	bundle = session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Len(t, bundle.Credentials, 1)
	require.NotNil(t, bundle.Credentials[0].BatchInstanceCountRemaining,
		"batch-of-2 credential should have non-nil remaining after first disclosure")
	require.Equal(t, uint(1), *bundle.Credentials[0].BatchInstanceCountRemaining,
		"batch-of-2 credential should have 1 remaining before second disclosure")
	grantPermission(t, c, session.Id, makeDisclosureChoice(bundle))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status, "second disclosure should succeed")

	result2 := checkVeramoVerifierOfferStatus(t, veramoSession2.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result2.Status)
	requireVerifierReceivedClaims(t, result2, "test-credential",
		claim([]any{"email"}, "batch2@example.com"),
	)

	// Step 4: Third disclosure — all instances exhausted, should fail.
	// Design decision: when all batch instances are exhausted, the session reports an
	// error rather than showing a permission request with empty owned options. This is
	// because the credential type is known but unusable, which is a hard failure rather
	// than a "missing credential" scenario where issuance could help.
	veramoSession3 := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession3.RequestUri)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Error, session.Status,
		"third disclosure should fail because all batch instances are exhausted")
	require.NotNil(t, session.Error, "session should contain an error when batch is exhausted")
}

// different trust model, the session should result in an error.
func testEudiVerifierRequestingVeramoCredentialFails(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a credential via the veramo OID4VCI issuer.
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "EmailCredentialSdJwt", `{
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
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "test.test.email",
						Name:         clientmodels.TranslatedString{"en": "Demo Email address", "nl": "Demo E-mailadres"},
						IssuerName:   clientmodels.TranslatedString{"en": "Demo test issuer", "nl": "Demo test issuer"},
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
								Value:       strVal("test@gmail.com"),
							},
						},
					},
				},
				Obtainable: []expectedCredentialDescriptor{
					{
						CredentialId: "test.test.email",
						Attributes: []expectedAttr{
							{
								Path:        []any{"email"},
								DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
							},
						},
					},
				},
			},
		},
	})

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

// testVeramoVerifierRequestingMissingCredentialSurfacesIt asserts the
// "missing credentials" UX: when a verifier asks for a VCT the wallet has
// never seen, the disclosure plan promotes a single CredentialDescriptor
// (with an empty IssueURL) into IssueDuringDisclosure.Steps so the frontend
// can tell the user *what* is being requested instead of stalling on a
// blank permission prompt. DisclosureChoicesOverview is hidden until the
// step resolves — which it never can, so the user's only path forward is
// cancellation.
func testVeramoVerifierRequestingMissingCredentialSurfacesIt(t *testing.T) {
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

	// addIssueDuringDisclosure hides DisclosureChoicesOverview when issuance is
	// needed — including the "issuance" of an unobtainable credential.
	require.Nil(t, session.DisclosurePlan.DisclosureChoicesOverview,
		"choices should be nil because there is one unsatisfiable issuance step")
	require.NotNil(t, session.DisclosurePlan.IssueDuringDisclosure)
	require.Len(t, session.DisclosurePlan.IssueDuringDisclosure.Steps, 1)
	require.Len(t, session.DisclosurePlan.IssueDuringDisclosure.Steps[0].Options, 1)

	bundle := session.DisclosurePlan.IssueDuringDisclosure.Steps[0].Options[0]
	require.Len(t, bundle.Credentials, 1, "DCQL maps each query to a single-credential bundle")
	option := bundle.Credentials[0]
	require.Equal(t, "https://localhost:8443/vct/email", option.CredentialId)
	require.Nil(t, option.IssueURL, "empty IssueURL is the wire-level signal that the credential is unobtainable")
	require.NotEmpty(t, option.Name, "Name populated from the VCT type metadata document")
	require.NotEmpty(t, option.Issuer.Id, "Issuer.Id populated via the VCT's issuer field + well-known fetch")
	require.NotEmpty(t, option.Issuer.Name, "Issuer.Name populated from the issuer's well-known display")
}

// testVeramoVerifierRequestingUnknownVctUsesUrlOnlyFallback asserts the
// URL-only fallback row of the failure cascade: the verifier requests a VCT
// the wallet has never seen *and* whose URL returns 404. The plan still
// reports the missing credential by URL — Name/Issuer remain empty.
func testVeramoVerifierRequestingUnknownVctUsesUrlOnlyFallback(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "missing-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": ["https://localhost:8443/vct/does-not-exist-anywhere"]
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
	require.Nil(t, session.DisclosurePlan.DisclosureChoicesOverview)
	require.NotNil(t, session.DisclosurePlan.IssueDuringDisclosure)
	require.Len(t, session.DisclosurePlan.IssueDuringDisclosure.Steps, 1)
	require.Len(t, session.DisclosurePlan.IssueDuringDisclosure.Steps[0].Options, 1)

	bundle := session.DisclosurePlan.IssueDuringDisclosure.Steps[0].Options[0]
	require.Len(t, bundle.Credentials, 1, "DCQL maps each query to a single-credential bundle")
	option := bundle.Credentials[0]
	require.Equal(t, "https://localhost:8443/vct/does-not-exist-anywhere", option.CredentialId)
	require.Nil(t, option.IssueURL)
	require.Empty(t, option.Name, "no Name when VCT type-metadata fetch failed")
	require.Empty(t, option.Issuer.Id, "no Issuer when we couldn't even read the type metadata")
}

// testVeramoVerifierMultiVctFirstMissingSecondMatched asserts the
// multi-VCT cascade: when the first VCT URL 404s but the second resolves to
// metadata for an unowned credential, the plan emits one fully-populated
// descriptor for the second VCT.
func testVeramoVerifierMultiVctFirstMissingSecondMatched(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Wallet is empty — even though /vct/email resolves and is well-formed,
	// no batches exist for it so the unobtainable path runs.
	dcqlQuery := `{
		"dcql": {
			"credentials": [
				{
					"id": "missing-cred",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": [
							"https://localhost:8443/vct/does-not-exist-anywhere",
							"https://localhost:8443/vct/email"
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
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.NotNil(t, session.DisclosurePlan)
	require.Nil(t, session.DisclosurePlan.DisclosureChoicesOverview)
	require.NotNil(t, session.DisclosurePlan.IssueDuringDisclosure)
	require.Len(t, session.DisclosurePlan.IssueDuringDisclosure.Steps, 1)
	require.Len(t, session.DisclosurePlan.IssueDuringDisclosure.Steps[0].Options, 1)

	bundle := session.DisclosurePlan.IssueDuringDisclosure.Steps[0].Options[0]
	require.Len(t, bundle.Credentials, 1, "DCQL maps each query to a single-credential bundle")
	option := bundle.Credentials[0]
	require.Equal(t, "https://localhost:8443/vct/email", option.CredentialId,
		"second VCT (whose fetch succeeded) wins")
	require.Nil(t, option.IssueURL)
	require.NotEmpty(t, option.Name)
}

// testDiscloseDeeplyNestedOrganizationCredential issues an OrganizationCredential
// with a deeply nested structure (university > faculties[] > departments[] > courses[])
// and discloses the entire university claim. The disclosure plan should correctly
// expand all nested arrays and objects into individual attributes with proper paths.
func testDiscloseDeeplyNestedOrganizationCredential(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
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

	// Request the entire university claim — forces expansion of all nested arrays.
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

	deptName := &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"}
	facName := &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"}
	departments := clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}
	courses := clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}

	expectedAttrs := []expectedAttr{
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		{
			Path:        []any{"university", "name"},
			DisplayName: &clientmodels.TranslatedString{"en": "University Name", "nl": "Naam universiteit"},
			Value:       strVal("TU Delft"),
		},
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
		// Faculty 0 (EEMCS).
		{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		// Department 0 (Software Technology).
		{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 1},
			Value: strVal("Distributed Systems"),
		},
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 2},
			Value: strVal("Intro to CS"),
		},
		// Department 1 (Data Science).
		{
			Path:        []any{"university", "faculties", 0, "departments", 1, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Data Science"),
		},
		header([]any{"university", "faculties", 0, "departments", 1, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 1, "courses", 0},
			Value: strVal("Machine Learning"),
		},
		// Faculty 1 (Architecture).
		{
			Path:        []any{"university", "faculties", 1, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("Architecture"),
		},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 1, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Urbanism"),
		},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 1, "departments", 0, "courses", 0},
			Value: strVal("City Planning"),
		},
		{
			Path:        []any{"university", "founded"},
			DisplayName: &clientmodels.TranslatedString{"en": "Founded", "nl": "Opgericht"},
			Value:       intVal(1842),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/organization",
						Name:         clientmodels.TranslatedString{"en": "Organization Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
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
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/organization", expectedAttrs)
}

// testDiscloseSpecificNestedArrayElement issues an OrganizationCredential and
// requests a specific faculty's department name by index path. This tests that
// deeply nested array indexing works correctly in the disclosure plan.
func testDiscloseSpecificNestedArrayElement(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
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
							"courses": ["Machine Learning", "Statistics"]
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

	// Request specific nested paths: second department of first faculty and
	// the second faculty's name.
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
						{ "path": ["university", "faculties", 0, "departments", 1, "dept_name"] },
						{ "path": ["university", "faculties", 1, "faculty_name"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	deptName := &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"}
	facName := &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"}
	departments := clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}
	courses := clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}
	university := clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}
	faculties := clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}

	// DCQL asked for two specific leaves, but the issuer made each
	// `faculty[i]` one big SD disclosure with `departments` and all
	// children inlined. So disclosing either faculty unavoidably reveals
	// every department + dept_name + course in that faculty. The plan must
	// surface those bundled fields up front.
	expectedAttrs := []expectedAttr{
		header([]any{"university"}, university),
		header([]any{"university", "faculties"}, faculties),
		// Faculty 0: faculty_name + both departments (and all their courses).
		{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 1},
			Value: strVal("Distributed Systems"),
		},
		{
			Path:        []any{"university", "faculties", 0, "departments", 1, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Data Science"),
		},
		header([]any{"university", "faculties", 0, "departments", 1, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 1, "courses", 0},
			Value: strVal("Machine Learning"),
		},
		{
			Path:  []any{"university", "faculties", 0, "departments", 1, "courses", 1},
			Value: strVal("Statistics"),
		},
		// Faculty 1: faculty_name + its single department.
		{
			Path:        []any{"university", "faculties", 1, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("Architecture"),
		},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 1, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Urbanism"),
		},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 1, "departments", 0, "courses", 0},
			Value: strVal("City Planning"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/organization",
						Name:         clientmodels.TranslatedString{"en": "Organization Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "faculties", 0, "faculty_name"}, "EEMCS"),
		claim([]any{"university", "faculties", 0, "departments", 0, "dept_name"}, "Software Technology"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 0}, "Compiler Construction"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 1}, "Distributed Systems"),
		claim([]any{"university", "faculties", 0, "departments", 1, "dept_name"}, "Data Science"),
		claim([]any{"university", "faculties", 0, "departments", 1, "courses", 0}, "Machine Learning"),
		claim([]any{"university", "faculties", 0, "departments", 1, "courses", 1}, "Statistics"),
		claim([]any{"university", "faculties", 1, "faculty_name"}, "Architecture"),
		claim([]any{"university", "faculties", 1, "departments", 0, "dept_name"}, "Urbanism"),
		claim([]any{"university", "faculties", 1, "departments", 0, "courses", 0}, "City Planning"),
	)
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/organization", expectedAttrs)
}

// testDiscloseNestedArrayWithNullPath issues an OrganizationCredential and
// uses null path components to request all faculty names and all department
// names across all faculties. This tests deeply nested wildcard expansion.
func testDiscloseNestedArrayWithNullPath(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
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
	}`)

	// Use null path to request all faculty names and all department names.
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
						{ "path": ["university", "faculties", null, "faculty_name"] },
						{ "path": ["university", "faculties", null, "departments", null, "dept_name"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	deptName := &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"}
	facName := &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"}
	departments := clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}
	courses := clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}

	// DCQL asked for faculty_names and dept_names only, but the issuer
	// inlines all departments + courses inside each faculty disclosure —
	// so disclosing any faculty unavoidably reveals every dept_name and
	// every course in that faculty.
	expectedAttrs := []expectedAttr{
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
		{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 1},
			Value: strVal("Distributed Systems"),
		},
		{
			Path:        []any{"university", "faculties", 0, "departments", 1, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Data Science"),
		},
		header([]any{"university", "faculties", 0, "departments", 1, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 1, "courses", 0},
			Value: strVal("Machine Learning"),
		},
		{
			Path:        []any{"university", "faculties", 1, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("Architecture"),
		},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 1, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Urbanism"),
		},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 1, "departments", 0, "courses", 0},
			Value: strVal("City Planning"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/organization",
						Name:         clientmodels.TranslatedString{"en": "Organization Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "faculties", 0, "faculty_name"}, "EEMCS"),
		claim([]any{"university", "faculties", 0, "departments", 0, "dept_name"}, "Software Technology"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 0}, "Compiler Construction"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 1}, "Distributed Systems"),
		claim([]any{"university", "faculties", 0, "departments", 1, "dept_name"}, "Data Science"),
		claim([]any{"university", "faculties", 0, "departments", 1, "courses", 0}, "Machine Learning"),
		claim([]any{"university", "faculties", 1, "faculty_name"}, "Architecture"),
		claim([]any{"university", "faculties", 1, "departments", 0, "dept_name"}, "Urbanism"),
		claim([]any{"university", "faculties", 1, "departments", 0, "courses", 0}, "City Planning"),
	)
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/organization", expectedAttrs)
}

// testDiscloseSingleDeepLeafShowsAncestry requests one deeply-nested leaf and
// asserts that all four named compound ancestors emit headers ahead of it.
func testDiscloseSingleDeepLeafShowsAncestry(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
		"university": {
			"name": "TU Delft",
			"faculties": [
				{
					"faculty_name": "EEMCS",
					"departments": [
						{
							"dept_name": "Software Technology",
							"courses": ["Compiler Construction", "Distributed Systems", "Intro to CS"]
						}
					]
				}
			],
			"founded": 1842
		}
	}`)

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
						{ "path": ["university", "faculties", 0, "departments", 0, "courses", 1] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The DCQL only asks for one course element, but the issuer bundles
	// the whole faculty into one disclosure — so disclosing that one
	// course unavoidably also reveals faculty_name and the rest of the
	// department + courses for that faculty.
	expectedAttrs := []expectedAttr{
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
		{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"},
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}),
		{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"},
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}),
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 1},
			Value: strVal("Distributed Systems"),
		},
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 2},
			Value: strVal("Intro to CS"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/organization",
						Name:         clientmodels.TranslatedString{"en": "Organization Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "faculties", 0, "faculty_name"}, "EEMCS"),
		claim([]any{"university", "faculties", 0, "departments", 0, "dept_name"}, "Software Technology"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 0}, "Compiler Construction"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 1}, "Distributed Systems"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 2}, "Intro to CS"),
	)
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/organization", expectedAttrs)
}

// testDiscloseSiblingLeavesShareAncestry requests two leaves under the same
// department and asserts that shared compound ancestors are emitted once.
func testDiscloseSiblingLeavesShareAncestry(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
		"university": {
			"name": "TU Delft",
			"faculties": [
				{
					"faculty_name": "EEMCS",
					"departments": [
						{
							"dept_name": "Software Technology",
							"courses": ["Compiler Construction", "Distributed Systems"]
						}
					]
				}
			],
			"founded": 1842
		}
	}`)

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
						{ "path": ["university", "faculties", 0, "departments", 0, "dept_name"] },
						{ "path": ["university", "faculties", 0, "departments", 0, "courses", 0] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// Two specific leaves were asked for, but the issuer bundles each
	// faculty as a single disclosure — so the whole faculty (faculty_name +
	// the one department, which contains both courses) gets released.
	expectedAttrs := []expectedAttr{
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
		{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"},
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}),
		{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"},
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}),
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 1},
			Value: strVal("Distributed Systems"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/organization",
						Name:         clientmodels.TranslatedString{"en": "Organization Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "faculties", 0, "faculty_name"}, "EEMCS"),
		claim([]any{"university", "faculties", 0, "departments", 0, "dept_name"}, "Software Technology"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 0}, "Compiler Construction"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 1}, "Distributed Systems"),
	)
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/organization", expectedAttrs)
}

// testDiscloseLeafWithSingleWildcard requests a leaf via a single null wildcard
// and asserts that headers for the shared ancestors are emitted only once
// across the wildcard-expanded concrete paths.
func testDiscloseLeafWithSingleWildcard(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
		"university": {
			"name": "TU Delft",
			"faculties": [
				{
					"faculty_name": "EEMCS",
					"departments": [
						{ "dept_name": "Software Technology", "courses": ["Compiler Construction"] }
					]
				},
				{
					"faculty_name": "Architecture",
					"departments": [
						{ "dept_name": "Urbanism", "courses": ["City Planning"] }
					]
				}
			],
			"founded": 1842
		}
	}`)

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
						{ "path": ["university", "faculties", null, "faculty_name"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	facName := &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"}
	deptName := &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"}
	departments := clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}
	courses := clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}

	// DCQL only asks for faculty_names but each faculty is one bundled
	// disclosure — the verifier ends up seeing the dept_name and courses
	// for every faculty too. The plan reflects that.
	expectedAttrs := []expectedAttr{
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
		{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		{
			Path:        []any{"university", "faculties", 1, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("Architecture"),
		},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 1, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Urbanism"),
		},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 1, "departments", 0, "courses", 0},
			Value: strVal("City Planning"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/organization",
						Name:         clientmodels.TranslatedString{"en": "Organization Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "faculties", 0, "faculty_name"}, "EEMCS"),
		claim([]any{"university", "faculties", 0, "departments", 0, "dept_name"}, "Software Technology"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 0}, "Compiler Construction"),
		claim([]any{"university", "faculties", 1, "faculty_name"}, "Architecture"),
		claim([]any{"university", "faculties", 1, "departments", 0, "dept_name"}, "Urbanism"),
		claim([]any{"university", "faculties", 1, "departments", 0, "courses", 0}, "City Planning"),
	)
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/organization", expectedAttrs)
}

// testDiscloseNullThenFixedIndexLogsOnlySelected combines a null wildcard with
// a fixed array index later in the path — the user's reported scenario. With
// two DCQL claims (faculty_name across all faculties, plus the first course of
// the first department in each faculty), the disclosure log MUST contain
// exactly those four leaves and the headers that lead to them — never the
// other faculty/department/course fields, and never university.name or
// university.founded.
func testDiscloseNullThenFixedIndexLogsOnlySelected(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
		"university": {
			"name": "TU Delft",
			"faculties": [
				{
					"faculty_name": "EEMCS",
					"departments": [
						{
							"dept_name": "Software Technology",
							"courses": ["Compiler Construction", "Distributed Systems"]
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

	// Same shape as the user's reported DCQL: null wildcard at faculty level
	// combined with a fixed-index path further down.
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
						{ "path": ["university", "faculties", null, "faculty_name"] },
						{ "path": ["university", "faculties", null, "departments", 0, "courses", 0] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	facName := &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"}
	departments := clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}
	courses := clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}
	university := clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}
	faculties := clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}

	deptName := &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"}

	// The issuer bundles each `departments[i]` value into a single SD
	// disclosure (the value is `{dept_name, courses}` directly, with no
	// inner _sd) and the courses array isn't per-element SD. So requesting
	// `["faculties", null, "departments", 0, "courses", 0]` unavoidably
	// pulls in `dept_name` and the rest of `courses` for that department —
	// the disclosure plan must show those siblings up front so the user
	// can see what they'll actually share.
	expectedAttrs := []expectedAttr{
		header([]any{"university"}, university),
		header([]any{"university", "faculties"}, faculties),
		{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 1},
			Value: strVal("Distributed Systems"),
		},
		{
			Path:        []any{"university", "faculties", 1, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("Architecture"),
		},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 1, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Urbanism"),
		},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 1, "departments", 0, "courses", 0},
			Value: strVal("City Planning"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/organization",
						Name:         clientmodels.TranslatedString{"en": "Organization Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "faculties", 0, "faculty_name"}, "EEMCS"),
		claim([]any{"university", "faculties", 0, "departments", 0, "dept_name"}, "Software Technology"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 0}, "Compiler Construction"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 1}, "Distributed Systems"),
		claim([]any{"university", "faculties", 1, "faculty_name"}, "Architecture"),
		claim([]any{"university", "faculties", 1, "departments", 0, "dept_name"}, "Urbanism"),
		claim([]any{"university", "faculties", 1, "departments", 0, "courses", 0}, "City Planning"),
	)
	// The disclosure log must contain only those four leaves and their
	// ancestor headers — nothing else. requireAttrsInOrder asserts exact
	// length, so any extra attribute (e.g., dept_name from the same
	// department, or university.name/founded) would fail this check.
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/organization", expectedAttrs)
}

// testDiscloseLeafWithDoubleWildcard requests a leaf via a double null wildcard
// (cartesian expansion) and asserts that per-faculty department headers are
// emitted but top-level headers are deduped.
func testDiscloseLeafWithDoubleWildcard(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
		"university": {
			"name": "TU Delft",
			"faculties": [
				{
					"faculty_name": "EEMCS",
					"departments": [
						{ "dept_name": "Software Technology", "courses": ["Compiler Construction"] },
						{ "dept_name": "Data Science", "courses": ["Machine Learning"] }
					]
				},
				{
					"faculty_name": "Architecture",
					"departments": [
						{ "dept_name": "Urbanism", "courses": ["City Planning"] }
					]
				}
			],
			"founded": 1842
		}
	}`)

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
						{ "path": ["university", "faculties", null, "departments", null, "dept_name"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	deptName := &clientmodels.TranslatedString{"en": "Department Name", "nl": "Afdelingsnaam"}
	departments := clientmodels.TranslatedString{"en": "Departments", "nl": "Afdelingen"}

	facName := &clientmodels.TranslatedString{"en": "Faculty Name", "nl": "Faculteitsnaam"}
	courses := clientmodels.TranslatedString{"en": "Courses", "nl": "Vakken"}

	// DCQL only asks for dept_names but each faculty is a single bundled
	// disclosure, so faculty_name and the rest of the department (incl.
	// courses) ride along.
	expectedAttrs := []expectedAttr{
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		header([]any{"university", "faculties"}, clientmodels.TranslatedString{"en": "Faculties", "nl": "Faculteiten"}),
		{
			Path:        []any{"university", "faculties", 0, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("EEMCS"),
		},
		header([]any{"university", "faculties", 0, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 0, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Software Technology"),
		},
		header([]any{"university", "faculties", 0, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 0, "courses", 0},
			Value: strVal("Compiler Construction"),
		},
		{
			Path:        []any{"university", "faculties", 0, "departments", 1, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Data Science"),
		},
		header([]any{"university", "faculties", 0, "departments", 1, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 0, "departments", 1, "courses", 0},
			Value: strVal("Machine Learning"),
		},
		{
			Path:        []any{"university", "faculties", 1, "faculty_name"},
			DisplayName: facName,
			Value:       strVal("Architecture"),
		},
		header([]any{"university", "faculties", 1, "departments"}, departments),
		{
			Path:        []any{"university", "faculties", 1, "departments", 0, "dept_name"},
			DisplayName: deptName,
			Value:       strVal("Urbanism"),
		},
		header([]any{"university", "faculties", 1, "departments", 0, "courses"}, courses),
		{
			Path:  []any{"university", "faculties", 1, "departments", 0, "courses", 0},
			Value: strVal("City Planning"),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/organization",
						Name:         clientmodels.TranslatedString{"en": "Organization Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "faculties", 0, "faculty_name"}, "EEMCS"),
		claim([]any{"university", "faculties", 0, "departments", 0, "dept_name"}, "Software Technology"),
		claim([]any{"university", "faculties", 0, "departments", 0, "courses", 0}, "Compiler Construction"),
		claim([]any{"university", "faculties", 0, "departments", 1, "dept_name"}, "Data Science"),
		claim([]any{"university", "faculties", 0, "departments", 1, "courses", 0}, "Machine Learning"),
		claim([]any{"university", "faculties", 1, "faculty_name"}, "Architecture"),
		claim([]any{"university", "faculties", 1, "departments", 0, "dept_name"}, "Urbanism"),
		claim([]any{"university", "faculties", 1, "departments", 0, "courses", 0}, "City Planning"),
	)
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/organization", expectedAttrs)
}

// testDiscloseShallowLeafShowsSingleHeader requests a leaf with exactly one
// named compound ancestor and asserts that exactly one header is emitted.
func testDiscloseShallowLeafShowsSingleHeader(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "OrganizationCredentialSdJwt", `{
		"university": {
			"name": "TU Delft",
			"faculties": [],
			"founded": 1842
		}
	}`)

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
						{ "path": ["university", "founded"] }
					]
				}
			]
		}
	}`
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)

	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	expectedAttrs := []expectedAttr{
		header([]any{"university"}, clientmodels.TranslatedString{"en": "University", "nl": "Universiteit"}),
		{
			Path:        []any{"university", "founded"},
			DisplayName: &clientmodels.TranslatedString{"en": "Founded", "nl": "Opgericht"},
			Value:       intVal(1842),
		},
	}
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{
					{
						CredentialId: "https://localhost:8443/vct/organization",
						Name:         clientmodels.TranslatedString{"en": "Organization Credential (SD-JWT)"},
						IssuerName:   clientmodels.TranslatedString{"en": "Test Issuer", "nl": "Test Uitgever"},
						Attributes:   expectedAttrs,
					},
				},
			},
		},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)
	requireVerifierReceivedClaims(t, result, "org-cred",
		claim([]any{"university", "founded"}, "1842"),
	)
	requireNewestDisclosureLogAttrs(t, c, "https://localhost:8443/vct/organization", expectedAttrs)
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

	// Each expected claim must exist with the right value.
	for _, exp := range expected {
		actual := navigateClaims(t, claims, exp.Path)
		require.Equal(t, exp.Value, fmt.Sprintf("%v", actual),
			"verifier claim at path %v value mismatch", exp.Path)
	}

	// And the verifier must NOT have received any other user-data leaves.
	// We walk the actual claims tree and require every visible leaf to
	// correspond to one of the expected paths. Top-level standard
	// JWT/SD-JWT claims (vct, iss, iat, …) are skipped because they are
	// always present and not user-controlled.
	expectedSet := make(map[string]struct{}, len(expected))
	for _, exp := range expected {
		expectedSet[claimPathString(exp.Path)] = struct{}{}
	}

	var unexpected []string
	walkClaimLeaves(claims, nil, func(path []any) {
		if len(path) == 1 {
			if name, ok := path[0].(string); ok {
				if _, std := sdjwtvc.StandardClaims[name]; std {
					return
				}
			}
		}
		if _, ok := expectedSet[claimPathString(path)]; ok {
			return
		}
		unexpected = append(unexpected, claimPathString(path))
	})

	require.Empty(t, unexpected,
		"verifier received unexpected claims for query %q: %s", queryId, strings.Join(unexpected, ", "))
}

// walkClaimLeaves visits every scalar leaf in the verifier-received claims
// tree, calling visit with the full path. Compound values (objects/arrays)
// are descended; nil values are treated as leaves so the helper notices
// when a verifier receives an explicit null.
func walkClaimLeaves(value any, prefix []any, visit func([]any)) {
	switch v := value.(type) {
	case map[string]any:
		for k, child := range v {
			next := append(append([]any{}, prefix...), k)
			walkClaimLeaves(child, next, visit)
		}
	case []any:
		for i, child := range v {
			next := append(append([]any{}, prefix...), i)
			walkClaimLeaves(child, next, visit)
		}
	default:
		visit(prefix)
	}
}

// claimPathString turns a path into a deterministic string key for set
// lookups. Mirrors clientmodels.ClaimPathKey but kept local to the test
// helper so we don't widen its API surface.
func claimPathString(path []any) string {
	return fmt.Sprintf("%v", path)
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

// expectedIssuanceStep describes one step in IssueDuringDisclosure.Steps.
type expectedIssuanceStep struct {
	Options []expectedCredentialDescriptor
}

// expectedCredentialDescriptor describes an expected CredentialDescriptor
// (used for obtainable options and issuance step options).
type expectedCredentialDescriptor struct {
	CredentialId string
	Name         *clientmodels.TranslatedString // nil to skip check
	IssuerName   *clientmodels.TranslatedString // nil to skip check
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
	Name         clientmodels.TranslatedString
	IssuerName   clientmodels.TranslatedString
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
		require.NotNil(t, plan.IssueDuringDisclosure, "plan should have IssueDuringDisclosure")
		require.Len(t, plan.IssueDuringDisclosure.Steps, len(expected.IssuanceSteps),
			"issuance step count mismatch")
		for i, expStep := range expected.IssuanceSteps {
			actualStep := plan.IssueDuringDisclosure.Steps[i]
			require.Len(t, actualStep.Options, len(expStep.Options),
				"issuance step %d option count mismatch", i)
			for j, expOpt := range expStep.Options {
				actualBundle := actualStep.Options[j]
				require.Len(t, actualBundle.Credentials, 1,
					"issuance step %d option %d expected single-credential bundle", i, j)
				requireCredentialDescriptor(t, actualBundle.Credentials[0], expOpt,
					fmt.Sprintf("issuance step %d option %d", i, j))
			}
		}
	}

	// --- Issued credential ids ---
	if expected.IssuedCredentialIds != nil {
		require.NotNil(t, plan.IssueDuringDisclosure, "plan should have IssueDuringDisclosure")
		require.Equal(t, expected.IssuedCredentialIds, plan.IssueDuringDisclosure.IssuedCredentialIds,
			"issued credential ids mismatch")
	}

	// --- Wrong credential issued ---
	if expected.WrongCredentialIssuedNil {
		require.NotNil(t, plan.IssueDuringDisclosure, "plan should have IssueDuringDisclosure")
		require.Nil(t, plan.IssueDuringDisclosure.WrongCredentialIssued,
			"wrong credential issued should be nil")
	}
	if expected.WrongCredentialIssued != nil {
		require.NotNil(t, plan.IssueDuringDisclosure, "plan should have IssueDuringDisclosure")
		require.NotNil(t, plan.IssueDuringDisclosure.WrongCredentialIssued,
			"wrong credential issued should not be nil")
		wrong := plan.IssueDuringDisclosure.WrongCredentialIssued
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
		// Flatten all bundle credentials and check against the flat expected
		// list. Most disclosure shapes produce single-credential bundles, so
		// total credential count == len(OwnedOptions). Multi-credential bundles
		// (e.g. one con requiring multiple singletons) bump the credential
		// count beyond the bundle count; the flat assertion still works.
		var flatOwned []*clientmodels.SelectableCredentialInstance
		for _, bundle := range pickOne.OwnedOptions {
			flatOwned = append(flatOwned, bundle.Credentials...)
		}
		require.Len(t, flatOwned, len(expChoice.Owned),
			"choice %d total owned credential count mismatch (across %d bundle(s))",
			i, len(pickOne.OwnedOptions))

		for j, expOwned := range expChoice.Owned {
			// Find a matching credential anywhere in any bundle.
			var matched *clientmodels.SelectableCredentialInstance
			for _, cred := range flatOwned {
				if credMatchesExpected(cred, expOwned) {
					matched = cred
					break
				}
			}
			require.NotNil(t, matched,
				"choice %d owned %d: no option matches expected %v", i, j, expectedPlanSummary(expOwned))

			// Full assertions on the matched credential.
			require.Equal(t, expOwned.CredentialId, matched.CredentialId,
				"choice %d owned %d credential id mismatch", i, j)
			require.Equal(t, expOwned.Name, matched.Name,
				"choice %d owned %d credential name mismatch", i, j)
			require.Equal(t, expOwned.IssuerName, matched.Issuer.Name,
				"choice %d owned %d issuer name mismatch", i, j)
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
	if expected.IssuerName != nil {
		require.Equal(t, clientmodels.TranslatedString(*expected.IssuerName), actual.Issuer.Name,
			"%s issuer name mismatch", context)
	}
	if len(expected.Attributes) > 0 {
		requireAttrsInOrder(t, actual.Attributes, expected.Attributes...)
	}
}

// credMatchesExpected returns true if the credential has all expected attributes
// with matching paths and values (order-aware).
func credMatchesExpected(cred *clientmodels.SelectableCredentialInstance, exp expectedPlanCredential) bool {
	if cred.CredentialId != exp.CredentialId {
		return false
	}
	if !reflect.DeepEqual(exp.Name, cred.Name) {
		return false
	}
	if !reflect.DeepEqual(exp.IssuerName, cred.Issuer.Name) {
		return false
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

// issueCredentialViaOpenID4VCI issues a single credential through the veramo-agent
// OID4VCI pre-authorized code flow. The credentialType identifies the credential
// configuration (e.g. "EmailCredentialSdJwt") and claimsJSON provides the claim
// values as a JSON object.
func issueCredentialViaOpenID4VCI(
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
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.NotEmpty(t, session.OfferedCredentials)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_Success)

	status := checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status)
}

// issueCredentialViaOpenID4VCIFromIssuer is like issueCredentialViaOpenID4VCI but
// allows specifying a custom issuer URL and admin token.
func issueCredentialViaOpenID4VCIFromIssuer(
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
	requireSessionState(t, session, session.Id, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.NotEmpty(t, session.OfferedCredentials)

	grantPermission(t, c, session.Id)

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

// requireBatchRemaining asserts the BatchInstanceCountsRemaining for a credential
// found by display name. Pass expected=nil for unlimited (batch-of-1), or a *uint for finite counts.
func requireBatchRemaining(t *testing.T, c *client.Client, credName string, expected *uint) {
	t.Helper()
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	cred := findCredentialByName(t, creds, "en", credName)
	require.NotNil(t, cred, "credential %q not found", credName)
	require.Len(t, cred.BatchInstanceCountsRemaining, 1)
	for _, remaining := range cred.BatchInstanceCountsRemaining {
		if expected == nil {
			require.Nil(t, remaining, "expected nil remaining count (unlimited) for %q", credName)
		} else {
			require.NotNil(t, remaining, "expected non-nil remaining count for %q", credName)
			require.Equal(t, *expected, *remaining, "remaining count mismatch for %q", credName)
		}
	}
}

func uintPtr(v uint) *uint { return &v }

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
