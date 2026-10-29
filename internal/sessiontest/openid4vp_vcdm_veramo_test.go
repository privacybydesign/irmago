package sessiontest

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// SD-JWT-secured W3C VCDM 2.0 (vc+sd-jwt) disclosure to the veramo verifier
// (v1.6.6+). The wallet envelopes the SD-JWT in a Verifiable Presentation signed
// with the holder key; the verifier checks the presentation's signature, aud and
// nonce, and returns the contents of credentialSubject as the claims. It does
// not verify the issuer signature of the enveloped SD-JWT itself.
//
// Veramo issues every vc+sd-jwt claim in the clear (see
// openid4vci_vcdm_issuance_test.go), so a disclosure always hands over the whole
// credentialSubject, whatever the verifier asks for.

const vcdmQueryId = "vcdm"

func testSessionHandlerForOpenID4VPVcdm(t *testing.T) {
	t.Run("discloses VCDM credential to veramo verifier", testDiscloseVcdmToVeramoVerifier)
	t.Run("query without meta matches VCDM credential", testVcdmQueryWithoutMetaMatches)
	t.Run("type_values mismatch offers no VCDM candidate", testVcdmTypeValuesMismatchOffersNoCandidate)
	t.Run("dc+sd-jwt query does not offer VCDM credential", testDcSdJwtQueryDoesNotOfferVcdmCredential)
	t.Run("VCDM and SD-JWT VC disclosed in one request", testVcdmAndSdJwtVcInOneRequest)
}

func testDiscloseVcdmToVeramoVerifier(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)
	holderDid := vcdmHolderDid(t, requireSingleVcdmCredential(t, c).Attributes)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, vcdmDcqlQuery(
		`"meta": {"type_values": [["`+vcdmVerifiableCredentialIri+`", "`+vcdmCredentialType+`"]]}`,
		[]any{"credentialSubject", "given_name"},
		[]any{"credentialSubject", "email"},
	))
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The verifier asked for two claims, but none is selectively disclosable, so
	// the plan shows the whole credentialSubject: what the verifier will receive.
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{{
			Owned: []expectedPlanCredential{{
				CredentialId:    vcdmCredentialId,
				Name:            vcdmCredentialName,
				IssuerName:      "Test Issuer",
				Attributes:      vcdmTestExpectedAttrs("Vera", "Modell", "vera@example.com", holderDid),
				IssuerVerified:  new(true),
				Format:          new(clientmodels.Format_SdJwtVcdm),
				HasIssuanceDate: new(true),
				HasExpiryDate:   new(false),
				Revoked:         new(false),
			}},
		}},
	})

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Equal(t, "RESPONSE_RECEIVED", result.Status)
	requireNoVeramoVcdmErrors(t, result)
	requireVerifierReceivedClaims(t, result, vcdmQueryId,
		claim([]any{"given_name"}, "Vera"),
		claim([]any{"family_name"}, "Modell"),
		claim([]any{"email"}, "vera@example.com"),
		claim([]any{"id"}, holderDid),
	)

	requireNewestDisclosureLogAttrs(t, c, vcdmCredentialId,
		vcdmTestExpectedAttrs("Vera", "Modell", "vera@example.com", holderDid))
}

func testVcdmQueryWithoutMetaMatches(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, vcdmDcqlQuery("", []any{"credentialSubject", "given_name"}))
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.NotNil(t, session.DisclosurePlan)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 1)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions, 1)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	require.Equal(t, vcdmCredentialId, cred.Credentials[0].CredentialId)
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	requireNoVeramoVcdmErrors(t, result)
}

func testVcdmTypeValuesMismatchOffersNoCandidate(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, vcdmDcqlQuery(
		`"meta": {"type_values": [["`+vcdmVerifiableCredentialIri+`", "SomeOtherCredential"]]}`,
		[]any{"credentialSubject", "given_name"},
	))
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireNoOwnedVcdmOption(t, session)
}

// The format isolation the CHANGELOG promises: a stored VCDM credential is
// never offered for a dc+sd-jwt query, even one naming its claims.
func testDcSdJwtQueryDoesNotOfferVcdmCredential(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, `{
		"dcql": {
			"credentials": [
				{
					"id": "sdjwt",
					"format": "dc+sd-jwt",
					"claims": [
						{ "path": ["credentialSubject", "given_name"] }
					]
				}
			]
		}
	}`)
	startOpenID4VPDisclosureSession(t, c, 2, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireNoOwnedVcdmOption(t, session)
}

func testVcdmAndSdJwtVcInOneRequest(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	issueCredentialViaOpenID4VCI(t, c, 1, sessionHandler, vcdmCredentialConfigId, vcdmTestClaims)
	issueCredentialViaOpenID4VCI(t, c, 2, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Test",
		"family_name": "User",
		"email": "test@example.com"
	}`)
	holderDid := vcdmHolderDid(t, requireSingleVcdmCredential(t, c).Attributes)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, `{
		"dcql": {
			"credentials": [
				{
					"id": "`+vcdmQueryId+`",
					"format": "vc+sd-jwt",
					"meta": {"type_values": [["`+vcdmVerifiableCredentialIri+`", "`+vcdmCredentialType+`"]]},
					"claims": [
						{ "path": ["credentialSubject", "given_name"] }
					]
				},
				{
					"id": "test-credential",
					"format": "dc+sd-jwt",
					"meta": {"vct_values": ["https://localhost:8443/vct/test"]},
					"claims": [
						{ "path": ["email"] }
					]
				}
			]
		}
	}`)
	startOpenID4VPDisclosureSession(t, c, 3, veramoSession.RequestUri)

	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.NotNil(t, session.DisclosurePlan)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 2)

	var choices []clientmodels.DisclosureDisconSelection
	for _, pickOne := range session.DisclosurePlan.DisclosureChoicesOverview {
		require.Len(t, pickOne.OwnedOptions, 1)
		choices = append(choices, makeDisclosureChoice(pickOne.OwnedOptions[0]))
	}
	grantPermission(t, c, session.Id, choices...)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Equal(t, "RESPONSE_RECEIVED", result.Status)
	requireNoVeramoVcdmErrors(t, result)
	requireVerifierReceivedClaims(t, result, vcdmQueryId,
		claim([]any{"given_name"}, "Vera"),
		claim([]any{"family_name"}, "Modell"),
		claim([]any{"email"}, "vera@example.com"),
		claim([]any{"id"}, holderDid),
	)
	requireVerifierReceivedClaims(t, result, "test-credential",
		claim([]any{"email"}, "test@example.com"),
	)
}

// ---------------------------------------------------------------------------
// VCDM disclosure helpers
// ---------------------------------------------------------------------------

// vcdmDcqlQuery builds a create-dcql-offer body with a single vc+sd-jwt query.
// meta is the raw `"meta": {...}` member, or empty for none.
func vcdmDcqlQuery(meta string, claimPaths ...[]any) string {
	claims := ""
	for i, path := range claimPaths {
		if i > 0 {
			claims += ","
		}
		pathJson, _ := json.Marshal(path)
		claims += fmt.Sprintf(`{"path": %s}`, pathJson)
	}
	if meta != "" {
		meta += ","
	}
	return fmt.Sprintf(`{
		"dcql": {
			"credentials": [
				{
					"id": %q,
					"format": "vc+sd-jwt",
					%s
					"claims": [%s]
				}
			]
		}
	}`, vcdmQueryId, meta, claims)
}

// veramoVcdmErrorCodes are the veramo verifier message codes that mean a
// vc+sd-jwt presentation was rejected. Its other messages are informational.
// VCDM2 is left out: veramo uses it both for the "formatted according to VCDM2"
// notice and for a credential without credentialSubject, and the latter leaves
// no claims, which requireVerifierReceivedClaims catches.
var veramoVcdmErrorCodes = map[string]struct{}{
	"INVALID_PRESENTATION": {},
	"INVALID_JWT":          {},
	"VC_ERROR":             {},
	"NBF_ERROR":            {},
	"IAT_ERROR":            {},
	"EXP_ERROR":            {},
	"NO_CREDENTIALS_FOUND": {},
	"INVALID_RESPONSE":     {},
	"INVALID_STATE":        {},
}

func requireNoVeramoVcdmErrors(t *testing.T, result veramoCheckResult) {
	t.Helper()
	require.NotNil(t, result.Result, "verifier result should not be nil")
	for _, msg := range result.Result.Messages {
		_, isError := veramoVcdmErrorCodes[msg.Code]
		require.False(t, isError, "verifier rejected the presentation: %s: %s", msg.Code, msg.Message)
	}
}

// requireNoOwnedVcdmOption asserts the wallet offers no stored VCDM credential
// for the request.
func requireNoOwnedVcdmOption(t *testing.T, session clientmodels.SessionState) {
	t.Helper()
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.NotNil(t, session.DisclosurePlan)
	for _, pickOne := range session.DisclosurePlan.DisclosureChoicesOverview {
		for _, bundle := range pickOne.OwnedOptions {
			for _, cred := range bundle.Credentials {
				require.NotEqual(t, vcdmCredentialId, cred.CredentialId, "VCDM credential should not be offered")
			}
		}
	}
}
