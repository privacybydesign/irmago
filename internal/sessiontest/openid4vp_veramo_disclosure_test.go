package sessiontest

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
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
	t.Run("issue via OID4VCI and disclose via OID4VP", testIssueViaOid4VciAndDiscloseViaOid4Vp)
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
	attrIds := make([]string, len(cred.Attributes))
	for i, attr := range cred.Attributes {
		attrIds[i] = attr.Id
	}
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred, attrIds...))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Step 5: Verify the verifier received the VP token.
	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Equal(t, "VERIFIED", result.Status,
		"verifier session should be VERIFIED after successful disclosure")
}

// ---------------------------------------------------------------------------
// Veramo verifier helpers
// ---------------------------------------------------------------------------

type veramoVerifierSession struct {
	State      string `json:"state"`
	RequestUri string `json:"requestUri"`
	CheckUri   string `json:"checkUri"`
}

type veramoAuthRequest struct {
	Nonce       string `json:"nonce"`
	ClientId    string `json:"client_id"`
	ResponseUri string `json:"response_uri"`
	State       string `json:"state"`
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

func fetchAuthorizationRequest(t *testing.T, state string) veramoAuthRequest {
	t.Helper()

	getOfferURL := fmt.Sprintf("%s/%s/get-offer/%s", veramoVerifierBaseURL, veramoVerifierName, state)
	resp, err := http.Get(getOfferURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "get-offer should succeed")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// The response is a signed JWT. Parse the payload without verifying the signature
	// (the verifier uses DID-based signing which we don't validate in this test).
	jwtToken := string(body)
	parts := strings.SplitN(jwtToken, ".", 3)
	require.Len(t, parts, 3, "auth request should be a valid JWT with 3 parts")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err, "JWT payload should be valid base64url")

	var authRequest veramoAuthRequest
	require.NoError(t, json.Unmarshal(payload, &authRequest), "JWT payload should be valid JSON")
	return authRequest
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

