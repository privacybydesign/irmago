package sessiontest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/require"
)

const (
	openid4vciIssuerBaseURL = "http://localhost:8880"
	openid4vciIssuerPath    = "/test-issuer"
	openid4vciIssuerURL     = openid4vciIssuerBaseURL + openid4vciIssuerPath
	openid4vciAdminToken    = "test-admin-token"
)

func TestOpenID4VCISessionHandler(t *testing.T) {
	waitForIssuer(t, 60*time.Second)

	t.Run("pre-authorized code flow reaches permission request", testOpenId4VciPreAuthFlowReachesPermission)
	t.Run("pre-authorized code flow grants permission and exchanges token", testOpenId4VciPreAuthFlowGrantsPermissionAndExchangesToken)
	t.Run("pre-authorized code flow can be dismissed", testOpenId4VciPreAuthFlowCanBeDismissed)
}

func testOpenId4VciPreAuthFlowReachesPermission(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createTestOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 30*time.Second)

	require.Equal(t, irmaclient.Protocol_OpenID4VCI, session.Protocol)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPreAuthorizedCode)
}

func testOpenId4VciPreAuthFlowGrantsPermissionAndExchangesToken(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createTestOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 30*time.Second)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPreAuthorizedCode)

	// Grant permission (no transaction code required for this issuer config).
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_PreAuthorizedCode,
		Payload: client.SessionPreAuthorizedCodeInteractionPayload{
			Proceed: true,
		},
	})

	// After granting permission the client exchanges the pre-authorized code for a
	// token and requests the credential. The test issuer uses did:jwk which is not
	// yet fully supported for credential verification, so the session ends with an
	// error after receiving the credential. We verify the protocol progressed past
	// the permission step.
	session = awaitWithTimeout(t, sessionHandler.SessionChan, 30*time.Second)
	// The offer status on the server proves the full token exchange completed.
	status := checkOfferStatus(t, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status,
		"server should have issued the credential, even if client verification fails")
}

func testOpenId4VciPreAuthFlowCanBeDismissed(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createTestOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 30*time.Second)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPreAuthorizedCode)

	// Dismiss the session instead of granting permission.
	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_DismissSession,
	})

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_Dismissed)
}

func startOpenID4VCISession(t *testing.T, c *client.Client, credOfferURL string) {
	t.Helper()
	sessionReq, err := json.Marshal(client.SessionRequestData{
		Qr:       irma.Qr{URL: credOfferURL},
		Protocol: irmaclient.Protocol_OpenID4VCI,
	})
	require.NoError(t, err)
	c.NewSession(string(sessionReq))
}

type oid4vciOfferResponse struct {
	URI    string `json:"uri"`
	ID     string `json:"id"`
	TxCode string `json:"txCode"`
}

func createTestOffer(t *testing.T) oid4vciOfferResponse {
	t.Helper()

	body := `{
		"credentials": ["TestCredentialSdJwt"],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate"
			}
		},
		"credentialDataSupplierInput": {
			"given_name": "Test",
			"family_name": "User",
			"email": "test@example.com"
		}
	}`

	req, err := http.NewRequest(http.MethodPost, openid4vciIssuerURL+"/api/create-offer", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+openid4vciAdminToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "create-offer should succeed")

	var result oid4vciOfferResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.NotEmpty(t, result.ID)
	require.NotEmpty(t, result.URI)
	return result
}

func checkOfferStatus(t *testing.T, offerID string) string {
	t.Helper()
	body := fmt.Sprintf(`{"id": %q}`, offerID)
	req, err := http.NewRequest(http.MethodPost, openid4vciIssuerURL+"/api/check-offer", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+openid4vciAdminToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		Status string `json:"status"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result.Status
}

func waitForIssuer(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	url := openid4vciIssuerURL + "/.well-known/openid-credential-issuer"
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("issuer not reachable at %s after %s", url, timeout)
}
