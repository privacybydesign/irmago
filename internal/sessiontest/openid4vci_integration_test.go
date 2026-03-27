package sessiontest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

	preAuthIssuerURL  = openid4vciIssuerBaseURL + "/test-issuer"
	preAuthAdminToken = "test-admin-token"

	authcodeIssuerURL  = openid4vciIssuerBaseURL + "/authcode-issuer"
	authcodeAdminToken = "authcode-admin-token"

	mockAuthorizationServerURL = "http://localhost:9090"
)

func TestOpenID4VCISessionHandler(t *testing.T) {
	waitForIssuer(t, preAuthIssuerURL, 60*time.Second)

	t.Run("pre-authorized code flow", func(t *testing.T) {
		t.Run("reaches permission request", testOpenId4VciPreAuthFlowReachesPermission)
		t.Run("grants permission and exchanges token", testOpenId4VciPreAuthFlowGrantsPermissionAndExchangesToken)
		t.Run("can be dismissed", testOpenId4VciPreAuthFlowCanBeDismissed)
	})

	waitForIssuer(t, authcodeIssuerURL, 30*time.Second)
	waitForIssuer(t, mockAuthorizationServerURL, 30*time.Second)

	t.Run("authorization code flow", func(t *testing.T) {
		t.Run("reaches auth request", testOpenId4VciAuthCodeFlowReachesAuthRequest)
		t.Run("grants permission and exchanges token", testOpenId4VciAuthCodeFlowGrantsPermissionAndExchangesToken)
		t.Run("can be dismissed", testOpenId4VciAuthCodeFlowCanBeDismissed)
	})
}

// ---------------------------------------------------------------------------
// Pre-authorized code flow tests
// ---------------------------------------------------------------------------

func testOpenId4VciPreAuthFlowReachesPermission(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, irmaclient.Protocol_OpenID4VCI, session.Protocol)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPreAuthorizedCode)
}

func testOpenId4VciPreAuthFlowGrantsPermissionAndExchangesToken(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)
	fmt.Printf("offer: %v\n", offer)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_PreAuthorizedCode,
		Payload:   client.SessionPreAuthorizedCodeInteractionPayload{Proceed: true},
	})

	// The test issuer uses did:web, so full credential verification should work.
	session = awaitSessionState(t, sessionHandler)
	fmt.Printf("error: %v\n", session.Error)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPermission)

	status := checkOfferStatus(t, preAuthIssuerURL, preAuthAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status,
		"server should have issued the credential via pre-authorized code flow")
}

func testOpenId4VciPreAuthFlowCanBeDismissed(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createPreAuthOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 30*time.Second)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_DismissSession,
	})

	session = awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	requireSessionState(t, session, 1, client.Type_Issuance, client.Status_Dismissed)
}

// ---------------------------------------------------------------------------
// Authorization code flow tests
// ---------------------------------------------------------------------------

func testOpenId4VciAuthCodeFlowReachesAuthRequest(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitStatus(t, sessionHandler, client.Status_RequestAuthorizationCode)

	require.Equal(t, irmaclient.Protocol_OpenID4VCI, session.Protocol)
	require.Equal(t, client.Type_Issuance, session.Type)
	require.NotEmpty(t, session.AuthorizationRequestUrl, "authorization request URL should be set")
}

func testOpenId4VciAuthCodeFlowGrantsPermissionAndExchangesToken(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitStatus(t, sessionHandler, client.Status_RequestAuthorizationCode)

	// Simulate the wallet visiting the authorization URL and getting a code.
	authCode := getAuthorizationCode(t, session.AuthorizationRequestUrl)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_AuthorizationCode,
		Payload: client.SessionAuthCodeInteractionPayload{
			Proceed: true,
			Code:    &authCode,
		},
	})

	// The authcode issuer uses did:web, so full credential verification should work.
	_ = awaitWithTimeout(t, sessionHandler.SessionChan, 30*time.Second)
	status := checkOfferStatus(t, authcodeIssuerURL, authcodeAdminToken, offer.ID)
	require.Equal(t, "CREDENTIAL_ISSUED", status,
		"server should have issued the credential via authorization code flow")
}

func testOpenId4VciAuthCodeFlowCanBeDismissed(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	offer := createAuthCodeOffer(t)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitStatus(t, sessionHandler, client.Status_RequestAuthorizationCode)

	userInteraction(t, c, client.SessionUserInteraction{
		SessionId: session.Id,
		Type:      client.UI_DismissSession,
	})

	session = awaitStatus(t, sessionHandler, client.Status_Dismissed)
	require.Equal(t, client.Type_Issuance, session.Type)
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------

func startOpenID4VCISession(t *testing.T, c *client.Client, credOfferURL string) {
	t.Helper()
	sessionReq, err := json.Marshal(client.SessionRequestData{
		Qr:       irma.Qr{URL: credOfferURL},
		Protocol: irmaclient.Protocol_OpenID4VCI,
	})
	require.NoError(t, err)
	c.NewSession(string(sessionReq))
}

// awaitStatus drains the session channel until a state with the expected status arrives.
// Intermediate states are skipped. Errors cause an immediate test failure.
func awaitStatus(t *testing.T, handler *MockSessionHandler, expected client.SessionStatus) client.SessionState {
	t.Helper()
	timeout := time.After(30 * time.Second)
	for {
		select {
		case session := <-handler.SessionChan:
			if session.Status == expected {
				return session
			}
			if session.Status == client.Status_Error {
				t.Fatalf("session errored while waiting for %q: %+v", expected, session.Error)
			}
		case <-timeout:
			t.Fatalf("timed out waiting for session status %q", expected)
		}
	}
}

// getAuthorizationCode simulates the wallet visiting the authorization URL and
// receiving a code from the mock authorization server.
func getAuthorizationCode(t *testing.T, authorizationRequestURL string) string {
	t.Helper()

	// The authorization URL uses the external URL from the issuer metadata
	// (http://localhost:9090/authorize?...). We can call it directly from the host.
	parsed, err := url.Parse(authorizationRequestURL)
	require.NoError(t, err)

	authorizeURL := mockAuthorizationServerURL + "/authorize?" + parsed.RawQuery
	resp, err := http.Get(authorizeURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.NotEmpty(t, result.Code)
	return result.Code
}

// ---------------------------------------------------------------------------
// Issuer admin helpers
// ---------------------------------------------------------------------------

type oid4vciOfferResponse struct {
	URI    string `json:"uri"`
	ID     string `json:"id"`
	TxCode string `json:"txCode"`
}

func createPreAuthOffer(t *testing.T) oid4vciOfferResponse {
	t.Helper()
	return postOffer(t, preAuthIssuerURL, preAuthAdminToken, `{
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
	}`)
}

func createAuthCodeOffer(t *testing.T) oid4vciOfferResponse {
	t.Helper()
	return postOffer(t, authcodeIssuerURL, authcodeAdminToken, `{
		"credentials": ["TestCredentialSdJwt"],
		"grants": {
			"authorization_code": {
				"issuer_state": "generate"
			}
		},
		"credentialDataSupplierInput": {
			"given_name": "Test",
			"family_name": "AuthCode",
			"email": "authcode@example.com"
		}
	}`)
}

func postOffer(t *testing.T, issuerURL, adminToken, body string) oid4vciOfferResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, issuerURL+"/api/create-offer", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

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

func checkOfferStatus(t *testing.T, issuerURL, adminToken, offerID string) string {
	t.Helper()
	body := fmt.Sprintf(`{"id": %q}`, offerID)
	req, err := http.NewRequest(http.MethodPost, issuerURL+"/api/check-offer", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
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

// ---------------------------------------------------------------------------
// Infrastructure helpers
// ---------------------------------------------------------------------------

func waitForIssuer(t *testing.T, baseURL string, timeout time.Duration) {
	t.Helper()
	wellKnown := baseURL + "/.well-known/openid-credential-issuer"
	// For the mock authorization server, use the discovery endpoint instead.
	if !strings.Contains(baseURL, "8880") {
		wellKnown = baseURL + "/.well-known/openid-configuration"
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(wellKnown)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("service not reachable at %s after %s", wellKnown, timeout)
}
