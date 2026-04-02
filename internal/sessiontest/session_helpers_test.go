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
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

func userInteraction(t *testing.T, c *client.Client, interaction clientmodels.SessionUserInteraction) {
	go func() {
		require.NoError(
			t,
			c.HandleUserInteraction(interaction),
		)
	}()
}

func schemalessPerformIrmaIssuanceSession(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	irmaServer *IrmaServer,
	request *irma.IssuanceRequest,
) {
	// delete keyshare session token so the pin is required
	c.DeleteKeyshareTokens()
	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, clientmodels.Protocol_Irma)
	require.Equal(t, session.Status, clientmodels.Status_RequestPermission)
	require.Equal(t, session.Type, clientmodels.Type_Issuance)
	require.Equal(t, session.Id, 1)
	require.Len(t, session.OfferedCredentials, 1)

	// give issuance permission
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_Permission,
		Payload: clientmodels.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Protocol, clientmodels.Protocol_Irma)
	require.Equal(t, session.Status, clientmodels.Status_RequestPin)
	require.Equal(t, session.Type, clientmodels.Type_Issuance)
	require.Equal(t, session.Id, 1)

	// give pin
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_EnteredPin,
		Payload: clientmodels.PinInteractionPayload{
			Pin:     "12345",
			Proceed: true,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, session.Protocol, clientmodels.Protocol_Irma)
	require.Equal(t, session.Status, clientmodels.Status_Success)
	require.Equal(t, session.Type, clientmodels.Type_Issuance)
	require.Equal(t, session.Id, 1)
}

func awaitWithTimeout[T any](t *testing.T, channel chan T, timeout time.Duration) T {
	select {
	case msg := <-channel:
		return msg
	case <-time.After(timeout):
		require.Fail(t, "failed to await after %s", timeout)
	}
	// unreachable in theory
	var ret T
	return ret
}

type SessionIntegrationTest func(t *testing.T, irmaServer *IrmaServer, client *client.Client, handler *MockSessionHandler)

func runEudiSessionTest(t *testing.T, name string, test SessionIntegrationTest) {
	t.Run(name, func(t *testing.T) {
		irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
		defer irmaServer.Stop()

		keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
		defer keyshareServer.Stop()

		c, sessionHandler := createClient(t)
		defer c.Close()

		test(t, irmaServer, c, sessionHandler)
	})
}

func runSessionTest(t *testing.T, name string, test SessionIntegrationTest) {
	t.Run(name, func(t *testing.T) {
		conf := IrmaServerConfigurationWithTempStorage(t)
		irmaServer := StartIrmaServer(t, conf)
		defer irmaServer.Stop()

		keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
		defer keyshareServer.Stop()

		c, sessionHandler := createClient(t)
		defer c.Close()

		test(t, irmaServer, c, sessionHandler)
	})
}

func issue(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	req *irma.IssuanceRequest,
) {
	issRequest := startSameDeviceIrmaSessionAtServer(t, irmaServer, req)
	c.NewSession(issRequest)
	session := awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
	require.Equal(t, session.Status, clientmodels.Status_RequestPermission)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_Permission,
		Payload: clientmodels.SessionPermissionInteractionPayload{
			Granted: true,
		},
	})
}

func awaitSessionState(t *testing.T, sessionHandler *MockSessionHandler) clientmodels.SessionState {
	return awaitWithTimeout(t, sessionHandler.SessionChan, 10*time.Second)
}

// studentCardDisclosure returns a common disclosure request for student card university and level
func studentCardDisclosure() irma.AttributeConDisCon {
	return irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
		},
	}
}

// mijnOverheidDisclosure returns a common disclosure request for MijnOverheid fullName
func mijnOverheidDisclosure() irma.AttributeConDisCon {
	return irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}
}

// studentCardOrMijnOverheidDisclosure returns a disclosure with choice between student card and MijnOverheid
func studentCardOrMijnOverheidDisclosure() irma.AttributeConDisCon {
	return irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.level"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
		},
	}
}

// requireSessionState validates common session fields in a single call
func requireSessionState(
	t *testing.T,
	session clientmodels.SessionState,
	id int,
	sessionType clientmodels.SessionType,
	status clientmodels.SessionStatus,
) {
	t.Helper()
	require.Equal(t, id, session.Id)
	require.Equal(t, status, session.Status)
	require.Equal(t, sessionType, session.Type)
}

// requireRequestorInfo validates the standard test requestor info
func requireRequestorInfo(t *testing.T, session clientmodels.SessionState) {
	t.Helper()
	require.Equal(t, "test-requestors.test-requestor", session.Requestor.Id)
	require.Equal(t, clientmodels.TranslatedString{"nl": "Lokale IRMA server", "en": "Local IRMA server"}, session.Requestor.Name)
	require.True(t, session.Requestor.Verified)
}

// grantPermission sends a permission granted interaction with optional disclosure choices
func grantPermission(t *testing.T, c *client.Client, sessionId int, choices ...clientmodels.DisclosureDisconSelection) {
	t.Helper()
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: sessionId,
		Type:      clientmodels.UI_Permission,
		Payload: clientmodels.SessionPermissionInteractionPayload{
			Granted:           true,
			DisclosureChoices: choices,
		},
	})
}

// denyPermission sends a permission denied interaction
func denyPermission(t *testing.T, c *client.Client, sessionId int) {
	t.Helper()
	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: sessionId,
		Type:      clientmodels.UI_Permission,
		Payload: clientmodels.SessionPermissionInteractionPayload{
			Granted: false,
		},
	})
}

// makeDisclosureChoice creates a disclosure selection from an owned option
func intPtr(v int) *int { return &v }

func makeDisclosureChoice(option *clientmodels.SelectableCredentialInstance, attributeIds ...string) clientmodels.DisclosureDisconSelection {
	paths := make([][]any, len(attributeIds))
	for i, id := range attributeIds {
		paths[i] = []any{id}
	}
	return clientmodels.DisclosureDisconSelection{
		Credentials: []clientmodels.SelectedCredential{
			{
				CredentialId:   option.CredentialId,
				CredentialHash: option.Hash,
				AttributePaths: paths,
			},
		},
	}
}

// expectedPickOne describes the expected shape of a DisclosurePickOne entry.
type expectedPickOne struct {
	optional   bool
	owned      int
	obtainable int
}

// requireIssuanceSteps checks plan.IssueDuringDislosure.Steps.
// Each optionCount argument gives the expected number of Options for that step,
// and the total number of arguments must equal the expected number of steps.
func requireIssuanceSteps(t *testing.T, plan *clientmodels.DisclosurePlan, optionCounts ...int) {
	t.Helper()
	require.NotNil(t, plan.IssueDuringDislosure)
	require.Len(t, plan.IssueDuringDislosure.Steps, len(optionCounts))
	for i, count := range optionCounts {
		require.Len(t, plan.IssueDuringDislosure.Steps[i].Options, count)
	}
}

// requireDisclosureChoices checks plan.DisclosureChoicesOverview against expected values.
func requireDisclosureChoices(t *testing.T, plan *clientmodels.DisclosurePlan, expected ...expectedPickOne) {
	t.Helper()
	require.Len(t, plan.DisclosureChoicesOverview, len(expected))
	for i, exp := range expected {
		got := plan.DisclosureChoicesOverview[i]
		require.Equal(t, exp.optional, got.Optional)
		require.Len(t, got.OwnedOptions, exp.owned)
		require.Len(t, got.ObtainableOptions, exp.obtainable)
	}
}

const (
	openid4vciIssuerBaseURL = "http://localhost:8880"

	preAuthIssuerURL  = openid4vciIssuerBaseURL + "/test-issuer"
	preAuthAdminToken = "test-admin-token"

	authcodeIssuerURL  = openid4vciIssuerBaseURL + "/authcode-issuer"
	authcodeAdminToken = "authcode-admin-token"

	mockAuthorizationServerURL = "http://localhost:9090"
)

func startOpenID4VCISession(t *testing.T, c *client.Client, credOfferURL string) {
	t.Helper()
	sessionReq, err := json.Marshal(client.SessionRequestData{
		Qr:       irma.Qr{URL: credOfferURL},
		Protocol: clientmodels.Protocol_OpenID4VCI,
	})
	require.NoError(t, err)
	c.NewSession(string(sessionReq))
}

// getAuthorizationCode simulates the wallet visiting the authorization URL and
// receiving a code from the mock authorization server.
func getAuthorizationCode(t *testing.T, authorizationRequestURL string) string {
	t.Helper()

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

func createPreAuthOfferWithTxCode(t *testing.T) oid4vciOfferResponse {
	t.Helper()
	return postOffer(t, preAuthIssuerURL, preAuthAdminToken, `{
		"credentials": ["TestCredentialSdJwt"],
		"grants": {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": {
				"pre-authorized_code": "generate",
				"tx_code": {
					"input_mode": "numeric",
					"length": 6
				}
			}
		},
		"credentialDataSupplierInput": {
			"given_name": "Test",
			"family_name": "TxCode",
			"email": "txcode@example.com"
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
