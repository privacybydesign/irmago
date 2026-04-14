package sessiontest

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }

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

func intPtr(v int) *int { return &v }

// requireAttr asserts that the attribute map contains an attribute at the given
// claim path with the expected string value.
func requireAttr(t *testing.T, am map[string]clientmodels.Attribute, path []any, expectedValue string) {
	t.Helper()
	key := clientmodels.ClaimPathKey(path)
	attr, ok := am[key]
	require.True(t, ok, "attribute %s should exist", key)
	require.NotNil(t, attr.Value, "attribute %s should have a value", key)
	require.NotNil(t, attr.Value.String, "attribute %s should have a string value", key)
	require.Equal(t, expectedValue, *attr.Value.String, "attribute %s value mismatch", key)
}

// requireNoAttr asserts that the attribute map does NOT contain an attribute at the given claim path.
func requireNoAttr(t *testing.T, am map[string]clientmodels.Attribute, path []any) {
	t.Helper()
	key := clientmodels.ClaimPathKey(path)
	_, ok := am[key]
	require.False(t, ok, "attribute %s should not exist", key)
}

// expectedAttr describes an expected attribute with its full claim path,
// display name, optional description, and value.
type expectedAttr struct {
	Path        []any
	DisplayName clientmodels.TranslatedString
	Description *clientmodels.TranslatedString // nil to skip description check
	Value       string
}

// requireAttrsInOrder asserts that the given attributes match the expected list
// exactly — same order, same paths, same values, same length. When display names
// are specified, those are checked too.
func requireAttrsInOrder(t *testing.T, attrs []clientmodels.Attribute, expected ...expectedAttr) {
	t.Helper()
	require.Len(t, attrs, len(expected), "attribute count mismatch")
	for i, exp := range expected {
		actual := attrs[i]
		require.Equal(t, clientmodels.ClaimPathKey(exp.Path), clientmodels.ClaimPathKey(actual.ClaimPath),
			"attribute %d path mismatch", i)
		require.NotNil(t, actual.Value, "attribute %d should have a value", i)
		require.NotNil(t, actual.Value.String, "attribute %d should have a string value", i)
		require.Equal(t, exp.Value, *actual.Value.String,
			"attribute %d (%s) value mismatch", i, clientmodels.ClaimPathKey(exp.Path))
		require.NotNil(t, exp.DisplayName, "attribute %d (%s) expected DisplayName must be set",
			i, clientmodels.ClaimPathKey(exp.Path))
		for locale, expectedName := range exp.DisplayName {
			actualName, ok := actual.DisplayName[locale]
			require.True(t, ok, "attribute %d (%s) should have display name for locale %q",
				i, clientmodels.ClaimPathKey(exp.Path), locale)
			require.Equal(t, expectedName, actualName,
				"attribute %d (%s) display name [%s] mismatch", i, clientmodels.ClaimPathKey(exp.Path), locale)
		}
		if exp.Description != nil {
			require.NotNil(t, actual.Description,
				"attribute %d (%s) should have a description", i, clientmodels.ClaimPathKey(exp.Path))
			for locale, expectedDesc := range *exp.Description {
				actualDesc, ok := (*actual.Description)[locale]
				require.True(t, ok, "attribute %d (%s) should have description for locale %q",
					i, clientmodels.ClaimPathKey(exp.Path), locale)
				require.Equal(t, expectedDesc, actualDesc,
					"attribute %d (%s) description [%s] mismatch", i, clientmodels.ClaimPathKey(exp.Path), locale)
			}
		}
	}
}

// expectedDisclosedAttr describes an expected disclosed attribute in an IRMA
// server session result.
type expectedDisclosedAttr struct {
	Identifier string // e.g. "irma-demo.RU.studentCard.university"
	Value      string
}

// requireIrmaServerResult retrieves the session result from the IRMA server
// and asserts that the disclosed attributes match the expected list exactly.
// Each inner slice of expected corresponds to one disjunction in the result.
func requireIrmaServerResult(t *testing.T, irmaServer *IrmaServer, token irma.RequestorToken, expected [][]expectedDisclosedAttr) {
	t.Helper()
	result, err := irmaServer.irma.GetSessionResult(token)
	require.NoError(t, err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus, "proof should be valid")
	require.Len(t, result.Disclosed, len(expected), "number of disclosed disjunctions mismatch")

	for i, expDiscon := range expected {
		actualDiscon := result.Disclosed[i]
		require.Len(t, actualDiscon, len(expDiscon),
			"disjunction %d: number of disclosed attributes mismatch", i)
		for j, exp := range expDiscon {
			actual := actualDiscon[j]
			require.Equal(t, exp.Identifier, actual.Identifier.String(), "disjunction %d attribute %d identifier mismatch", i, j)
			require.Equal(t, irma.AttributeProofStatusPresent, actual.Status, "disjunction %d attribute %d should be present", i, j)
			require.NotNil(t, actual.RawValue, "disjunction %d attribute %d should have a raw value", i, j)
			require.Equal(t, exp.Value, *actual.RawValue, "disjunction %d attribute %d value mismatch", i, j)
		}
	}
}

// requireIrmaServerResultStatus retrieves the session result and checks
// the proof status without validating individual attributes.
func requireIrmaServerResultStatus(t *testing.T, irmaServer *IrmaServer, token irma.RequestorToken, expectedStatus irma.ServerStatus) {
	t.Helper()
	result, err := irmaServer.irma.GetSessionResult(token)
	require.NoError(t, err)
	require.Equal(t, expectedStatus, result.Status, "session status mismatch")
}

// makeDisclosureChoice creates a DisclosureDisconSelection that discloses all
// attributes of the given credential instance.
func makeDisclosureChoice(option *clientmodels.SelectableCredentialInstance) clientmodels.DisclosureDisconSelection {
	paths := make([][]any, len(option.Attributes))
	for i, attr := range option.Attributes {
		paths[i] = attr.ClaimPath
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
	openid4vciIssuerBaseURL = "https://localhost:8443"

	preAuthIssuerURL  = openid4vciIssuerBaseURL + "/test-issuer"
	preAuthAdminToken = "test-admin-token"

	authcodeIssuerURL  = openid4vciIssuerBaseURL + "/authcode-issuer"
	authcodeAdminToken = "authcode-admin-token"

	mockAuthorizationServerURL = "http://localhost:9090"
)

func init() {
	// Trust the self-signed localhost certificate used by the TLS proxy in Docker,
	// so test helpers can make HTTPS calls to the issuer and verifier admin APIs.
	certFile := filepath.Join(testdataFolder, "configurations", "certs", "localhost.crt")
	pem, err := os.ReadFile(certFile)
	if err != nil {
		return // cert not found; skip (e.g., running without TLS)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	pool.AppendCertsFromPEM(pem)
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
}

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
