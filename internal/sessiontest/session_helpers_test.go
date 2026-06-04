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

// testingT is a minimal testing interface that our assertion helpers accept.
// Both *testing.T and fakeT (for failure tests) satisfy this interface.
type testingT interface {
	Errorf(format string, args ...interface{})
	FailNow()
	Helper()
}

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
	sessionId int,
	request *irma.IssuanceRequest,
) {
	// delete keyshare session token so the pin is required
	c.DeleteKeyshareTokens()
	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, request)

	c.NewSession(sessionId, sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, session.Protocol, clientmodels.Protocol_Irma)
	require.Equal(t, session.Status, clientmodels.Status_RequestPermission)
	require.Equal(t, session.Type, clientmodels.Type_Issuance)
	require.Equal(t, session.Id, sessionId)
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
	require.Equal(t, session.Id, sessionId)

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
	require.Equal(t, session.Id, sessionId)
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
	sessionId int,
	req *irma.IssuanceRequest,
) {
	issRequest := startSameDeviceIrmaSessionAtServer(t, irmaServer, req)
	c.NewSession(sessionId, issRequest)
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

// pk is a shorthand for building a ClaimPathKey from path components.
// pk("email") → "[email]", pk("address", "street") → "[address street]"
func pk(components ...any) string {
	return clientmodels.ClaimPathKey(components)
}

// attributeMap builds a map from the serialized full ClaimPath to the Attribute.
func attributeMap(attrs []clientmodels.Attribute) map[string]clientmodels.Attribute {
	m := make(map[string]clientmodels.Attribute, len(attrs))
	for _, a := range attrs {
		m[clientmodels.ClaimPathKey(a.ClaimPath)] = a
	}
	return m
}

// expectedAttr describes an expected attribute with its full claim path,
// display name, optional description, and typed value.
type expectedAttr struct {
	Path           []any
	DisplayName    *clientmodels.TranslatedString
	Description    *clientmodels.TranslatedString // nil to skip description check
	Value          *clientmodels.AttributeValue   // nil means section header (asserts actual is nil)
	RequestedValue *clientmodels.AttributeValue   // nil to skip check
}

// strVal creates a string AttributeValue.
func strVal(s string) *clientmodels.AttributeValue {
	return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_String, String: &s}
}

// boolVal creates a boolean AttributeValue.
func boolVal(b bool) *clientmodels.AttributeValue {
	return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Bool, Bool: &b}
}

// intVal creates an integer AttributeValue.
func intVal(i int64) *clientmodels.AttributeValue {
	return &clientmodels.AttributeValue{Type: clientmodels.AttributeType_Int, Int: &i}
}

// header creates an expectedAttr for a section header (Value == nil).
func header(path []any, displayName clientmodels.TranslatedString) expectedAttr {
	return expectedAttr{
		Path:        path,
		DisplayName: &displayName,
	}
}

// requireAttrsInOrder asserts that the given attributes match the expected list
// exactly — same order, same paths, same values, same length. When display names
// are specified, those are checked too.
func requireAttrsInOrder(t testingT, attrs []clientmodels.Attribute, expected ...expectedAttr) {
	t.Helper()
	require.Len(t, attrs, len(expected), "attribute count mismatch")
	for i, exp := range expected {
		actual := attrs[i]
		pathKey := clientmodels.ClaimPathKey(exp.Path)
		require.Equal(t, pathKey, clientmodels.ClaimPathKey(actual.ClaimPath),
			"attribute %d path mismatch", i)
		if exp.Value != nil {
			require.NotNil(t, actual.Value, "attribute %d (%s) should have a value", i, pathKey)
			require.Equal(t, exp.Value.Type, actual.Value.Type,
				"attribute %d (%s) value type mismatch", i, pathKey)
			require.Equal(t, exp.Value, actual.Value,
				"attribute %d (%s) value mismatch", i, pathKey)
		} else {
			require.Nil(t, actual.Value,
				"attribute %d (%s) should be a section header (nil value)", i, pathKey)
		}
		if exp.DisplayName != nil {
			require.NotNil(t, actual.DisplayName,
				"attribute %d (%s) should have a display name", i, pathKey)
			for locale, expectedName := range *exp.DisplayName {
				actualName, ok := (*actual.DisplayName)[locale]
				require.True(t, ok, "attribute %d (%s) should have display name for locale %q",
					i, pathKey, locale)
				require.Equal(t, expectedName, actualName,
					"attribute %d (%s) display name [%s] mismatch", i, pathKey, locale)
			}
		} else {
			require.Nil(t, actual.DisplayName,
				"attribute %d (%s) should have nil display name (array item)", i, pathKey)
		}
		if exp.Description != nil {
			require.NotNil(t, actual.Description,
				"attribute %d (%s) should have a description", i, pathKey)
			for locale, expectedDesc := range *exp.Description {
				actualDesc, ok := (*actual.Description)[locale]
				require.True(t, ok, "attribute %d (%s) should have description for locale %q",
					i, pathKey, locale)
				require.Equal(t, expectedDesc, actualDesc,
					"attribute %d (%s) description [%s] mismatch", i, pathKey, locale)
			}
		}
		if exp.RequestedValue != nil {
			require.NotNil(t, actual.RequestedValue,
				"attribute %d (%s) should have a requested value", i, pathKey)
			require.Equal(t, exp.RequestedValue.Type, actual.RequestedValue.Type,
				"attribute %d (%s) requested value type mismatch", i, pathKey)
			require.Equal(t, exp.RequestedValue, actual.RequestedValue,
				"attribute %d (%s) requested value mismatch", i, pathKey)
		}
	}
}

// requireNewestDisclosureLogAttrs loads the newest logs and asserts that the
// most recent disclosure log entry's credential (matched by credentialId)
// has attributes equal to expected — same shape as requireAttrsInOrder. Used
// to verify that the persisted disclosure log mirrors the disclosure-plan UI.
func requireNewestDisclosureLogAttrs(t testingT, c *client.Client, credentialId string, expected []expectedAttr) {
	t.Helper()
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	var matched *clientmodels.LogCredential
	for i := range logs {
		if logs[i].Type != clientmodels.LogType_Disclosure || logs[i].DisclosureLog == nil {
			continue
		}
		for j := range logs[i].DisclosureLog.Credentials {
			cred := &logs[i].DisclosureLog.Credentials[j]
			if cred.CredentialId == credentialId {
				matched = cred
				break
			}
		}
		if matched != nil {
			break
		}
	}
	require.NotNil(t, matched, "expected disclosure log entry for credential %q", credentialId)
	requireAttrsInOrder(t, matched.Attributes, expected...)
}

// findAttr finds the first attribute with the given claim path in the slice.
func findAttr(attrs []clientmodels.Attribute, path ...any) *clientmodels.Attribute {
	key := clientmodels.ClaimPathKey(path)
	for i := range attrs {
		if clientmodels.ClaimPathKey(attrs[i].ClaimPath) == key {
			return &attrs[i]
		}
	}
	return nil
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

// singleCredBundles wraps each credential as a single-credential bundle.
// Use for test fixtures whose discons are single-cred-per-con (the common
// case) — that's most existing fixtures.
func singleCredBundles(creds ...*clientmodels.SelectableCredentialInstance) []*clientmodels.DisclosureBundle {
	if len(creds) == 0 {
		return nil
	}
	out := make([]*clientmodels.DisclosureBundle, len(creds))
	for i, c := range creds {
		out[i] = &clientmodels.DisclosureBundle{
			Credentials: []*clientmodels.SelectableCredentialInstance{c},
		}
	}
	return out
}

// makeDisclosureChoice creates a DisclosureDisconSelection that discloses all
// attributes of every credential in the given bundle.
func makeDisclosureChoice(bundle *clientmodels.DisclosureBundle) clientmodels.DisclosureDisconSelection {
	creds := make([]clientmodels.SelectedCredential, 0, len(bundle.Credentials))
	for _, option := range bundle.Credentials {
		var paths [][]any
		for _, attr := range option.Attributes {
			if attr.Value == nil {
				continue // skip section headers
			}
			paths = append(paths, attr.ClaimPath)
		}
		creds = append(creds, clientmodels.SelectedCredential{
			CredentialId:   option.CredentialId,
			CredentialHash: option.Hash,
			AttributePaths: paths,
		})
	}
	return clientmodels.DisclosureDisconSelection{Credentials: creds}
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

func startOpenID4VCISession(t *testing.T, c *client.Client, sessionId int, credOfferURL string) {
	t.Helper()
	sessionReq, err := json.Marshal(client.SessionRequestData{
		Qr:                    irma.Qr{URL: credOfferURL},
		Protocol:              clientmodels.Protocol_OpenID4VCI,
		OpenID4VCIRedirectUri: "https://open.yivi.app/-/auth-callback",
	})
	require.NoError(t, err)
	c.NewSession(sessionId, string(sessionReq))
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

type openid4vciOfferResponse struct {
	URI    string `json:"uri"`
	ID     string `json:"id"`
	TxCode string `json:"txCode"`
}

func createPreAuthOffer(t *testing.T) openid4vciOfferResponse {
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

// createPostIssuanceVctPreAuthOffer creates an offer for
// PostIssuanceVctTestCredentialSdJwt. Veramo serves vct:"unknown" for this
// credential's issuer metadata (because its `extends` target doesn't match
// any VCT entry), but signs the actual VCT URL into the issued JWT. The
// wallet is therefore forced through the post-issuance type-metadata
// resolution path rather than offer-time resolution.
func createPostIssuanceVctPreAuthOffer(t *testing.T) openid4vciOfferResponse {
	t.Helper()
	return postOffer(t, preAuthIssuerURL, preAuthAdminToken, `{
		"credentials": ["PostIssuanceVctTestCredentialSdJwt"],
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

// createVctMetadataPreAuthOffer creates an offer for VctMetadataTestCredentialSdJwt,
// a credential whose issuer config advertises a fetchable `vct` URL pointing to
// a SD-JWT VC type-metadata document with display strings that differ from the
// OID4VCI credential_metadata block. Used to verify the wallet's preference for
// type-metadata over credential_metadata.
func createVctMetadataPreAuthOffer(t *testing.T) openid4vciOfferResponse {
	t.Helper()
	return postOffer(t, preAuthIssuerURL, preAuthAdminToken, `{
		"credentials": ["VctMetadataTestCredentialSdJwt"],
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

func createPreAuthOfferWithTxCode(t *testing.T) openid4vciOfferResponse {
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

func createAuthCodeOffer(t *testing.T) openid4vciOfferResponse {
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

func postOffer(t *testing.T, issuerURL, adminToken, body string) openid4vciOfferResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, issuerURL+"/api/create-offer", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "create-offer should succeed")

	var result openid4vciOfferResponse
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
