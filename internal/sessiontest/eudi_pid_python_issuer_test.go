package sessiontest

import (
	"encoding/base64"
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
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// EUDI Python PID issuer tests
//
// These tests exercise the OID4VCI issuance and OID4VP disclosure path for a
// credential whose `vct` is a non-URL identifier — concretely
// `urn:eudi:pid:1` — emitted by the EUDI reference Python PID issuer
// (eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py, pinned to
// v0.9.4 in docker-compose.yml).
//
// The default veramo-agent (used by the other openid4vci_*_test.go tests)
// always derives `vct` from `baseUrl + path`, so it cannot emit non-URL vcts.
// These tests cover the same end-to-end shape against an issuer that can.
// ============================================================================

const (
	eudiPidIssuerPyURL                   = "https://localhost:8443/eudi-pid-issuer-py"
	eudiPidIssuerPyCredentialConfigID    = "eu.europa.ec.eudi.pid_vc_sd_jwt"
	eudiPidIssuerPyVct                   = "urn:eudi:pid:1"
	eudiPidIssuerPyDisplayNameEN         = "PID (SD-JWT VC)"
	eudiPidIssuerPyOpenID4VPVerifierHost = "http://localhost:8089" // existing eudi_openid4vp service
)

// testSessionHandlerForEudiPidPythonIssuer is the test entrypoint registered in
// session_handler_test.go. It groups all subtests that depend on the Python
// PID issuer service being up.
func testSessionHandlerForEudiPidPythonIssuer(t *testing.T) {
	t.Run("issues PID with non-URL vct", testEudiPidPythonIssuerIssuesPidWithNonUrlVct)
	t.Run("discloses PID subset to veramo verifier", testEudiPidPythonIssuerDisclosesToVeramoVerifier)
	t.Run("discloses PID subset to EUDI Kotlin verifier", testEudiPidPythonIssuerDisclosesToEudiKotlinVerifier)
}

// ----------------------------------------------------------------------------
// Subtests
// ----------------------------------------------------------------------------

func testEudiPidPythonIssuerIssuesPidWithNonUrlVct(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidViaPythonIssuer(t, c, sessionHandler, samplePidUserData())

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findCredentialByName(t, creds, "en", eudiPidIssuerPyDisplayNameEN)
	require.NotNil(t, cred, "issued PID credential should appear in GetCredentials")

	// The stored credential's id must be exactly the non-URL vct emitted
	// by the issuer — this is what the test is here to prove.
	require.Equal(t, eudiPidIssuerPyVct, cred.CredentialId,
		"stored credential id must be the non-URL vct")

	// The Python issuer fills `date_of_issuance` with the current date and
	// `date_of_expiry` with +`countries.<x>.validity` days (90 in our config).
	today := time.Now().UTC().Format("2006-01-02")
	expiry := time.Now().UTC().Add(90 * 24 * time.Hour).Format("2006-01-02")

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{Path: []any{"family_name"}, DisplayName: &clientmodels.TranslatedString{"en": "Family Name(s)"}, Value: strVal("Doe")},
		expectedAttr{Path: []any{"given_name"}, DisplayName: &clientmodels.TranslatedString{"en": "Given Name(s)"}, Value: strVal("Jane")},
		expectedAttr{Path: []any{"birthdate"}, DisplayName: &clientmodels.TranslatedString{"en": "Birth Date"}, Value: strVal("1990-05-19")},
		expectedAttr{Path: []any{"place_of_birth"}, DisplayName: &clientmodels.TranslatedString{"en": "Birth Place"}, Value: strVal("")},
		expectedAttr{Path: []any{"nationalities"}, DisplayName: &clientmodels.TranslatedString{"en": "Nationalities"}, Value: strVal("")},
		header([]any{"address"}, clientmodels.TranslatedString{"en": "Address"}),
		expectedAttr{Path: []any{"address", "street_address"}, DisplayName: &clientmodels.TranslatedString{"en": "Street"}, Value: strVal("")},
		expectedAttr{Path: []any{"address", "locality"}, DisplayName: &clientmodels.TranslatedString{"en": "Locality"}, Value: strVal("")},
		expectedAttr{Path: []any{"address", "region"}, DisplayName: &clientmodels.TranslatedString{"en": "Region"}, Value: strVal("")},
		expectedAttr{Path: []any{"address", "postal_code"}, DisplayName: &clientmodels.TranslatedString{"en": "Postal Code"}, Value: strVal("")},
		expectedAttr{Path: []any{"address", "country"}, DisplayName: &clientmodels.TranslatedString{"en": "Country"}, Value: strVal("")},
		expectedAttr{Path: []any{"address", "formatted"}, DisplayName: &clientmodels.TranslatedString{"en": "Full Address"}, Value: strVal("")},
		expectedAttr{Path: []any{"address", "house_number"}, DisplayName: &clientmodels.TranslatedString{"en": "House Number"}, Value: strVal("")},
		expectedAttr{Path: []any{"personal_administrative_number"}, DisplayName: &clientmodels.TranslatedString{"en": "Personal Administrative Number"}, Value: strVal("")},
		expectedAttr{Path: []any{"picture"}, DisplayName: &clientmodels.TranslatedString{"en": "Portrait Image"}, Value: strVal("")},
		expectedAttr{Path: []any{"birth_family_name"}, DisplayName: &clientmodels.TranslatedString{"en": "Birth Family Name(s)"}, Value: strVal("")},
		expectedAttr{Path: []any{"birth_given_name"}, DisplayName: &clientmodels.TranslatedString{"en": "Birth Given Name(s)"}, Value: strVal("")},
		expectedAttr{Path: []any{"sex"}, DisplayName: &clientmodels.TranslatedString{"en": "Sex"}, Value: strVal("")},
		expectedAttr{Path: []any{"email_address"}, DisplayName: &clientmodels.TranslatedString{"en": "Email Address"}, Value: strVal("")},
		expectedAttr{Path: []any{"mobile_phone_number"}, DisplayName: &clientmodels.TranslatedString{"en": "Mobile Phone Number"}, Value: strVal("")},
		expectedAttr{Path: []any{"date_of_issuance"}, DisplayName: &clientmodels.TranslatedString{"en": "Issuance Date"}, Value: strVal(today)},
		expectedAttr{Path: []any{"date_of_expiry"}, DisplayName: &clientmodels.TranslatedString{"en": "Expiry Date"}, Value: strVal(expiry)},
		expectedAttr{Path: []any{"issuing_authority"}, DisplayName: &clientmodels.TranslatedString{"en": "Issuance Authority"}, Value: strVal("Test PID issuer")},
		expectedAttr{Path: []any{"document_number"}, DisplayName: &clientmodels.TranslatedString{"en": "Document Number"}, Value: strVal("")},
		expectedAttr{Path: []any{"trust_anchor"}, DisplayName: &clientmodels.TranslatedString{"en": "Trust Anchor"}, Value: strVal("")},
		expectedAttr{Path: []any{"issuing_country"}, DisplayName: &clientmodels.TranslatedString{"en": "Issuing Country"}, Value: strVal("FC")},
		expectedAttr{Path: []any{"issuing_jurisdiction"}, DisplayName: &clientmodels.TranslatedString{"en": "Issuing Jurisdiction"}, Value: strVal("")},
	)
}

func testEudiPidPythonIssuerDisclosesToVeramoVerifier(t *testing.T) {
	// The EUDI Python issuer signs SD-JWTs using an X.509 chain (x5c header).
	// The veramo-verifier (eduwallet/veramo-verifier v1.6.0) resolves the SD-JWT
	// signing key only via did:web/did:jwk/did:key or `kid`/`jwk` headers — it
	// has no x5c support. As a result the verifier returns INVALID_SDJWT with
	// "could not determine signing key of SD-JWT". This is independent of the
	// non-URL vct path under test. The Kotlin verifier subtest covers the
	// disclosure side end-to-end.
	t.Skip("veramo-verifier v1.6.0 does not support x5c-signed SD-JWTs; see comment")

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidViaPythonIssuer(t, c, sessionHandler, samplePidUserData())

	dcqlQuery := fmt.Sprintf(`{
		"dcql": {
			"credentials": [
				{
					"id": "pid",
					"format": "dc+sd-jwt",
					"meta": {
						"vct_values": [%q]
					},
					"claims": [
						{ "path": ["given_name"] },
						{ "path": ["family_name"] }
					]
				}
			]
		}
	}`, eudiPidIssuerPyVct)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, dcqlQuery)
	startOpenID4VPDisclosureSession(t, c, veramoSession.RequestUri)

	disclosureSession := awaitSessionState(t, sessionHandler)
	if disclosureSession.Status == clientmodels.Status_Error && disclosureSession.Error != nil {
		t.Fatalf("disclosure errored: %+v", disclosureSession.Error)
	}
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	chosen := disclosureSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, disclosureSession.Id, makeDisclosureChoice(chosen))

	disclosureSession = awaitSessionState(t, sessionHandler)
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	result := checkVeramoVerifierOfferStatus(t, veramoSession.State)
	require.Contains(t, []string{"VERIFIED", "RESPONSE_RECEIVED"}, result.Status)

	requireVerifierReceivedClaims(t, result, "pid",
		claim([]any{"given_name"}, "Jane"),
		claim([]any{"family_name"}, "Doe"),
	)
}

func testEudiPidPythonIssuerDisclosesToEudiKotlinVerifier(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issuePidViaPythonIssuer(t, c, sessionHandler, samplePidUserData())

	startReq := fmt.Sprintf(`{
		"type": "vp_token",
		"dcql_query": {
			"credentials": [
				{
					"id": "pid",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": [%q] },
					"claims": [
						{ "path": ["given_name"] },
						{ "path": ["family_name"] }
					]
				}
			]
		},
		"nonce": "nonce",
		"jar_mode": "by_reference",
		"request_uri_method": "post"
	}`, eudiPidIssuerPyVct)

	verifierSession, err := irmaclient.StartTestSessionAtEudiVerifier(eudiPidIssuerPyOpenID4VPVerifierHost, startReq)
	require.NoError(t, err)

	startOpenID4VPDisclosureSession(t, c, verifierSession.SessionLink)

	disclosureSession := awaitSessionState(t, sessionHandler)
	if disclosureSession.Status == clientmodels.Status_Error && disclosureSession.Error != nil {
		t.Fatalf("disclosure errored: %+v", disclosureSession.Error)
	}
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	chosen := disclosureSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, disclosureSession.Id, makeDisclosureChoice(chosen))

	disclosureSession = awaitSessionState(t, sessionHandler)
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse, err := irmaclient.GetWalletResponseFromEudiVerifier(verifierSession)
	require.NoError(t, err)
	require.NotNil(t, walletResponse, "EUDI verifier returned no wallet response")
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// createPidIssuerTestClient creates a client that trusts the test CA used by
// the EUDI Python PID issuer to sign credentials.
func createPidIssuerTestClient(t *testing.T) (*client.Client, *MockSessionHandler) {
	t.Helper()
	caPEM := readEudiPidIssuerPyCA(t)
	return createClientWithoutKeyshareEnrollment(t, caPEM)
}

// pidUserData is the JSON payload of user-supplied claims that the Python
// issuer embeds in the issued PID. Issuer-controlled claims
// (date_of_issuance, date_of_expiry, issuing_authority, issuing_country)
// are filled in by the issuer itself.
type pidUserData struct {
	FamilyName string `json:"family_name"`
	GivenName  string `json:"given_name"`
	Birthdate  string `json:"birthdate"`
}

func samplePidUserData() pidUserData {
	return pidUserData{
		FamilyName: "Doe",
		GivenName:  "Jane",
		Birthdate:  "1990-05-19",
	}
}

// issuePidViaPythonIssuer drives the full pre-authorized OID4VCI flow against
// the EUDI Python PID issuer: post an offer-request, parse the offer, accept
// the pre-auth code (with the tx_code embedded in the response), grant
// permission, and assert the session reaches Success.
func issuePidViaPythonIssuer(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	data pidUserData,
) {
	t.Helper()

	offer := createPidOfferViaPythonIssuer(t, data)

	startOpenID4VCISession(t, c, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
			Proceed:         true,
			TransactionCode: &offer.TxCode,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)
	require.Equal(t, eudiPidIssuerPyDisplayNameEN, session.OfferedCredentials[0].Name["en"])

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

// pidOfferResponse is what createPidOfferViaPythonIssuer returns to callers.
// The Python issuer's /credentialOfferReq2 returns the offer JSON itself
// (not a URL), and embeds the tx_code value in `grants.<grant>.tx_code.value`
// (a non-standard but useful-for-tests extension we read out here).
type pidOfferResponse struct {
	URI    string // openid-credential-offer://... reconstructed from the JSON
	TxCode string // value of grants[pre-authorized_code].tx_code.value
}

// createPidOfferViaPythonIssuer posts an unsigned-JWT-shaped request to the
// Python issuer's /credentialOfferReq2 endpoint. The endpoint decodes the
// payload without verifying the signature (see app/preauthorization.py in
// the upstream repo), so the header and signature segments can be empty.
func createPidOfferViaPythonIssuer(t *testing.T, data pidUserData) pidOfferResponse {
	t.Helper()

	requestPayload := map[string]any{
		"credentials": []map[string]any{
			{
				"credential_configuration_id": eudiPidIssuerPyCredentialConfigID,
				"data": map[string]any{
					"family_name": data.FamilyName,
					"given_name":  data.GivenName,
					"birthdate":   data.Birthdate,
				},
			},
		},
	}
	payloadJSON, err := json.Marshal(requestPayload)
	require.NoError(t, err)

	// Construct a JWT-shape "header.payload.signature" where header and
	// signature are empty objects/strings. The issuer only base64url-decodes
	// the payload segment.
	emptyHeader := base64.RawURLEncoding.EncodeToString([]byte("{}"))
	payloadSeg := base64.RawURLEncoding.EncodeToString(payloadJSON)
	jwtShape := emptyHeader + "." + payloadSeg + "."

	form := url.Values{}
	form.Set("request", jwtShape)

	req, err := http.NewRequest(http.MethodPost,
		eudiPidIssuerPyURL+"/credentialOfferReq2",
		strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"Python issuer /credentialOfferReq2 should accept the request")

	var offerJSON map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&offerJSON))

	txCode := extractTxCodeValue(t, offerJSON)
	offerBytes, err := json.Marshal(offerJSON)
	require.NoError(t, err)

	uri := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerBytes))
	return pidOfferResponse{URI: uri, TxCode: txCode}
}

func extractTxCodeValue(t *testing.T, offer map[string]any) string {
	t.Helper()
	grants, ok := offer["grants"].(map[string]any)
	require.True(t, ok, "credential offer missing grants")
	preAuth, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any)
	require.True(t, ok, "credential offer missing pre-authorized_code grant")
	tx, ok := preAuth["tx_code"].(map[string]any)
	if !ok {
		return ""
	}
	switch v := tx["value"].(type) {
	case string:
		return v
	case float64:
		// JSON unmarshals all numbers as float64. The Python issuer emits the
		// tx_code value as a JSON number; we render it back as a decimal string.
		return fmt.Sprintf("%d", int64(v))
	default:
		return ""
	}
}

func readEudiPidIssuerPyCA(t *testing.T) []byte {
	t.Helper()
	caPath := filepath.Join(testdataFolder, "eudi-pid-issuer-py", "certs", "ca.pem")
	caPEM, err := os.ReadFile(caPath)
	require.NoError(t, err)
	return caPEM
}
