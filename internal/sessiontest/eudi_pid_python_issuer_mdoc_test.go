package sessiontest

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// mso_mdoc issuance and disclosure against the EUDI Python issuer
//
// The mdoc-av tests in openid4vp_mdoc_av_disclosure_test.go seed a credential
// straight into storage, which leaves the whole OID4VCI half of the mdoc path
// — format parser, COSE algorithm validation, holder binding, batch storage —
// covered only by unit tests. These two subtests close that gap by issuing the
// credential from the reference issuer and then presenting what it issued.
//
// The issuer is the same eudi_pid_issuer_py container the SD-JWT tests use,
// with eu.europa.ec.eudi.age_verification_mdoc added to countries.FC's
// supported_credential_ids. It signs the MSO with the same issuer.key/issuer.der
// as its SD-JWTs; that certificate carries the ISO 18013-5 Annex B.1.2 document
// signer usage (1.0.18013.5.1.2), without which the wallet refuses it.
// ============================================================================

const (
	eudiPidIssuerPyAvCredentialConfigID = "eu.europa.ec.eudi.age_verification_mdoc"
	eudiPidIssuerPyAvDocType            = "eu.europa.ec.av.1"
)

// testSessionHandlerForEudiPidPythonIssuerMdoc is registered alongside the
// SD-JWT subtests in session_handler_test.go.
func testSessionHandlerForEudiPidPythonIssuerMdoc(t *testing.T) {
	t.Run("issues age verification mdoc", testEudiPidPythonIssuerIssuesAvMdoc)
	t.Run("discloses issued mdoc to EUDI Kotlin verifier", testEudiPidPythonIssuerDisclosesAvMdoc)
}

// ----------------------------------------------------------------------------
// Subtests
// ----------------------------------------------------------------------------

func testEudiPidPythonIssuerIssuesAvMdoc(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findMdocCredentialByDocType(t, creds, eudiPidIssuerPyAvDocType)

	// The stored credential type is the docType, taken from the signed MSO
	// rather than the offer or the unsigned envelope.
	require.Equal(t, eudiPidIssuerPyAvDocType, cred.CredentialId)
	require.Contains(t, cred.CredentialInstanceIds, clientmodels.Format_MsoMdoc,
		"the stored instance must be filed under the mso_mdoc format, which is what every format-keyed read depends on")
}

func testEudiPidPythonIssuerDisclosesAvMdoc(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	// The verifier validates the MSO's document signer chain against this
	// anchor, so it has to be the CA that signed the issuer's certificate —
	// nothing else in the request establishes who may issue this docType.
	startReq := createAvMdocAuthRequest(t)

	// Not eudiPidIssuerPyOpenID4VPVerifierHost (:8089) as the SD-JWT tests use:
	// that instance demands a relying-party registration certificate for
	// anything VERIFIER_ATTESTATIONCLASSIFICATIONS does not exempt, and it
	// decides the exemption on vct alone. An mso_mdoc query names its credential
	// with doctype_value, so it stays unclassified there whichever bucket the
	// docType is listed in, and the session is refused with
	// MissingRegistrationCertificate before the wallet is ever contacted.
	// :8090 is the instance the other mdoc test already runs against.
	verifierSession, err := StartTestSessionAtEudiVerifier(testdata.OpenID4VP_DirectPostJwt_Host, startReq)
	require.NoError(t, err)

	startOpenID4VPDisclosureSession(t, c, 2, verifierSession.SessionLink)

	disclosureSession := awaitSessionState(t, sessionHandler)
	if disclosureSession.Status == clientmodels.Status_Error && disclosureSession.Error != nil {
		t.Fatalf("disclosure errored: %+v", disclosureSession.Error)
	}
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	chosen := disclosureSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, disclosureSession.Id, makeDisclosureChoice(chosen))

	disclosureSession = awaitSessionState(t, sessionHandler)
	requireSessionState(t, disclosureSession, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// Reaching Success only proves the wallet was satisfied; the verifier
	// accepting the DeviceResponse — issuer signature, device signature over
	// the session transcript, and digest match — is what the wallet response
	// proves.
	walletResponse, err := GetWalletResponseFromEudiVerifier(verifierSession)
	require.NoError(t, err)
	require.NotNil(t, walletResponse, "EUDI verifier returned no wallet response")
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

// issueAvMdocViaPythonIssuer drives the pre-authorized OID4VCI flow for the
// age-verification mdoc, mirroring issuePidViaPythonIssuer. The display name is
// not asserted on the offer: the issuer publishes no display metadata for this
// configuration, so the wallet falls back to rendering the raw docType.
func issueAvMdocViaPythonIssuer(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
) {
	t.Helper()

	offer := createAvMdocOfferViaPythonIssuer(t)

	startOpenID4VCISession(t, c, sessionId, offer.URI)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPreAuthorizedCode)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_PreAuthorizedCode,
		Payload: clientmodels.SessionPreAuthorizedCodeInteractionPayload{
			Proceed:         true,
			TransactionCode: &offer.TxCode,
		},
	})

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_RequestPermission)
	require.Len(t, session.OfferedCredentials, 1)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

// createAvMdocOfferViaPythonIssuer posts the same unsigned-JWT-shaped request
// createPidOfferViaPythonIssuer uses, naming the mdoc configuration instead.
func createAvMdocOfferViaPythonIssuer(t *testing.T) pidOfferResponse {
	t.Helper()

	requestPayload := map[string]any{
		"credentials": []map[string]any{
			{
				"credential_configuration_id": eudiPidIssuerPyAvCredentialConfigID,
				"data": map[string]any{
					"age_over_18": true,
				},
			},
		},
	}
	payloadJSON, err := json.Marshal(requestPayload)
	require.NoError(t, err)

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
		"Python issuer /credentialOfferReq2 should accept the mdoc request")

	var offerJSON map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&offerJSON))

	txCode := extractTxCodeValue(t, offerJSON)
	require.NotEmpty(t, txCode,
		"Python issuer offer must embed grants.<pre-authorized_code>.tx_code.value")

	offerBytes, err := json.Marshal(offerJSON)
	require.NoError(t, err)

	uri := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerBytes))
	return pidOfferResponse{URI: uri, TxCode: txCode}
}

// createAvMdocAuthRequest builds the verifier's session-creation request for the
// age query, passing the issuer's CA as issuer_chain so the verifier can walk
// the MSO's document signer chain to a trusted root.
func createAvMdocAuthRequest(t *testing.T) string {
	t.Helper()

	caPEM := readEudiPidIssuerPyCA(t)

	request := map[string]any{
		"type": "vp_token",
		"dcql_query": map[string]any{
			"credentials": []map[string]any{
				{
					"id":     "age",
					"format": string(clientmodels.Format_MsoMdoc),
					"meta":   map[string]any{"doctype_value": eudiPidIssuerPyAvDocType},
					"claims": []map[string]any{
						{"path": []string{eudiPidIssuerPyAvDocType, "age_over_18"}},
					},
				},
			},
		},
		"nonce":    "nonce",
		"jar_mode": "by_reference",
		// The client fetches the request object with a GET and sends no
		// wallet_nonce, and the verifier enforces the method the transaction was
		// started with. Every transaction must also name an intended use or carry
		// a relying-party registration certificate, which the wallet does not
		// produce; id "1" is the one the image configures out of the box.
		"request_uri_method": "get",
		"intended_use_id":    eudiVerifierIntendedUseId,
		"issuer_chain":       string(caPEM),
	}

	body, err := json.Marshal(request)
	require.NoError(t, err)
	return string(body)
}

// findMdocCredentialByDocType locates a stored credential by its docType,
// rather than by display name as the SD-JWT tests do: this configuration
// publishes no display metadata, so the wallet has no name to match on.
func findMdocCredentialByDocType(t *testing.T, creds []*clientmodels.Credential, docType string) *clientmodels.Credential {
	t.Helper()

	for _, cred := range creds {
		if cred.CredentialId == docType {
			return cred
		}
	}

	var seen []string
	for _, cred := range creds {
		seen = append(seen, cred.CredentialId)
	}
	t.Fatalf("no credential with docType %q in wallet; found %v", docType, seen)
	return nil
}
