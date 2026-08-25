package sessiontest

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// mso_mdoc issuance and disclosure against the EUDI Python issuer
//
// Every mdoc integration test now gets its credential the way a user would, by
// issuing one from the reference issuer over OpenID4VCI, so the whole issuance
// half of the path — format parser, COSE algorithm validation, holder binding,
// batch storage — is exercised by whatever presents afterwards. The subtests here
// are the ones asserting on issuance itself; openid4vp_mdoc_av_disclosure_test.go
// and openid4vp_dc_api_mdoc_test.go issue as a fixture and assert on presentation.
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
// SD-JWT subtests in session_handler_test.go, under "openid4vci/mdoc".
//
// Grouped by which half of the flow each subtest is actually asserting on, since
// only the first group is about issuance. The rest need a real issuance too, but
// as a fixture: what they check is what the wallet does with the credential at
// presentation, and reading them as issuance tests overstates what the OpenID4VCI
// path is covered for.
func testSessionHandlerForEudiPidPythonIssuerMdoc(t *testing.T) {
	t.Run("issuance/stores the credential its signed MSO describes", testEudiPidPythonIssuerIssuesAvMdoc)
	t.Run("issuance/refuses a credential from an untrusted issuer", testEudiPidPythonIssuerUntrustedIssuerIsRejected)

	t.Run("disclosure/discloses issued mdoc to EUDI Kotlin verifier", testEudiPidPythonIssuerDisclosesAvMdoc)
	t.Run("disclosure/batch instances are spent one per presentation", testEudiPidPythonIssuerBatchIsSingleUse)
	t.Run("disclosure/discloses two claims at once", testEudiPidPythonIssuerDisclosesTwoClaims)
	t.Run("disclosure/discloses only the requested claim", testEudiPidPythonIssuerDisclosesOnlyRequestedClaim)
	t.Run("disclosure/matches a values constraint", testEudiPidPythonIssuerMatchesValuesConstraint)
	t.Run("disclosure/refuses an unsatisfied values constraint", testEudiPidPythonIssuerRejectsUnsatisfiedValuesConstraint)
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

	// Both booleans the offer asked for, in the docType's own namespace: the AV
	// profile allows nothing else in this credential.
	require.Len(t, cred.Attributes, 2)
	for _, attr := range cred.Attributes {
		require.Equal(t, eudiPidIssuerPyAvDocType, attr.ClaimPath[0],
			"an AV element lives in the namespace named after the docType")
		require.NotNil(t, attr.Value.Bool, "age_over_NN elements are booleans")
	}

	// The activity log names the same credential.
	//
	// It is worth asserting separately from the stored credential above: the log
	// entry is written from the offered-credential snapshot, not from the stored
	// batch, so the two are populated by different code and an id that is right
	// in the wallet can still be missing from the log the user reads afterwards.
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 1, "issuance should be the only entry; this client never enrolled with a keyshare server")

	issuanceLog := findLog(logs, clientmodels.LogType_Issuance)
	require.NotNil(t, issuanceLog, "issuing an mdoc should create an issuance log")
	require.NotNil(t, issuanceLog.IssuanceLog)
	require.Equal(t, clientmodels.Protocol_OpenID4VCI, issuanceLog.IssuanceLog.Protocol)
	require.Len(t, issuanceLog.IssuanceLog.Credentials, 1)

	logged := issuanceLog.IssuanceLog.Credentials[0]
	require.Equal(t, eudiPidIssuerPyAvDocType, logged.CredentialId,
		"the issuance log must name the docType; an mso_mdoc configuration carries no vct to fall back on")
	require.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_MsoMdoc}, logged.Formats,
		"the issuance log must file the entry under mso_mdoc, which is what every format-keyed read depends on")
	require.Len(t, logged.Attributes, 2, "both issued claims are logged; the selective part happens at presentation")
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

	// The offer the user is asked to accept names the docType out of the signed
	// MSO. It has to come from the credential: an mso_mdoc credential
	// configuration publishes no vct, so a dialog built from the issuer's
	// advertised metadata alone would name nothing at all.
	require.Equal(t, eudiPidIssuerPyAvDocType, session.OfferedCredentials[0].CredentialId,
		"the offered credential must be named by the docType the issuer signed")

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
					"age_over_21": true,
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
	return createAvMdocAuthRequestWithClaims(t, []map[string]any{
		{"path": []string{eudiPidIssuerPyAvDocType, "age_over_18"}},
	})
}

// createAvMdocAuthRequestWithClaims builds the verifier's session-creation
// request for an arbitrary set of DCQL claims against the age credential.
func createAvMdocAuthRequestWithClaims(t *testing.T, claims []map[string]any) string {
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
					"claims": claims,
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

// testEudiPidPythonIssuerBatchIsSingleUse covers the property the AV profile's
// batch issuance exists for.
//
// Annex A recommends batches of thirty attestations because a proof of age is
// single-use: an mdoc is a fixed signed blob, so presenting one twice hands two
// relying parties the same bytes to correlate. Batching only helps if the wallet
// actually spends a fresh instance per presentation and the instances are not
// themselves linkable, which is three separate wallet behaviours — batch storage,
// per-instance device keys, and marking an instance used — none of which is
// visible from a single presentation.
func testEudiPidPythonIssuerBatchIsSingleUse(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	// Observed through the wallet API the app uses rather than the database
	// underneath it. A remaining count above one straight after issuance carries
	// both halves of what the storage read used to assert: the wallet asked for a
	// batch rather than a single attestation, and it has spent none of it yet.
	remainingAfterIssuance := avMdocInstancesRemaining(t, c)
	require.Greater(t, remainingAfterIssuance, uint(1),
		"the issuer advertises batch_credential_issuance, so a batch of one means the wallet never asked for more than a single attestation")

	// Two presentations, one after the other, as two relying parties would see
	// them.
	first := discloseAvMdocOnce(t, c, sessionHandler, 2)
	second := discloseAvMdocOnce(t, c, sessionHandler, 3)

	require.NotEqual(t, issuerAuthOf(t, first), issuerAuthOf(t, second),
		"both presentations sent the same issuerAuth, so the same attestation was presented twice and the two relying parties can link them")

	// Distinct attestations are not enough on their own: a batch signed over one
	// reused device key is just as linkable, and deviceKeyInfo is part of what the
	// relying parties receive. Checking the two instances actually spent, rather
	// than every key in storage, is deliberate -- what a colluding pair of relying
	// parties can compare is what they were sent, and proving it for all thirty
	// would mean thirty verifier round trips.
	require.NotEqual(t, deviceKeyOf(t, first), deviceKeyOf(t, second),
		"both presentations were bound to the same device key, so the two relying parties can link them even though the attestations differ")

	require.Equal(t, remainingAfterIssuance-2, avMdocInstancesRemaining(t, c),
		"two presentations must spend exactly two instances")
}

// avMdocInstancesRemaining reports how many instances of the age credential the
// wallet has left, as the app sees it: the per-format count the credential list
// carries.
func avMdocInstancesRemaining(t *testing.T, c *client.Client) uint {
	t.Helper()

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	cred := findMdocCredentialByDocType(t, creds, eudiPidIssuerPyAvDocType)
	remaining, ok := cred.BatchInstanceCountsRemaining[clientmodels.Format_MsoMdoc]
	require.True(t, ok,
		"the credential list must report a remaining count under the mso_mdoc format")
	require.NotNil(t, remaining, "a batched mdoc credential must carry a remaining count")

	return *remaining
}

// issuerAuthOf identifies which attestation was presented: issuerAuth is signed
// per instance, so two presentations of one instance carry the same value and two
// instances never do.
func issuerAuthOf(t *testing.T, presented stdmdoc.MDoc) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(presented.IssuerSigned.IssuerAuth)
}

// deviceKeyOf reads the device public key a presented attestation is bound to out
// of its own MSO -- the copy the verifier authenticates the DeviceSigned against,
// and therefore the copy that would correlate two presentations if it repeated.
func deviceKeyOf(t *testing.T, presented stdmdoc.MDoc) string {
	t.Helper()

	deviceKey, err := stdmdoc.DeviceKeyFromIssuerAuth(presented.IssuerSigned.IssuerAuth)
	require.NoError(t, err)

	encoded, err := x509.MarshalPKIXPublicKey(deviceKey)
	require.NoError(t, err)

	return base64.RawURLEncoding.EncodeToString(encoded)
}

// discloseAvMdocOnce runs one disclosure of the age credential and returns the
// document the verifier received, so a caller can compare any part of what was
// presented against what another presentation sent.
func discloseAvMdocOnce(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionId int) stdmdoc.MDoc {
	t.Helper()

	verifierSession, err := StartTestSessionAtEudiVerifier(testdata.OpenID4VP_DirectPostJwt_Host, createAvMdocAuthRequest(t))
	require.NoError(t, err)

	startOpenID4VPDisclosureSession(t, c, sessionId, verifierSession.SessionLink)

	session := awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_Error && session.Error != nil {
		t.Fatalf("disclosure errored: %+v", session.Error)
	}
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	chosen := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(chosen))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse, err := GetWalletResponseFromEudiVerifier(verifierSession)
	require.NoError(t, err)
	return presentedDocument(t, walletResponse, "age")
}

// presentedDocument decodes the single document the verifier received for the
// given query id.
func presentedDocument(t *testing.T, walletResponse map[string]any, queryId string) stdmdoc.MDoc {
	t.Helper()

	vpToken, ok := walletResponse["vp_token"].(map[string]any)
	require.True(t, ok, "vp_token should be a JSON object, got %T", walletResponse["vp_token"])

	entry, ok := vpToken[queryId]
	require.True(t, ok, "vp_token should carry query id %q", queryId)
	encoded, ok := entry.(string)
	if !ok {
		list, isList := entry.([]any)
		require.True(t, isList, "vp_token[%q] should be a string or array, got %T", queryId, entry)
		require.Len(t, list, 1)
		encoded, ok = list[0].(string)
		require.True(t, ok)
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(encoded)
	}
	require.NoError(t, err)

	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(raw, &response))
	require.Len(t, response.Documents, 1)

	return response.Documents[0]
}

// testEudiPidPythonIssuerDisclosesTwoClaims asks for both age booleans at once.
//
// Every other mdoc test discloses a single element, which cannot tell "discloses
// what was asked" apart from "discloses the whole namespace": with one element in
// the query and one in the credential the two are the same set. Here the
// credential carries two and both are requested; the test below covers the other
// direction.
func testEudiPidPythonIssuerDisclosesTwoClaims(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	request := createAvMdocAuthRequestWithClaims(t, []map[string]any{
		{"path": []string{eudiPidIssuerPyAvDocType, "age_over_18"}},
		{"path": []string{eudiPidIssuerPyAvDocType, "age_over_21"}},
	})
	disclosed := discloseAvMdocAndDecode(t, c, sessionHandler, 2, request)

	require.Equal(t, map[string]any{"age_over_18": true, "age_over_21": true}, disclosed)
}

// testEudiPidPythonIssuerDisclosesOnlyRequestedClaim is that other direction: the
// credential holds two elements, the query names one, and the response must carry
// exactly that one. Selective disclosure is the point of the format, and a wallet
// that shipped both would leak an attribute nobody asked for while every
// single-element test still passed.
func testEudiPidPythonIssuerDisclosesOnlyRequestedClaim(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	request := createAvMdocAuthRequestWithClaims(t, []map[string]any{
		{"path": []string{eudiPidIssuerPyAvDocType, "age_over_21"}},
	})
	disclosed := discloseAvMdocAndDecode(t, c, sessionHandler, 2, request)

	require.Equal(t, map[string]any{"age_over_21": true}, disclosed)
}

// testEudiPidPythonIssuerMatchesValuesConstraint covers a DCQL values constraint
// the credential satisfies.
//
// The comparison behind it is dcql.ClaimValuesEqual, which replaced a bare Go ==
// that panicked on uncomparable values and silently never matched numbers decoded
// by different decoders. It has unit tests; this is the first time the constraint
// travels through a real verifier's query against a real credential's
// CBOR-decoded claims.
func testEudiPidPythonIssuerMatchesValuesConstraint(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	request := createAvMdocAuthRequestWithClaims(t, []map[string]any{
		{"path": []string{eudiPidIssuerPyAvDocType, "age_over_18"}, "values": []any{true}},
	})
	disclosed := discloseAvMdocAndDecode(t, c, sessionHandler, 2, request)

	require.Equal(t, map[string]any{"age_over_18": true}, disclosed)
}

// testEudiPidPythonIssuerRejectsUnsatisfiedValuesConstraint asks for
// age_over_18 = false against a credential that says true.
//
// The credential matches on docType and on claim path and differs only in the
// constrained value, which is what separates a values constraint that is
// evaluated from one that is parsed and ignored. The wallet must offer nothing
// rather than present a credential contradicting the query.
func testEudiPidPythonIssuerRejectsUnsatisfiedValuesConstraint(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	request := createAvMdocAuthRequestWithClaims(t, []map[string]any{
		{"path": []string{eudiPidIssuerPyAvDocType, "age_over_18"}, "values": []any{false}},
	})

	verifierSession, err := StartTestSessionAtEudiVerifier(testdata.OpenID4VP_DirectPostJwt_Host, request)
	require.NoError(t, err)

	startOpenID4VPDisclosureSession(t, c, 2, verifierSession.SessionLink)
	session := awaitSessionState(t, sessionHandler)

	// Either the session errors outright or it asks for permission with nothing
	// to answer with. Both are correct refusals; what must not appear is an owned
	// option, which would mean the constraint was ignored.
	if session.Status == clientmodels.Status_Error {
		return
	}
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.NotNil(t, session.DisclosurePlan)
	for _, choice := range session.DisclosurePlan.DisclosureChoicesOverview {
		require.Empty(t, choice.OwnedOptions,
			"the wallet offered a credential whose age_over_18 is true for a query constrained to false")
	}
}

// discloseAvMdocAndDecode runs one disclosure of the given request through to
// success and returns the element/value pairs the verifier received.
func discloseAvMdocAndDecode(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	sessionId int,
	request string,
) map[string]any {
	t.Helper()

	verifierSession, err := StartTestSessionAtEudiVerifier(testdata.OpenID4VP_DirectPostJwt_Host, request)
	require.NoError(t, err)

	startOpenID4VPDisclosureSession(t, c, sessionId, verifierSession.SessionLink)

	session := awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_Error && session.Error != nil {
		t.Fatalf("disclosure errored: %+v", session.Error)
	}
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	chosen := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(chosen))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	walletResponse, err := GetWalletResponseFromEudiVerifier(verifierSession)
	require.NoError(t, err)
	return disclosedElements(t, walletResponse, "age")
}

// disclosedElements unwraps the presented document's Tag-24 issuerSigned items
// into the element/value pairs the verifier can actually read.
func disclosedElements(t *testing.T, walletResponse map[string]any, queryId string) map[string]any {
	t.Helper()

	document := presentedDocument(t, walletResponse, queryId)
	items, ok := document.IssuerSigned.NameSpaces[eudiPidIssuerPyAvDocType]
	require.True(t, ok, "namespace %q should be disclosed", eudiPidIssuerPyAvDocType)

	disclosed := map[string]any{}
	for _, item := range items {
		decoded := decodeIssuerSignedItem(t, item)
		disclosed[decoded.ElementIdentifier] = decoded.ElementValue
	}
	return disclosed
}

// testEudiPidPythonIssuerUntrustedIssuerIsRejected runs a genuine issuance
// against a wallet that does not trust the issuer's root.
//
// The mdoc package rejects an untrusted chain in its own unit tests, but those
// call the verifier directly. This is the only check that the trust anchor is
// actually consulted on the live issuance path — offer, token, proof of
// possession and a real signed credential all succeed, and the wallet must still
// refuse to store what came back. Everything except the trust anchor is
// identical to the passing issuance test: the credential is authentic, it is
// simply signed by someone this wallet has no reason to believe.
func testEudiPidPythonIssuerUntrustedIssuerIsRejected(t *testing.T) {
	// A real CA, and the wrong one: the demo verifier root, which signs the
	// relying-party certificates rather than the attestation provider's.
	// Configuring no anchor at all would risk passing for the wrong reason, if
	// an empty trust model were ever treated as "trust everything".
	wrongCA, err := os.ReadFile(filepath.Join(testdataFolder, "eudi", "verifier", "ca.crt"))
	require.NoError(t, err)

	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, wrongCA)
	defer c.Close()

	offer := createAvMdocOfferViaPythonIssuer(t)

	startOpenID4VCISession(t, c, 1, offer.URI)
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

	// Exactly one end state, asserted as such. Issuance verifies before it asks:
	// openid4vci's session runs obtainCredentials -- which is where the format
	// parser's ParseAndVerify checks the chain -- and reports Failure from there,
	// several steps before RequestPermission would be called. So the trust
	// failure always lands before any permission step, and tolerating a
	// RequestPermission here would hide it if that order ever changed.
	session = awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Status_Error, session.Status,
		"a credential signed by an untrusted issuer must not be accepted")
	require.NotNil(t, session.Error)

	// The stronger property the ordering buys: the user is never shown, and
	// never asked to accept, a credential the wallet has already decided to
	// refuse. OfferedCredentials is populated only by RequestPermission.
	require.Empty(t, session.OfferedCredentials,
		"the wallet offered a credential it was about to reject")

	creds, err := c.GetCredentials()
	require.NoError(t, err)
	for _, cred := range creds {
		require.NotEqual(t, eudiPidIssuerPyAvDocType, cred.CredentialId,
			"the rejected credential was stored anyway")
	}
}
