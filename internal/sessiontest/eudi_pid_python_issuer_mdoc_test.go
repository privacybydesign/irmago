package sessiontest

import (
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
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
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
	t.Run("batch instances are spent one per presentation", testEudiPidPythonIssuerBatchIsSingleUse)
	t.Run("discloses two claims at once", testEudiPidPythonIssuerDisclosesTwoClaims)
	t.Run("discloses only the requested claim", testEudiPidPythonIssuerDisclosesOnlyRequestedClaim)
	t.Run("matches a values constraint", testEudiPidPythonIssuerMatchesValuesConstraint)
	t.Run("refuses an unsatisfied values constraint", testEudiPidPythonIssuerRejectsUnsatisfiedValuesConstraint)
	t.Run("refuses a credential from an untrusted issuer", testEudiPidPythonIssuerUntrustedIssuerIsRejected)
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

	credStore := db.NewCredentialStore(c.EudiStorageForTesting().Db())
	batches, err := credStore.GetBatchesByDocType(eudiPidIssuerPyAvDocType)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	batch := batches[0]

	require.Greater(t, batch.BatchSize, uint(1),
		"the issuer advertises batch_credential_issuance, so a batch of one means the wallet never asked for more than a single attestation")
	require.Equal(t, batch.BatchSize, batch.RemainingCount,
		"a freshly issued batch has spent nothing yet")

	// Every instance must carry its own device key: one reused key across the
	// batch would correlate the presentations that the batch exists to separate.
	// Read straight from the database rather than off the batch: the display
	// preloads GetBatchesByDocType uses do not include instances.
	var instances []models.IssuedCredentialInstance
	require.NoError(t, c.EudiStorageForTesting().Db().
		Preload("HolderBindingKey").
		Where("credential_batch_id = ?", batch.ID).
		Find(&instances).Error)
	require.Len(t, instances, int(batch.BatchSize))
	thumbprints := map[string]struct{}{}
	for _, instance := range instances {
		require.NotNil(t, instance.HolderBindingKey, "instance %s has no holder binding key", instance.ID)
		require.True(t, instance.HolderBindingKey.PublicKeyThumbprint.Valid)
		thumbprints[instance.HolderBindingKey.PublicKeyThumbprint.V] = struct{}{}
	}
	require.Len(t, thumbprints, len(instances), "the batch reuses a device key across instances")

	// Two presentations, one after the other. Each must spend one instance and
	// send a different attestation.
	first := discloseAvMdocOnce(t, c, sessionHandler, 2)
	second := discloseAvMdocOnce(t, c, sessionHandler, 3)

	require.NotEqual(t, first, second,
		"both presentations sent the same issuerAuth, so the same attestation was presented twice and the two relying parties can link them")

	batches, err = credStore.GetBatchesByDocType(eudiPidIssuerPyAvDocType)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	require.Equal(t, batch.BatchSize-2, batches[0].RemainingCount,
		"two presentations must spend exactly two instances")
}

// discloseAvMdocOnce runs one disclosure of the age credential and returns the
// issuerAuth bytes of what was presented — the per-instance part of the
// credential, so two presentations of the same instance return the same value
// and two different instances do not.
func discloseAvMdocOnce(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, sessionId int) string {
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
	return issuerAuthFromWalletResponse(t, walletResponse, "age")
}

// issuerAuthFromWalletResponse digs the presented document's issuerAuth out of
// the verifier's wallet response.
func issuerAuthFromWalletResponse(t *testing.T, walletResponse map[string]any, queryId string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(presentedDocument(t, walletResponse, queryId).IssuerSigned.IssuerAuth)
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

	// The wallet may refuse at the permission step or after fetching the
	// credential, depending on how far it gets before verifying; either way it
	// must end in an error and store nothing.
	session = awaitSessionState(t, sessionHandler)
	if session.Status == clientmodels.Status_RequestPermission {
		grantPermission(t, c, session.Id)
		session = awaitSessionState(t, sessionHandler)
	}

	require.Equal(t, clientmodels.Status_Error, session.Status,
		"a credential signed by an untrusted issuer must not be accepted")
	require.NotNil(t, session.Error)

	creds, err := c.GetCredentials()
	require.NoError(t, err)
	for _, cred := range creds {
		require.NotEqual(t, eudiPidIssuerPyAvDocType, cred.CredentialId,
			"the rejected credential was stored anyway")
	}
}
