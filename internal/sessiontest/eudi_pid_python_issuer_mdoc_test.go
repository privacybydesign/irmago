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

	// The one element the AV profile makes mandatory. Every other age_over_NN is
	// optional, so it is the only element any assertion here may name; the rest are
	// found by asking the credential what it carries.
	avMandatoryElement = "age_over_18"
)

// The display metadata this configuration publishes, as read from the pinned
// image's metadata document (/.well-known/openid-credential-issuer, configuration
// eu.europa.ec.eudi.age_verification_mdoc): credential_metadata.display[0].name,
// the issuer metadata's own top-level display[0].name, and the claim display for
// each ["eu.europa.ec.av.1", age_over_NN] path the offers here request.
//
// Both mdoc suites read these — this one for the offer, the AV disclosure suite
// for the permission screen and the log — which is why they live with the issuer
// rather than with either set of assertions.
//
// Asserted literally rather than read back out of the wallet: reading them back
// would pass just as happily against the empty strings a credential with no
// display metadata produces, which is exactly what the seeded fixture these
// subtests used to run on produced, and what made the wallet look as though it
// could not name an mdoc credential at all.
//
// Only an "en" locale is published, for the credential, the issuer and every
// claim alike, so this issuer can prove a fallback but not a translation.
//
// age_over_18 is the only claim named here on purpose: the AV profile makes it the
// one mandatory element and every other age_over_NN optional, so pinning another
// element's label would assert something the issuer is free to stop publishing.
// The rest are checked by shape where they appear.
const (
	avCredentialDisplayName = "Proof of Age"
	avIssuerDisplayName     = "Digital Credentials Issuer"
	avAgeOver18DisplayName  = "Age Over 18"
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
	t.Run("issuance/the offer names the credential, its issuer and every claim", testEudiPidPythonIssuerOfferNamesEverything)
	t.Run("issuance/offer text falls back to a locale the issuer does publish", testEudiPidPythonIssuerOfferFallsBackToPublishedLocale)
	t.Run("issuance/refuses a credential from an untrusted issuer", testEudiPidPythonIssuerUntrustedIssuerIsRejected)

	t.Run("disclosure/discloses issued mdoc to EUDI Kotlin verifier", testEudiPidPythonIssuerDisclosesAvMdoc)
	t.Run("disclosure/batch instances are spent one per presentation", testEudiPidPythonIssuerBatchIsSingleUse)
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

	// The one element the AV profile makes mandatory, in the docType own namespace.
	// Every other age_over_NN is optional, so this offer mints none of them.
	require.Len(t, cred.Attributes, 1)
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
	require.Len(t, logged.Attributes, 1, "the issued claim is logged; the selective part happens at presentation")
}

// testEudiPidPythonIssuerOfferNamesEverything asserts the text of the permission
// screen the user is shown before accepting an mdoc: the credential's name, its
// issuer, and a label and value for every claim.
//
// This is the screen where consent is actually given, and every string on it is
// resolved from the issuer's OpenID4VCI metadata rather than from the credential
// — ISO 18013-5 has no display concept, so the signed mdoc carries element
// identifiers and values and nothing a user would read. That is exactly why it is
// worth pinning here: the wallet joins two documents by claim path to build this
// screen, and a join that silently misses leaves a dialog of raw identifiers
// asking for consent.
//
// Two things this issuer cannot prove, deliberately not asserted:
//
//   - Translations. The pinned image publishes an "en" locale only, for the
//     credential, the issuer and every claim, so there is no second locale to
//     compare against. The subtest below asserts the fallback instead, and the
//     locale switch itself is covered end to end against the veramo issuer in
//     eudi_logs_test.go ("Test Issuer" / "Test Uitgever").
//   - The logo. Both logo URIs in the upstream metadata point at third-party
//     hosts (examplestate.com, dev.issuer.eudiw.dev), so whether an image
//     resolves depends on outbound network access to someone else's server.
//     Asserting either way would make this subtest fail for a reason that has
//     nothing to do with the wallet.
func testEudiPidPythonIssuerOfferNamesEverything(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	session := offerAvMdocViaPythonIssuer(t, c, 1, sessionHandler)
	offered := session.OfferedCredentials[0]

	require.Equal(t, avCredentialDisplayName, offered.Name,
		"the offer must name the credential from the issuer's credential_metadata")
	require.Equal(t, avIssuerDisplayName, offered.Issuer.Name,
		"the offer must name the issuer from the issuer metadata's own display entry")
	require.True(t, offered.Issuer.Verified,
		"the credentials were fetched and their chain verified before this screen is built")

	requireAvOfferAttributes(t, offered.Attributes)

	grantPermission(t, c, session.Id)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

// testEudiPidPythonIssuerOfferFallsBackToPublishedLocale runs the same offer on a
// Dutch wallet against an issuer that publishes "en" only.
//
// The property is that an unpublished locale falls back to what the issuer does
// publish, rather than resolving to an empty string: a wallet whose language the
// issuer never translated must still show a name, a claim label and a value. This
// is the half of the translation question this container can answer — the other
// half, that a published translation is preferred, needs metadata with two
// locales and is covered against the veramo issuer instead.
func testEudiPidPythonIssuerOfferFallsBackToPublishedLocale(t *testing.T) {
	caPEM := readEudiPidIssuerPyCA(t)
	c, _, sessionHandler := instantiateClient(t, caPEM, "nl")
	defer c.Close()

	session := offerAvMdocViaPythonIssuer(t, c, 1, sessionHandler)
	offered := session.OfferedCredentials[0]

	require.Equal(t, avCredentialDisplayName, offered.Name,
		"a locale the issuer does not publish must fall back to one it does, not to an empty name")
	require.Equal(t, avIssuerDisplayName, offered.Issuer.Name,
		"the issuer name must survive the same fallback")
	requireAvOfferAttributes(t, offered.Attributes)
}

// requireAvOfferAttributes checks the claims on an AV offer: age_over_18 by name,
// everything else by shape.
//
// Only age_over_18 is named because the AV profile makes it the single mandatory
// element and leaves every other age_over_NN optional — which of them a given
// configuration mints is the issuer's choice, so naming one would make this fail
// on an issuer change that breaks nothing about the permission screen. What has to
// hold for all of them is the part the wallet is responsible for: a qualified
// [namespace, elementIdentifier] path in the docType's namespace, a label resolved
// from the issuer's metadata, and the boolean that was actually signed.
func requireAvOfferAttributes(t *testing.T, attrs []clientmodels.Attribute) {
	t.Helper()

	require.NotEmpty(t, attrs, "the offer must list the claims the credential carries")

	ageOver18 := findAttr(attrs, eudiPidIssuerPyAvDocType, avMandatoryElement)
	require.NotNil(t, ageOver18, "the mandatory age_over_18 element is missing from the offer")
	require.Equal(t, boolVal(true), ageOver18.Value)
	require.NotNil(t, ageOver18.DisplayName, "age_over_18 reached the offer with no label")
	require.Equal(t, avAgeOver18DisplayName, *ageOver18.DisplayName)

	for i, attr := range attrs {
		// A label never replaces the path, and the namespace is the docType. This is
		// what makes the join non-trivial: the issuer publishes its claim paths in
		// the same two-component form, and a bare elementIdentifier matches nothing.
		require.Len(t, attr.ClaimPath, 2,
			"attribute %d lost its qualified [namespace, elementIdentifier] path", i)
		require.Equal(t, eudiPidIssuerPyAvDocType, attr.ClaimPath[0],
			"attribute %d is not in the namespace named after the docType", i)
		require.NotNil(t, attr.DisplayName, "attribute %d reached the offer with no label", i)
		require.NotEmpty(t, *attr.DisplayName, "attribute %d has an empty label", i)
		require.NotNil(t, attr.Value, "attribute %d has no value", i)
		require.NotNil(t, attr.Value.Bool, "attribute %d should be an age_over_NN boolean", i)
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

// offerAvMdocViaPythonIssuer drives the pre-authorized OID4VCI flow for the
// age-verification mdoc up to the permission screen, and returns the session
// state carrying the offer.
//
// Split from issueAvMdocViaPythonIssuer so a subtest can assert what the offer
// says before accepting it: once permission is granted the state moves on, and
// the offered-credential snapshot is only populated on RequestPermission.
func offerAvMdocViaPythonIssuer(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
) clientmodels.SessionState {
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

	return session
}

// issueAvMdocViaPythonIssuer accepts the offer above, leaving the credential in
// the wallet.
//
// The display text is not asserted here, and not because there is none to assert:
// the issuer publishes credential, issuer and per-claim display metadata for this
// configuration. It is asserted in testEudiPidPythonIssuerOfferNamesEverything,
// and again against the permission screen in
// openid4vp_mdoc_av_disclosure_test.go. This helper is a fixture for the subtests
// about presentation, and re-asserting the wording in every one of them would pin
// it in eight places.
func issueAvMdocViaPythonIssuer(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
) {
	t.Helper()

	session := offerAvMdocViaPythonIssuer(t, c, sessionId, sessionHandler)

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
					avMandatoryElement: true,
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
		{"path": []string{eudiPidIssuerPyAvDocType, avMandatoryElement}},
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

// findMdocCredentialByDocType locates a stored credential by its docType, rather
// than by display name as the SD-JWT tests do. The wallet does resolve a name for
// this configuration — the issuer publishes one — but the docType is the identity
// the credential is filed under, and matching on the name would make every caller
// of this helper fail on an issuer wording change that breaks nothing.
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
		{"path": []string{eudiPidIssuerPyAvDocType, avMandatoryElement}, "values": []any{true}},
	})
	disclosed := discloseAvMdocAndDecode(t, c, sessionHandler, 2, request)

	require.Equal(t, map[string]any{avMandatoryElement: true}, disclosed)
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
		{"path": []string{eudiPidIssuerPyAvDocType, avMandatoryElement}, "values": []any{false}},
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
