package sessiontest

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/testdata"
)

// avDocType is the EU Age Verification profile's docType. Five dot-separated
// parts where a Yivi scheme identifier has three, which is what makes the
// relying party's authorized-set matching worth exercising against a real
// certificate rather than only in unit tests.
const avDocType = "eu.europa.ec.av.1"

// The display text these subtests assert lives with the issuer that publishes it,
// in eudi_pid_python_issuer_mdoc_test.go: avCredentialDisplayName,
// avIssuerDisplayName and the per-claim labels.

// testSessionHandlerForOpenID4VPWithMdocAv covers an mso_mdoc age-verification
// presentation end to end against the EU reference verifier container.
//
// The wallet matches the DCQL query, signs a DeviceResponse with the device key
// of a credential it was genuinely issued, and the verifier accepts it. The
// relying party certificate the container presents is
// testdata/eudi/verifier/verifier.crt, whose scheme extension authorizes
// eu.europa.ec.av.1 — so the authorization stage runs for real and passes because
// the certificate genuinely permits the query.
//
// What these subtests add over the disclosure subtest in
// eudi_pid_python_issuer_mdoc_test.go, which also issues for real and presents to
// this container, is what happens to the bytes: the authorization request is
// captured so the session transcript can be rebuilt independently, and the
// DeviceResponse the verifier received is verified here rather than being taken
// on the container's word that it arrived.
//
// The disclosure runs against both verifier containers, because the response
// mode changes the bytes deviceAuth signs over: direct_post.jwt puts the
// response encryption key's thumbprint in the handover, direct_post puts a CBOR
// null there. Only one of the two can be wrong at a time, and only the AV
// Blueprint's own choice — direct_post — matters for conformance.
func testSessionHandlerForOpenID4VPWithMdocAv(t *testing.T) {
	t.Run("age verification mdoc is disclosed to the verifier",
		testOpenID4VP_MdocAv_Disclosure)
	t.Run("age verification mdoc is disclosed with response mode direct_post",
		testOpenID4VP_MdocAv_DisclosureDirectPost)
	t.Run("an unauthorized mdoc doctype is refused",
		testOpenID4VP_MdocAv_UnauthorizedDocType)
	t.Run("the permission screen falls back to a locale the issuer publishes",
		testOpenID4VP_MdocAv_DisclosureUnderUnpublishedLocale)
}

// testOpenID4VP_MdocAv_DisclosureUnderUnpublishedLocale runs a full disclosure on
// a Dutch wallet against an issuer that publishes "en" only.
//
// The five display resolvers in mdoc_dcql (credentialDisplayName,
// claimDisplayName, issuerTrustedParty and the two logo loaders) each take the
// wallet's locale and resolve stored metadata against it, and until this subtest
// every test in the suite asked for the one locale the metadata carries — so the
// path where the requested locale is absent was reached nowhere. What must not
// happen is that it resolves to an empty string: a Dutch user would then be asked
// to approve a nameless credential from a nameless issuer, on the one screen where
// consent is given.
//
// The offer side of the same question is covered in
// eudi_pid_python_issuer_mdoc_test.go; this is the disclosure side, which is
// different code (mdoc_dcql.FindCandidates, not openid4vci.buildOfferedCredentials)
// and would fail independently. The disclosure runs to completion rather than
// stopping at the screen, so the log written afterwards is checked under the same
// locale: log text is re-resolved against live credential metadata on read, which
// is a third resolver with the same missing-locale input.
func testOpenID4VP_MdocAv_DisclosureUnderUnpublishedLocale(t *testing.T) {
	caPEM := readEudiPidIssuerPyCA(t)
	c, _, sessionHandler := instantiateClient(t, caPEM, "nl")
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	testSession, _ := startMdocAvSessionCapturingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, createAvMdocAuthRequest(t))

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	// The same text the English wallet is shown, because "en" is all the issuer
	// published — asserted through the same constants, so the two subtests cannot
	// drift apart on what the fallback is falling back to.
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{{
					CredentialId: avDocType,
					Name:         avCredentialDisplayName,
					IssuerName:   avIssuerDisplayName,
					Attributes: []expectedAttr{
						{
							Path:        []any{avDocType, avMandatoryElement},
							DisplayName: new(avAgeOver18DisplayName),
							Value:       boolVal(true),
						},
					},
				}},
			},
		},
	})

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]

	// The text above is English on a Dutch wallet, and this is the only thing that
	// says so — a frontend shipping its own Dutch labels for docTypes it knows
	// substitutes one exactly here, and must not when the issuer did publish the
	// user's language. Asserted end to end because it is resolved from stored
	// metadata by mdoc_dcql, not by the unit-tested resolver alone.
	require.True(t, choice.Credentials[0].DisplayIsFallback,
		"an en-only issuer against a Dutch wallet must be reported as a fallback")

	approvedRequestor := session.Requestor
	require.True(t, approvedRequestor.Verified,
		"the relying party certificate authenticated the request, and the screen must say so in any locale")
	grantPermission(t, c, 2, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	requireMdocVerifierResult(t, testSession.VerifierSession, "age", avDocType, avMandatoryElement, true)

	// The log is read back under "nl" too, so the read-time re-resolution runs with
	// the absent locale as well.
	requireMdocAvDisclosureLog(t, c, approvedRequestor)
}

// testOpenID4VP_MdocAv_UnauthorizedDocType asks for a docType the verifier's
// certificate does not authorize, and is the check that keeps the test above
// honest: it proves the authorization stage really runs against the certificate's
// scheme extension, so the passing case passes because eu.europa.ec.av.1 was
// added to that authorized set and not because the check was skipped.
//
// The refusal happens before any credential matching, so this one needs no
// credential in the wallet at all — and therefore no issuance.
func testOpenID4VP_MdocAv_UnauthorizedDocType(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	dcql := `{
		"credentials": [
		  {
			"id": "age",
			"format": "mso_mdoc",
			"meta": { "doctype_value": "eu.europa.ec.av.2" },
			"claims": [
			  { "path": ["eu.europa.ec.av.2", "age_over_18"] }
			]
		  }
		]
	}`

	testSession := startOpenID4VPSession(t, c, 1, sessionHandler, dcql)
	session := testSession.ClientSession

	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_Error, session.Status)
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError,
		"credential eu.europa.ec.av.2 is not in the authorized set")
}

func testOpenID4VP_MdocAv_Disclosure(t *testing.T) {
	runMdocAvDisclosure(t, testdata.OpenID4VP_DirectPostJwt_Host)
}

// testOpenID4VP_MdocAv_DisclosureDirectPost runs the same disclosure against the
// direct_post verifier.
//
// This is the response mode the AV Blueprint's Annex A §A.6 requires, and it is
// not the same code path: the handover carries a CBOR null where direct_post.jwt
// carries the response encryption key's thumbprint, so a bug in either branch of
// that choice shows up in exactly one of these two subtests.
func testOpenID4VP_MdocAv_DisclosureDirectPost(t *testing.T) {
	runMdocAvDisclosure(t, testdata.OpenID4VP_DirectPost_Host)
}

func runMdocAvDisclosure(t *testing.T, verifierHost string) {
	t.Helper()

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	// The credential is issued for real, over OpenID4VCI from the reference
	// issuer, rather than written into storage by the test. What is presented
	// below is then whatever issuance actually produced and stored -- device key,
	// batch, cached claims and all -- so a fault anywhere in that half shows up
	// here instead of being papered over by a fixture that agrees with the reader.
	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	// Session 1 was the issuance, so the presentation is session 2.
	testSession, requestJwt := startMdocAvSessionCapturingRequest(t, c, 2, sessionHandler,
		verifierHost, createAvMdocAuthRequest(t))

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)

	// The permission screen names the credential, its issuer and the claim, all
	// three resolved from the issuer metadata that OpenID4VCI fetched at issuance.
	// Nothing here is mdoc-specific in the wallet: the same
	// services.IssuerNamesByLanguage / credential_metadata plumbing serves SD-JWT.
	//
	// This is asserted literally on purpose. These subtests used to run on a seeded
	// batch that carried neither IssuerDisplay nor CredentialMetadata, so the plan
	// really did come back with the raw docType as the name, no claim label and an
	// empty issuer name -- and the assertions here encoded that as correct. It read
	// as a gap in mdoc display support; it was the fixture.
	//
	// The claim path stays the two-component [namespace, elementIdentifier] form
	// mdoc matching requires; a label never replaces it.
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{{
					CredentialId: avDocType,
					Name:         avCredentialDisplayName,
					IssuerName:   avIssuerDisplayName,
					Attributes: []expectedAttr{
						{
							Path:        []any{avDocType, "age_over_18"},
							DisplayName: new(avAgeOver18DisplayName),
							Value:       boolVal(true),
						},
					},
				}},
			},
		},
	})

	// The permission screen and the credential list are built by different code
	// (mdoc_dcql.FindCandidates and services.CredentialService), and a user who
	// approves a disclosure is trusting that the screen names the same issuer the
	// list does. Pinning both to the literal above would let them drift apart
	// without either assertion noticing, so cross-check them against each other.
	require.Equal(t, avIssuerDisplayName, avMdocIssuerName(t, c),
		"the credential list and the permission screen must name the issuer identically")

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]

	// The other half of the pair asserted in the Dutch subtest: this wallet asked
	// for the language the issuer publishes, so the frontend must leave the text
	// alone. A flag stuck at true would have it override every issuer's labels.
	require.False(t, choice.Credentials[0].DisplayIsFallback,
		"an English wallet against an en-publishing issuer is not a fallback")

	// Kept for the log assertion below, which checks the entry is filed under the
	// verifier the permission screen actually named.
	approvedRequestor := session.Requestor
	grantPermission(t, c, 2, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	response := requireMdocVerifierResult(t, testSession.VerifierSession, "age", avDocType, "age_over_18", true)

	// The assertions above only establish what the verifier *received*. They pass
	// whether or not deviceAuth actually verifies, because the container is not
	// known to check it — and a handover the verifier cannot reproduce is silent
	// in the wallet and fatal only at a verifier that does check. So verify the
	// signature here, against a transcript rebuilt from the request the wallet was
	// actually given.
	requireDeviceAuthVerifies(t, response, avSessionTranscript(t, requestJwt))

	requireMdocAvDisclosureLog(t, c, approvedRequestor)
}

// requireMdocAvDisclosureLog checks the wallet recorded the presentation in its
// activity log.
//
// MdocDcqlHandler.buildLogCredential is the only mdoc-specific code on the
// logging path, and nothing else in the suite runs it: it has to turn a
// namespace/elementIdentifier claim selection into the qualified
// [namespace, elementIdentifier] attribute paths the rest of the wallet
// addresses mdoc claims by, and read values out of the batch's namespaced claim
// map rather than an SD-JWT's flat payload. The mdoc removal log covered in
// eudi_logs_test.go goes through format-agnostic code instead, so it does not
// exercise any of this.
//
// A log entry is written after the response has already gone out, so a fault
// here reaches the user's activity screen while the session and the verifier
// both report success.
func requireMdocAvDisclosureLog(t *testing.T, c *client.Client, approvedRequestor clientmodels.TrustedParty) {
	t.Helper()

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	// Exactly one disclosure entry, not one entry: the log also carries the
	// OpenID4VCI issuance that put the credential in this wallet. Counting
	// disclosures is what rules out the session being logged twice, which the
	// merged read path across the two stores makes possible.
	disclosureCount := 0
	for _, entry := range logs {
		if entry.Type == clientmodels.LogType_Disclosure {
			disclosureCount++
		}
	}
	require.Equal(t, 1, disclosureCount, "the presentation should be logged exactly once")

	disclosureLog := findLog(logs, clientmodels.LogType_Disclosure)
	require.NotNil(t, disclosureLog, "an mdoc disclosure should create a disclosure log")
	require.NotNil(t, disclosureLog.DisclosureLog)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, disclosureLog.DisclosureLog.Protocol)

	// Compared against the requestor the permission screen showed rather than a
	// hardcoded name: that is the property worth asserting — the entry names the
	// verifier the user approved — and it does not pin the container's
	// certificate subject.
	require.NotNil(t, disclosureLog.DisclosureLog.Verifier)
	require.Equal(t, approvedRequestor.Id, disclosureLog.DisclosureLog.Verifier.Id)
	require.Equal(t, approvedRequestor.Name, disclosureLog.DisclosureLog.Verifier.Name)
	// The log must agree with the screen the user approved. This one was dropped
	// on write, so an entry could carry the id and name of a verifier whose
	// request a certificate had authenticated, and call it unverified in the
	// same breath.
	require.Equal(t, approvedRequestor.Verified, disclosureLog.DisclosureLog.Verifier.Verified,
		"the disclosure log must record the verifier the same way the permission screen showed it")

	require.Len(t, disclosureLog.DisclosureLog.Credentials, 1)
	logged := disclosureLog.DisclosureLog.Credentials[0]
	require.Equal(t, avDocType, logged.CredentialId)
	require.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_MsoMdoc}, logged.Formats,
		"the disclosure log must file the entry under mso_mdoc, which is what every format-keyed read depends on")
	// The same name the permission screen showed, asserted through the constant the
	// disclosure plan above uses so the two cannot drift apart. This is the case
	// where a read-time re-resolution against live credential metadata could
	// overwrite the snapshot with an empty string, which is why it is the resolved
	// display name that is pinned here and not the docType.
	//
	// This asserted the raw docType until the seeded fixture was removed, "because
	// the AV profile publishes no display metadata". The profile does not, but the
	// issuer does, and the credential is issued by the issuer.
	require.Equal(t, avCredentialDisplayName, logged.Name)

	// The disclosed claim keeps its qualified path, with the value resolved from
	// the batch's namespaced claim map, and carries the label the issuer published
	// for it — a label never replaces the path.
	requireAttrsInOrder(t, logged.Attributes, expectedAttr{
		Path:        []any{avDocType, "age_over_18"},
		DisplayName: new(avAgeOver18DisplayName),
		Value:       boolVal(true),
	})

	// The batch timestamps come along; they are what dates the entry in the UI.
	require.NotNil(t, logged.IssuanceDate, "disclosure log should carry the issuance date")
	require.NotNil(t, logged.ExpiryDate, "disclosure log should carry the expiry date")
}

// startMdocAvSessionCapturingRequest starts a verifier session and hands the
// wallet the request object, returning it to the caller as well.
//
// It exists because the transcript deviceAuth signs over can only be rebuilt
// from the authorization request, and none of its inputs are obtainable any
// other way: the verifier mints a per-session response_uri
// (…/wallet/direct_post/<token>) and, in direct_post.jwt mode, a per-session
// response encryption key, both of which live only inside the request object.
// That object is single-use — a second fetch of request_uri answers 400 — so the
// test cannot simply read it alongside the wallet.
//
// So it is fetched once here and re-served to the wallet verbatim from a local
// server. The bytes are untouched, signature and x5c included, so the wallet
// authenticates exactly the request the verifier signed; only the URL it was
// retrieved from differs, and that URL is not part of what the wallet verifies.
func startMdocAvSessionCapturingRequest(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
	verifierHost string,
	authRequestJson string,
) (openID4VPTestSession, string) {
	t.Helper()

	verifierSession, err := StartTestSessionAtEudiVerifier(verifierHost, authRequestJson)
	require.NoError(t, err)

	link, err := url.Parse(verifierSession.SessionLink)
	require.NoError(t, err)
	query := link.Query()
	requestUri := query.Get("request_uri")
	require.NotEmpty(t, requestUri, "the verifier must hand out a request_uri to capture")

	requestJwt := fetchAuthorizationRequest(t, requestUri)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(requestJwt))
	}))
	t.Cleanup(server.Close)

	query.Set("request_uri", server.URL)
	// Built by hand rather than through url.URL: a Scheme carrying its own "//"
	// makes String() emit "eudi-openid4vp://:?...", with a stray colon.
	sessionRequest, err := json.Marshal(client.SessionRequestData{
		Type:     irma.ActionDisclosing,
		URL:      "eudi-openid4vp://?" + query.Encode(),
		Protocol: clientmodels.Protocol_OpenID4VP,
	})
	require.NoError(t, err)

	c.NewSession(sessionId, string(sessionRequest))
	return openID4VPTestSession{
		ClientSession:   awaitSessionState(t, sessionHandler),
		VerifierSession: verifierSession,
	}, requestJwt
}

// fetchAuthorizationRequest retrieves the request object once. The transaction was
// started with request_uri_method "get", and the verifier enforces the method it
// was started with, so this is a GET with no wallet_nonce.
func fetchAuthorizationRequest(t *testing.T, requestUri string) string {
	t.Helper()

	response, err := http.Get(requestUri)
	require.NoError(t, err)
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode,
		"fetching the request object failed: %s", string(body))

	return strings.TrimSpace(string(body))
}

// avSessionTranscript rebuilds the SessionTranscript the wallet's deviceAuth
// signed over, from the authorization request it was given.
//
// This deliberately re-derives the handover rather than calling the wallet's own
// newOpenID4VPSessionTranscript: a check that reuses the code under test agrees
// with itself no matter which formula it implements, and getting the formula
// wrong is precisely the failure this test is here to catch. The construction is
// the one in eudi/openid4vp/mdoc_dcql/sessiontranscript.go, which follows
// Multipaz's vpSessionTranscript:
//
//	HandoverInfo      = [clientId, nonce, jwkThumbprint, responseUri]
//	Handover          = ["OpenID4VPHandover", SHA-256(CBOR(HandoverInfo))]
//	SessionTranscript = [null, null, Handover]
func avSessionTranscript(t *testing.T, requestJwt string) stdmdoc.SessionTranscript {
	t.Helper()

	var request struct {
		ClientId       string `json:"client_id"`
		Nonce          string `json:"nonce"`
		ResponseUri    string `json:"response_uri"`
		ResponseMode   string `json:"response_mode"`
		ClientMetadata *struct {
			Jwks json.RawMessage `json:"jwks"`
		} `json:"client_metadata"`
	}

	segments := strings.Split(requestJwt, ".")
	require.Len(t, segments, 3, "the request object is a compact JWS")
	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(payload, &request))

	require.NotEmpty(t, request.ClientId)
	require.NotEmpty(t, request.ResponseUri)

	var thumbprint []byte
	if request.ResponseMode == "direct_post.jwt" {
		require.NotNil(t, request.ClientMetadata, "an encrypted response mode must publish client_metadata")
		thumbprint = responseEncryptionKeyThumbprint(t, request.ClientMetadata.Jwks)
	}

	handoverInfo := []any{request.ClientId, request.Nonce, encryptionKeyElement(thumbprint), request.ResponseUri}
	handoverInfoBytes, err := cbor.Marshal(handoverInfo)
	require.NoError(t, err)
	digest := sha256.Sum256(handoverInfoBytes)

	return stdmdoc.SessionTranscript{
		Handover: []any{"OpenID4VPHandover", digest[:]},
	}
}

// encryptionKeyElement renders the third HandoverInfo element: the thumbprint
// when the response is encrypted, CBOR null when it is not. Spelled out rather
// than relying on a nil []byte encoding as null, so the shape does not depend on
// that detail.
func encryptionKeyElement(thumbprint []byte) any {
	if len(thumbprint) == 0 {
		return nil
	}
	return thumbprint
}

// responseEncryptionKeyThumbprint picks the key the response is encrypted to and
// returns its SHA-256 JWK thumbprint. The selection mirrors the wallet's
// selectResponseEncryptionKey: the first published key carrying an alg. A
// verifier publishing several usable keys would make the two disagree, and the
// deviceAuth check below is what would report it.
func responseEncryptionKeyThumbprint(t *testing.T, jwks json.RawMessage) []byte {
	t.Helper()

	set, err := jwk.Parse(jwks)
	require.NoError(t, err)

	for i := range set.Len() {
		key, ok := set.Key(i)
		if !ok {
			continue
		}
		if _, ok := key.Algorithm(); !ok {
			continue
		}
		thumbprint, err := key.Thumbprint(crypto.SHA256)
		require.NoError(t, err)
		return thumbprint
	}

	t.Fatalf("client_metadata carries no usable response encryption key: %s", string(jwks))
	return nil
}

// requireDeviceAuthVerifies verifies the presented DeviceResponse the way a
// verifier that checks device binding would: issuer signature and digests
// against the run's IACA, then deviceAuth against the given transcript.
//
// A mismatch here means the wallet signed over a transcript the verifier cannot
// reproduce — the response still transmits fine, which is why nothing earlier in
// the test notices.
func requireDeviceAuthVerifies(
	t *testing.T,
	response stdmdoc.DeviceResponse,
	transcript stdmdoc.SessionTranscript,
) {
	t.Helper()

	verifier := stdmdoc.NewVerifier([]*x509.Certificate{eudiPidIssuerPyCACert(t)})
	results, err := verifier.VerifyDeviceResponse(response, avDocType, avDocType, transcript)
	require.NoError(t, err)
	require.Len(t, results, 1)

	result := results[0]
	require.True(t, result.Valid, "presented mdoc did not verify: %s", result.Error)
	require.True(t, result.DeviceAuthValid,
		"deviceAuth did not verify against the rebuilt session transcript: %s", result.Error)
	require.Equal(t, true, result.Attributes["age_over_18"])
}

// requireMdocVerifierResult fetches the wallet response from the verifier and
// checks that the vp_token holds a DeviceResponse disclosing exactly the
// requested element, returning that DeviceResponse so the caller can verify its
// signatures.
//
// An mso_mdoc vp_token entry is base64url-encoded CBOR rather than the compact
// JWS the SD-JWT helpers expect, so this cannot reuse requireVerifierResult:
// the value has to be decoded into a DeviceResponse and its issuerSigned items
// unwrapped from their Tag-24 envelopes to read the disclosed claim back.
func requireMdocVerifierResult(
	t *testing.T,
	verifierSession EudiVerifierSession,
	queryId string,
	expectedDocType string,
	expectedElement string,
	expectedValue any,
) stdmdoc.DeviceResponse {
	t.Helper()

	result, err := GetWalletResponseFromEudiVerifier(verifierSession)
	require.NoError(t, err)
	require.Nil(t, result["error"], "verifier returned error: %v", result["error_description"])

	vpToken, ok := result["vp_token"].(map[string]any)
	require.True(t, ok, "vp_token should be a JSON object, got %T", result["vp_token"])

	entry, ok := vpToken[queryId]
	require.True(t, ok, "vp_token should carry query id %q, got keys %v", queryId, vpToken)

	// The token is either the encoded DeviceResponse itself or a single-element
	// array of them, depending on how the verifier reports one presentation.
	encoded, ok := entry.(string)
	if !ok {
		list, isList := entry.([]any)
		require.True(t, isList, "vp_token[%q] should be a string or array, got %T", queryId, entry)
		require.Len(t, list, 1, "expected exactly one presentation for query %q", queryId)
		encoded, ok = list[0].(string)
		require.True(t, ok, "vp_token[%q][0] should be a string, got %T", queryId, list[0])
	}

	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(encoded)
	}
	require.NoError(t, err, "vp_token entry should be base64-encoded CBOR")

	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(raw, &response), "vp_token entry should decode as a DeviceResponse")

	require.Equal(t, uint64(0), response.Status, "DeviceResponse status should be OK")
	require.Len(t, response.Documents, 1)

	document := response.Documents[0]
	require.Equal(t, expectedDocType, document.DocType)
	require.NotNil(t, document.DeviceSigned, "the presented document must carry a DeviceSigned")

	items, ok := document.IssuerSigned.NameSpaces[expectedDocType]
	require.True(t, ok, "namespace %q should be disclosed, got %v", expectedDocType,
		namespaceKeys(document.IssuerSigned.NameSpaces))
	require.Len(t, items, 1, "exactly the requested element should be disclosed")

	disclosed := decodeIssuerSignedItem(t, items[0])
	require.Equal(t, expectedElement, disclosed.ElementIdentifier)
	require.Equal(t, expectedValue, disclosed.ElementValue)

	return response
}

// decodeIssuerSignedItem unwraps one Tag-24 wrapped issuerSigned item. The outer
// Tag-24 has to be peeled before the inner byte string decodes as an item; the
// bytes are treated as read-only here since re-encoding them would break the
// digest they were hashed under.
func decodeIssuerSignedItem(t *testing.T, item stdmdoc.Tag24Item) stdmdoc.IssuerSignedItem {
	t.Helper()

	var rawTag cbor.RawTag
	require.NoError(t, cbor.Unmarshal(item.EncodedItem, &rawTag))
	require.Equal(t, uint64(24), rawTag.Number, "issuerSigned items are Tag-24 wrapped")

	var inner []byte
	require.NoError(t, cbor.Unmarshal(rawTag.Content, &inner))

	var decoded stdmdoc.IssuerSignedItem
	require.NoError(t, cbor.Unmarshal(inner, &decoded))
	return decoded
}

func namespaceKeys(namespaces map[string][]stdmdoc.Tag24Item) []string {
	keys := make([]string, 0, len(namespaces))
	for key := range namespaces {
		keys = append(keys, key)
	}
	return keys
}

// eudiPidIssuerPyCACert parses the issuer CA the containers are configured with,
// so a test can verify a presented mdoc the way the verifier does. It is the
// trust anchor for the document signer inside the MSO, which is the only reason
// this test can check the issuer signature at all.
func eudiPidIssuerPyCACert(t *testing.T) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode(readEudiPidIssuerPyCA(t))
	require.NotNil(t, block, "the issuer CA file should hold a PEM block")

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	return cert
}

// avMdocIssuerName reports the issuer name the credential list carries for the
// age credential, which is what the permission screen is compared against.
func avMdocIssuerName(t *testing.T, c *client.Client) string {
	t.Helper()

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	return findMdocCredentialByDocType(t, creds, avDocType).Issuer.Name
}
