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
	"sync/atomic"
	"testing"
	"time"

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

	// Requests the reference verifier would never send, each one thing away from
	// the request the subtests above accept. They sit here rather than in a
	// violations group of their own because what they establish is a property of
	// this disclosure: it succeeds because the request authenticated a relying
	// party the wallet trusts, and not because the wallet accepts what it is given.
	// The rig that mints them is helper_mdoc_request_variants_test.go.
	t.Run("a re-signed but unmodified request is still accepted",
		testOpenID4VP_MdocAv_ControlMintedUnmodified)
	t.Run("a corrupted request signature is refused",
		testOpenID4VP_MdocAv_CorruptSignature)
	t.Run("alg none with the signature stripped is refused",
		testOpenID4VP_MdocAv_AlgNone)
	t.Run("an absent typ header is refused",
		testOpenID4VP_MdocAv_MissingTyp)
	t.Run("an absent x5c header is refused",
		testOpenID4VP_MdocAv_NoX5c)
	t.Run("a client_id naming a host the certificate has no SAN for is refused",
		testOpenID4VP_MdocAv_ClientIdSanMismatch)
	t.Run("a redirect_uri client_id is refused",
		testOpenID4VP_MdocAv_RedirectUriClientId)

	// Queries the relying party's certificate does not authorize, or that no
	// credential in the wallet can answer. The authorized set lives in the
	// certificate's scheme extension, so these are the other half of the
	// unauthorized-docType subtest above: it covers the credential, these cover
	// the attributes and the shape of the query.
	t.Run("an attribute outside the authorized set is refused",
		testOpenID4VP_MdocAv_AttributeNotAuthorized)
	t.Run("an attribute the AV profile forbids is refused",
		testOpenID4VP_MdocAv_ForbiddenAttribute)
	t.Run("the wrong format for a credential the wallet holds is refused",
		testOpenID4VP_MdocAv_WrongFormat)
	t.Run("a claim path in another namespace matches nothing",
		testOpenID4VP_MdocAv_WrongNamespace)
	t.Run("the verifier refuses a one-element mdoc claim path",
		testOpenID4VP_MdocAv_MalformedClaimPath)

	// The semantics of a validly signed request: every one of these carries the
	// verifier's real certificate and a signature that verifies, and is refused for
	// what it asks rather than for who asked. They are the reason the signature
	// subtests above are not the whole story — a request can authenticate its
	// sender perfectly and still be one no wallet should honour.
	t.Run("the verifier refuses a session request with no nonce",
		testOpenID4VP_MdocAv_NoNonceAtVerifier)
	t.Run("a request object with no nonce is refused",
		testOpenID4VP_MdocAv_NonceAbsent)
	t.Run("an empty nonce is refused",
		testOpenID4VP_MdocAv_NonceEmpty)
	t.Run("a response_type other than vp_token is refused",
		testOpenID4VP_MdocAv_ResponseTypeCode)
	t.Run("a dc_api response mode on a URL-invoked session is refused",
		testOpenID4VP_MdocAv_DcApiResponseModeOnRedirectPath)
	t.Run("an unrecognised response_mode is refused",
		testOpenID4VP_MdocAv_UnknownResponseMode)
	t.Run("a request issued far in the future is refused",
		testOpenID4VP_MdocAv_IatFarFuture)
	t.Run("a request that expired long ago is refused",
		testOpenID4VP_MdocAv_LongExpired)
	t.Run("direct_post.jwt with no jwks to encrypt to is refused",
		testOpenID4VP_MdocAv_EncryptedResponseWithoutJwks)
	t.Run("an aud naming another wallet is accepted, deliberately",
		testOpenID4VP_MdocAv_AudienceNotValidated)

	// Which certificate may authenticate a relying party. Each of these signs a
	// request the wallet can read perfectly, with a certificate that is wrong in
	// exactly one way, and each pins the refusal *reason*: an expired certificate
	// refused as "unknown authority" would mean the date check never ran, and the
	// subtest would pass while covering nothing.
	t.Run("a self-signed relying party certificate is refused",
		testOpenID4VP_MdocAv_SelfSignedCertificate)
	t.Run("the issuer's own certificate cannot authenticate a verifier",
		testOpenID4VP_MdocAv_IssuerCertificateAsVerifier)
	t.Run("an expired relying party certificate is refused",
		testOpenID4VP_MdocAv_ExpiredCertificate)
	t.Run("a not-yet-valid relying party certificate is refused",
		testOpenID4VP_MdocAv_NotYetValidCertificate)
	t.Run("the trust anchor itself cannot act as the leaf",
		testOpenID4VP_MdocAv_CaCertificateAsLeaf)
	t.Run("an x5c leaf that is not the signer is refused",
		testOpenID4VP_MdocAv_X5cLeafIsNotTheSigner)
	t.Run("an empty x5c array is refused",
		testOpenID4VP_MdocAv_X5cEmptyArray)

	// The JWS itself, rather than what it says. No reason is pinned for these
	// three: the messages come from the JWT library, which this repository has
	// just moved across a major version, and any acceptance fails the subtest
	// regardless of what the refusal says.
	t.Run("an algorithm-confusion HS256 request is refused",
		testOpenID4VP_MdocAv_AlgConfusionHS256)
	t.Run("an alg that does not match the key's curve is refused",
		testOpenID4VP_MdocAv_AlgMismatchES384)
	t.Run("a two-segment request object is refused",
		testOpenID4VP_MdocAv_TwoSegmentJwt)

	// The fetch rather than its contents. request_uri is a URL the wallet is sent
	// to by a link, so what comes back is whatever that host decides to send.
	t.Run("a request_uri serving HTML is refused",
		testOpenID4VP_MdocAv_RequestUriServesHtml)
	t.Run("a request_uri answering with a server error is refused",
		testOpenID4VP_MdocAv_RequestUriServerError)

	// The shape of the query itself. The reference verifier catches the malformed
	// paths at session creation, so those are asserted against the container; the
	// rest are minted, because a request the container would not produce can only
	// reach the wallet that way.
	t.Run("the verifier refuses a three-element mdoc claim path",
		testOpenID4VP_MdocAv_ClaimPathTooDeep)
	t.Run("the verifier refuses an empty claim path",
		testOpenID4VP_MdocAv_ClaimPathEmpty)
	t.Run("the verifier refuses an mdoc query with no doctype_value",
		testOpenID4VP_MdocAv_MdocQueryWithoutMeta)
	t.Run("a request with neither dcql_query nor scope is refused",
		testOpenID4VP_MdocAv_NoDcqlQuery)
	t.Run("scope and dcql_query together are refused",
		testOpenID4VP_MdocAv_ScopeAndDcqlTogether)
	t.Run("two credential queries sharing an id are refused",
		testOpenID4VP_MdocAv_DuplicateQueryIds)
	t.Run("a required credential_set naming an unknown query id is refused",
		testOpenID4VP_MdocAv_CredentialSetsUnsatisfiable)
	t.Run("a credential_set with an empty options array is refused",
		testOpenID4VP_MdocAv_CredentialSetEmptyOptions)

	// Parameters the link and the request object carry between them.
	t.Run("a link client_id that differs from the signed one is refused",
		testOpenID4VP_MdocAv_LinkClientIdMismatch)
	t.Run("an empty client_id is refused",
		testOpenID4VP_MdocAv_ClientIdEmpty)
	t.Run("a client_id with no scheme prefix is refused",
		testOpenID4VP_MdocAv_ClientIdNoPrefix)
	t.Run("a nonce with non-URL-safe characters is refused",
		testOpenID4VP_MdocAv_NonceNotUrlSafe)
	t.Run("direct_post with no response_uri is refused",
		testOpenID4VP_MdocAv_ResponseUriAbsent)
	t.Run("response_uri and redirect_uri together are refused",
		testOpenID4VP_MdocAv_ResponseAndRedirectUriTogether)

	// What happens to a presentation after the wallet has made it. The first is the
	// wallet's own guard; the other two are the verifier's, and asserted because
	// this wallet's single-use attestations and transcript binding are only worth
	// what the party receiving them enforces.
	t.Run("the wallet refuses to answer a response_uri on another host",
		testOpenID4VP_MdocAv_ResponseUriElsewhere)
	t.Run("a presentation replayed into another session is refused",
		testOpenID4VP_MdocAv_VpTokenReplay)
	t.Run("the same presentation submitted twice is refused",
		testOpenID4VP_MdocAv_DoubleSubmission)
}

// testOpenID4VP_MdocAv_ResponseUriElsewhere points response_uri at a host this
// wallet has never heard of and watches whether anything arrives there.
//
// The most consequential subtest in this file. Everything else here refuses a
// request; this one is about where a *response* goes — and a response carries the
// disclosed attributes. A relying party authenticated for localhost that can name
// any response_uri it likes can have the presentation delivered somewhere its own
// certificate says nothing about.
//
// The wallet refuses before answering, comparing the response location's host
// against the client_id it authenticated. The local server is not there to receive
// the response but to prove it was never sent: a passing refusal assertion alone
// would not distinguish "refused" from "refused after posting".
func testOpenID4VP_MdocAv_ResponseUriElsewhere(t *testing.T) {
	var landed atomic.Int64

	exfiltration := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		landed.Add(int64(len(body) + 1))
		w.WriteHeader(http.StatusOK)
	}))
	defer exfiltration.Close()

	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	testSession, _ := startMdocAvSessionServingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, createAvMdocAuthRequest(t),
		mdocAvRequestOverrides{Transform: func(t *testing.T, requestJwt string) string {
			return mintRequestVariant(t, requestJwt, func(hdr, claims map[string]any) {
				claims["response_uri"] = exfiltration.URL + "/response"
				// An encrypted response would be unreadable to this server anyway,
				// and the question is where the wallet is willing to send one.
				claims["response_mode"] = "direct_post"
			})
		}})

	requireMdocViolationRefused(t, testSession.ClientSession)
	require.Contains(t, testSession.ClientSession.Error.WrappedError, "does not match client_id",
		"the refusal should be about where the response would go")
	require.Zero(t, landed.Load(),
		"the wallet posted something to a host the relying party certificate does not cover")
}

// testOpenID4VP_MdocAv_VpTokenReplay takes a genuine presentation and posts it into
// a different session.
//
// ISO 18013-5 §9.1.5: the session transcript binds a response to one request. The
// second session has its own nonce, so the deviceAuth signature over the first
// session's transcript cannot verify against it — which is why the verifier answers
// InvalidDeviceSignature rather than complaining about a duplicate.
//
// This also covers posting with a state from nowhere, which the old CLI listed
// separately: a mangled state fails identically, because the transcript check runs
// before any state handling and a captured token cannot satisfy it either way.
func testOpenID4VP_MdocAv_VpTokenReplay(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	// A genuine presentation, so there is a token the verifier accepted.
	testSession, _ := startMdocAvSessionCapturingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, createAvMdocAuthRequest(t))

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	grantPermission(t, c, 2, makeDisclosureChoice(session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]))
	requireSessionState(t, awaitSessionState(t, sessionHandler), 2,
		clientmodels.Type_Disclosure, clientmodels.Status_Success)

	captured := encodedVpToken(t, testSession.VerifierSession, "age")

	// A second, independent session with its own nonce and transcript. Its request
	// object is fetched here rather than by a wallet, so consuming the single-use
	// request_uri costs nothing.
	secondSession, err := StartTestSessionAtEudiVerifier(
		testdata.OpenID4VP_DirectPost_Host, createAvMdocAuthRequest(t))
	require.NoError(t, err)

	link, err := url.Parse(secondSession.SessionLink)
	require.NoError(t, err)
	secondRequest := fetchAuthorizationRequest(t, link.Query().Get("request_uri"))
	responseUri, state := responseBindingFromRequest(t, secondRequest)

	status, body := postVpTokenDirectly(t, responseUri, state, "age", captured)

	require.GreaterOrEqual(t, status, 400,
		"the verifier accepted a presentation bound to another session: %s", body)
	require.Contains(t, body, "InvalidDeviceSignature",
		"the refusal should be the transcript binding, not something incidental")
}

// testOpenID4VP_MdocAv_DoubleSubmission submits one genuine presentation twice, to
// the session it belongs to.
//
// The transcript matches, so nothing cryptographic stops it: only single-use
// handling of the transaction does, and the verifier answers
// PresentationNotInExpectedState. Worth asserting because the wallet's own
// single-use attestations assume the other side does not treat a completed
// transaction as still open — a verifier that accepted a second response would let
// a captured one be counted twice.
func testOpenID4VP_MdocAv_DoubleSubmission(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	testSession, requestJwt := startMdocAvSessionCapturingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, createAvMdocAuthRequest(t))

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	grantPermission(t, c, 2, makeDisclosureChoice(session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]))
	requireSessionState(t, awaitSessionState(t, sessionHandler), 2,
		clientmodels.Type_Disclosure, clientmodels.Status_Success)

	captured := encodedVpToken(t, testSession.VerifierSession, "age")
	responseUri, state := responseBindingFromRequest(t, requestJwt)

	status, body := postVpTokenDirectly(t, responseUri, state, "age", captured)

	require.GreaterOrEqual(t, status, 400,
		"the verifier accepted the same presentation a second time: %s", body)
	require.Contains(t, body, "PresentationNotInExpectedState",
		"the refusal should be the transaction's single-use handling")
}

// testOpenID4VP_MdocAv_ClaimPathTooDeep sends a three-element mdoc claim path.
//
// OID4VP 1.0 §6.4.1: exactly two, [namespace, elementIdentifier]. The other side of
// the one-element subtest above — a check written as "at least two" accepts this
// one, and then addresses an element that cannot exist.
func testOpenID4VP_MdocAv_ClaimPathTooDeep(t *testing.T) {
	requireVerifierRefusesCredentialQuery(t, map[string]any{
		"id":     "age",
		"format": string(clientmodels.Format_MsoMdoc),
		"meta":   map[string]any{"doctype_value": avDocType},
		"claims": []map[string]any{{"path": []string{avDocType, avMandatoryElement, "extra"}}},
	})
}

// testOpenID4VP_MdocAv_ClaimPathEmpty sends a claims entry whose path is empty.
//
// OID4VP 1.0 §6.4: a claim path must be non-empty. An empty path addresses the
// whole credential, which for an mdoc would be every element in every namespace —
// the opposite of selective disclosure.
func testOpenID4VP_MdocAv_ClaimPathEmpty(t *testing.T) {
	requireVerifierRefusesCredentialQuery(t, map[string]any{
		"id":     "age",
		"format": string(clientmodels.Format_MsoMdoc),
		"meta":   map[string]any{"doctype_value": avDocType},
		"claims": []map[string]any{{"path": []string{}}},
	})
}

// testOpenID4VP_MdocAv_MdocQueryWithoutMeta omits meta.doctype_value from an
// mso_mdoc query.
//
// OID4VP 1.0 §6.1 makes it REQUIRED for this format, and for good reason: it is the
// only thing in the query that says which credential is being asked for. Without it
// the claim paths name a namespace and nothing says which document that namespace
// belongs to.
func testOpenID4VP_MdocAv_MdocQueryWithoutMeta(t *testing.T) {
	requireVerifierRefusesCredentialQuery(t, map[string]any{
		"id":     "age",
		"format": string(clientmodels.Format_MsoMdoc),
		"claims": []map[string]any{{"path": []string{avDocType, avMandatoryElement}}},
	})
}

// testOpenID4VP_MdocAv_NoDcqlQuery removes dcql_query without supplying a scope.
//
// OID4VP 1.0 §5.1: one of the two MUST be present. A request that asks for nothing
// is not a request to answer — and a wallet that read it as "no constraints" rather
// than "malformed" would be one query away from disclosing everything.
func testOpenID4VP_MdocAv_NoDcqlQuery(t *testing.T) {
	requireMdocAvRefusal(t, mdocAvRefusalCase{
		ErrorContains: "neither a dcql_query nor a scope",
		Mutate: func(hdr, claims map[string]any) {
			delete(claims, "dcql_query")
		},
	})
}

// testOpenID4VP_MdocAv_ScopeAndDcqlTogether supplies both.
//
// OID4VP 1.0 §5.1 makes them mutually exclusive. They are two ways of saying what is
// requested, and honouring one while ignoring the other means the user is shown a
// request built from half of what arrived.
func testOpenID4VP_MdocAv_ScopeAndDcqlTogether(t *testing.T) {
	requireMdocAvRefusal(t, mdocAvRefusalCase{
		ErrorContains: "scope and dcql_query must not both be present",
		Mutate: func(hdr, claims map[string]any) {
			claims["scope"] = "proof_of_age"
		},
	})
}

// testOpenID4VP_MdocAv_DuplicateQueryIds repeats one credential query twice under
// the same id.
//
// OID4VP 1.0 §6.1 requires ids to be unique within a query, because the id is what
// the response is keyed by: vp_token is an object mapping query id to presentation,
// so two queries sharing an id cannot both be answered distinguishably.
func testOpenID4VP_MdocAv_DuplicateQueryIds(t *testing.T) {
	requireMdocAvRefusal(t, mdocAvRefusalCase{
		ErrorContains: "present more than once",
		Mutate: func(hdr, claims map[string]any) {
			query, ok := claims["dcql_query"].(map[string]any)
			require.True(t, ok, "the request should carry a dcql_query")
			credentials, ok := query["credentials"].([]any)
			require.True(t, ok)
			require.NotEmpty(t, credentials)
			query["credentials"] = []any{credentials[0], credentials[0]}
		},
	})
}

// testOpenID4VP_MdocAv_CredentialSetsUnsatisfiable requires a credential set naming
// a query id the request does not define.
//
// OID4VP 1.0 §6.2. A required set that cannot be satisfied by any combination of the
// queries present is a request that can never be answered, and the wallet should say
// so rather than answering the part it does understand.
func testOpenID4VP_MdocAv_CredentialSetsUnsatisfiable(t *testing.T) {
	requireMdocAvRefusal(t, mdocAvRefusalCase{
		ErrorContains: "references unknown credential query id",
		Mutate: func(hdr, claims map[string]any) {
			query, ok := claims["dcql_query"].(map[string]any)
			require.True(t, ok, "the request should carry a dcql_query")
			query["credential_sets"] = []any{
				map[string]any{"options": []any{[]any{"absent"}}, "required": true},
			}
		},
	})
}

// testOpenID4VP_MdocAv_CredentialSetEmptyOptions requires a credential set whose
// options array is empty.
//
// Distinct from the subtest above, where the options name an id the query does not
// define: here there are no options at all, so the set is unsatisfiable by
// construction rather than by reference.
func testOpenID4VP_MdocAv_CredentialSetEmptyOptions(t *testing.T) {
	requireMdocAvRefusal(t, mdocAvRefusalCase{
		ErrorContains: "empty options array",
		Mutate: func(hdr, claims map[string]any) {
			query, ok := claims["dcql_query"].(map[string]any)
			require.True(t, ok, "the request should carry a dcql_query")
			query["credential_sets"] = []any{
				map[string]any{"options": []any{}, "required": true},
			}
		},
	})
}

// testOpenID4VP_MdocAv_LinkClientIdMismatch leaves the request object untouched and
// changes only the client_id in the link the wallet was handed.
//
// OID4VP 1.0 §5.6. The link arrives out of band — a QR code, a deep link — and is
// unsigned; the request object is signed. If the two may disagree, the unsigned half
// can name any verifier it likes while the signed half authenticates another, and
// what the user is told about who is asking comes from the wrong one.
func testOpenID4VP_MdocAv_LinkClientIdMismatch(t *testing.T) {
	requireMdocAvRequestRefusedWithClientId(t, "x509_san_dns:other.example",
		func(hdr, claims map[string]any) {})
}

// testOpenID4VP_MdocAv_ClientIdEmpty empties the client_id inside the signed
// request while the link still carries the real one.
//
// OID4VP 1.0 §5.10: a verifier with no identifier cannot be authenticated, since
// there is nothing to match the certificate's SAN against.
func testOpenID4VP_MdocAv_ClientIdEmpty(t *testing.T) {
	requireMdocAvRequestRefusedWithClientId(t, "x509_san_dns:localhost",
		func(hdr, claims map[string]any) {
			claims["client_id"] = ""
		})
}

// testOpenID4VP_MdocAv_ClientIdNoPrefix uses a bare identifier with no scheme.
//
// OID4VP 1.0 §5.10 reads an unprefixed client_id as pre-registered, which assumes a
// registry both parties share. This wallet has none, so there is nothing to resolve
// the name against — distinct from the redirect_uri subtest, which names a scheme
// this wallet declines rather than no scheme at all.
func testOpenID4VP_MdocAv_ClientIdNoPrefix(t *testing.T) {
	const bare = "some-preregistered-verifier"

	requireMdocAvRequestRefusedWithClientId(t, bare, func(hdr, claims map[string]any) {
		claims["client_id"] = bare
	})
}

// testOpenID4VP_MdocAv_NonceNotUrlSafe sends a nonce containing spaces and symbols.
//
// OID4VP 1.0 §5.2. Distinct from the absent and empty subtests: this one is present
// and non-empty, and travels into the mdoc session transcript, so a value that does
// not survive a round trip through a URL is a transcript the verifier may rebuild
// differently — which fails as an invalid device signature, blaming the wrong thing.
func testOpenID4VP_MdocAv_NonceNotUrlSafe(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		claims["nonce"] = "nonce with spaces & symbols"
	})
}

// testOpenID4VP_MdocAv_ResponseUriAbsent asks for direct_post and gives nowhere to
// post to.
//
// OID4VP 1.0 §5.1 makes response_uri REQUIRED for that mode. redirect_uri is removed
// too, so there is genuinely no destination — a wallet that fell back to one would be
// choosing where to send a presentation itself.
func testOpenID4VP_MdocAv_ResponseUriAbsent(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		claims["response_mode"] = "direct_post"
		delete(claims, "response_uri")
		delete(claims, "redirect_uri")
	})
}

// testOpenID4VP_MdocAv_ResponseAndRedirectUriTogether supplies both destinations.
//
// OID4VP 1.0 §5.1: when response_uri is present, redirect_uri must not be. Two
// destinations in one request leave the choice to the wallet, and the one it does not
// pick is where the verifier is waiting.
func testOpenID4VP_MdocAv_ResponseAndRedirectUriTogether(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		claims["redirect_uri"] = "https://localhost/redirect"
	})
}

// testOpenID4VP_MdocAv_RequestUriServesHtml answers request_uri with a web page.
//
// OID4VP 1.0 §5.6. The realistic shape of this is not an attack but a
// misconfiguration — a reverse proxy answering an error page, a login redirect, a
// captive portal — and the wallet must end the session rather than try to make
// sense of it.
func testOpenID4VP_MdocAv_RequestUriServesHtml(t *testing.T) {
	requireMdocAvRequestUriRefused(t,
		"<!doctype html><html><body>not a request object</body></html>",
		"text/html", http.StatusOK)
}

// testOpenID4VP_MdocAv_RequestUriServerError answers request_uri with HTTP 500.
//
// A failed fetch must fail the session. The failure mode worth ruling out is a
// wallet that treats the request object as optional when it cannot be retrieved and
// falls back to the parameters in the link — which are unsigned, and which is the
// whole reason the request object exists.
func testOpenID4VP_MdocAv_RequestUriServerError(t *testing.T) {
	requireMdocAvRequestUriRefused(t,
		`{"error":"server_error"}`,
		"application/json", http.StatusInternalServerError)
}

// testOpenID4VP_MdocAv_AlgConfusionHS256 re-signs the request as HS256, using the
// public key its own x5c header advertises as the HMAC secret.
//
// RFC 8725 §3.1, and the oldest JWT attack there is. It works against any verifier
// that reads alg from the token and then asks for "the key": the certificate's
// public key is public, so anyone holding the request can compute a MAC over a
// payload of their choosing. Refusing it is what makes the x5c chain mean
// something — the chain here is the real one, untouched.
func testOpenID4VP_MdocAv_AlgConfusionHS256(t *testing.T) {
	requireMdocAvRefusal(t, mdocAvRefusalCase{RawTransform: resignAsHS256})
}

// testOpenID4VP_MdocAv_AlgMismatchES384 claims ES384 over a P-256 key.
//
// RFC 7518 §3.4 ties the algorithm to the curve. Distinct from the HS256 case: the
// family is right and only the curve is wrong, which is the variant an
// implementation that checks "is this an ECDSA alg" rather than "is this the
// algorithm this key can produce" would let through.
func testOpenID4VP_MdocAv_AlgMismatchES384(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		hdr["alg"] = "ES384"
	})
}

// testOpenID4VP_MdocAv_TwoSegmentJwt drops the signature segment entirely.
//
// RFC 7515 §3.1: a JWS has three segments. Not the same as alg:none, which keeps
// the shape and declares itself unsigned — this one is malformed, and must be
// refused while parsing rather than treated as an unsigned token that happens to
// have nothing after the second dot.
func testOpenID4VP_MdocAv_TwoSegmentJwt(t *testing.T) {
	requireMdocAvRefusal(t, mdocAvRefusalCase{RawTransform: dropJwtSignature})
}

// testOpenID4VP_MdocAv_SelfSignedCertificate signs the request with a certificate
// that is correct in every respect except that nothing vouches for it.
//
// ISO 18013-5 §9.1.4. Right common name, right SAN, matching client_id, internally
// consistent signature — only the anchor is missing. This is the property scenario
// 13 of the old CLI could not test reliably, because withholding the container's CA
// file stops creating an untrusted verifier the moment that CA is also compiled in
// as a trust anchor.
func testOpenID4VP_MdocAv_SelfSignedCertificate(t *testing.T) {
	key, der := selfSignedLocalhostCert(t)

	requireMdocAvRefusal(t, mdocAvRefusalCase{
		SigningKey:    key,
		ErrorContains: "certificate signed by unknown authority",
		Mutate: func(hdr, claims map[string]any) {
			hdr["x5c"] = x5cHeader(der)
		},
	})
}

// testOpenID4VP_MdocAv_IssuerCertificateAsVerifier signs the request with the PID
// issuer's document signer identity.
//
// The sharpest of these: this chain *is* trusted by the wallet, and the signature
// is genuine — but it is trusted in the issuer store, and a request comes from a
// relying party. Keeping the two stores apart is what stops an issuer, which the
// wallet must trust to sign credentials, from also being able to ask for them.
func testOpenID4VP_MdocAv_IssuerCertificateAsVerifier(t *testing.T) {
	key, chain := pidIssuerSigningIdentity(t)

	requireMdocAvRefusal(t, mdocAvRefusalCase{
		SigningKey:    key,
		ErrorContains: "certificate signed by unknown authority",
		Mutate: func(hdr, claims map[string]any) {
			hdr["x5c"] = x5cHeader(chain...)
		},
	})
}

// testOpenID4VP_MdocAv_ExpiredCertificate presents a leaf that expired a month ago.
//
// RFC 5280 §6.1.3. Issued by the CA the wallet trusts, correct SAN, valid
// signature — only the dates are wrong, which is what makes the pinned reason
// worth having.
func testOpenID4VP_MdocAv_ExpiredCertificate(t *testing.T) {
	key, leaf := mintRelyingPartyLeaf(t,
		time.Now().Add(-400*24*time.Hour), time.Now().Add(-30*24*time.Hour))

	requireMdocAvRefusal(t, mdocAvRefusalCase{
		SigningKey:    key,
		ErrorContains: "expired or is not yet valid",
		Mutate: func(hdr, claims map[string]any) {
			hdr["x5c"] = x5cHeader(leaf)
		},
	})
}

// testOpenID4VP_MdocAv_NotYetValidCertificate presents a leaf that becomes valid
// next month.
//
// The other side of the window. Worth its own subtest because a validity check
// written as "notAfter is in the past" passes every expired-certificate test and
// accepts this one.
func testOpenID4VP_MdocAv_NotYetValidCertificate(t *testing.T) {
	key, leaf := mintRelyingPartyLeaf(t,
		time.Now().Add(30*24*time.Hour), time.Now().Add(400*24*time.Hour))

	requireMdocAvRefusal(t, mdocAvRefusalCase{
		SigningKey:    key,
		ErrorContains: "expired or is not yet valid",
		Mutate: func(hdr, claims map[string]any) {
			hdr["x5c"] = x5cHeader(leaf)
		},
	})
}

// testOpenID4VP_MdocAv_CaCertificateAsLeaf presents the trust anchor itself as the
// end-entity certificate, signing with the root's own key.
//
// The most trusted certificate the wallet holds, which is exactly why it must not
// be able to act as a relying party. Note what the refusal actually says: the CA
// carries no SAN, so it fails the name match against the client_id rather than a
// basicConstraints check. That is a real refusal and pinned as such — but it means
// a CA certificate that *did* carry a matching SAN would need the separate check to
// stop it, so the reason is recorded here rather than assumed.
func testOpenID4VP_MdocAv_CaCertificateAsLeaf(t *testing.T) {
	caCert, caKey := relyingPartyCA(t)

	requireMdocAvRefusal(t, mdocAvRefusalCase{
		SigningKey:    caKey,
		ErrorContains: "not valid for any names",
		Mutate: func(hdr, claims map[string]any) {
			hdr["x5c"] = x5cHeader(caCert.Raw)
		},
	})
}

// testOpenID4VP_MdocAv_X5cLeafIsNotTheSigner presents one trusted certificate and
// signs with another's key.
//
// Both leaves are legitimately issued by the trusted CA for localhost, so every
// certificate here is trustworthy and the signature is well formed — they simply do
// not belong together. A wallet that verified the chain and the signature
// independently, without checking that the signature verifies against the leaf it
// just trusted, would accept this.
func testOpenID4VP_MdocAv_X5cLeafIsNotTheSigner(t *testing.T) {
	_, decoy := mintRelyingPartyLeaf(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	signingKey, _ := mintRelyingPartyLeaf(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	requireMdocAvRefusal(t, mdocAvRefusalCase{
		SigningKey:    signingKey,
		ErrorContains: "signature is invalid",
		Mutate: func(hdr, claims map[string]any) {
			hdr["x5c"] = x5cHeader(decoy)
		},
	})
}

// testOpenID4VP_MdocAv_X5cEmptyArray sends an x5c header that is present and empty.
//
// Distinct from the absent-x5c subtest above: an empty array names no certificate
// while satisfying any check that only asks whether the header exists.
func testOpenID4VP_MdocAv_X5cEmptyArray(t *testing.T) {
	requireMdocAvRefusal(t, mdocAvRefusalCase{
		ErrorContains: "empty x5c array",
		Mutate: func(hdr, claims map[string]any) {
			hdr["x5c"] = []any{}
		},
	})
}

// testOpenID4VP_MdocAv_NoNonceAtVerifier omits the nonce from the session request
// sent to the container.
//
// AV Annex A §A.6 requires it, and the container enforces it at session creation,
// so this never reaches a wallet. Asserted anyway because it is the reason the
// subtest below has to mint its own request: without knowing the container refuses
// first, "the wallet rejects a nonce-less request" could not be tested at all.
func testOpenID4VP_MdocAv_NoNonceAtVerifier(t *testing.T) {
	authRequest := createAvMdocSessionRequest(t, map[string]any{
		"id":     "age",
		"format": string(clientmodels.Format_MsoMdoc),
		"meta":   map[string]any{"doctype_value": avDocType},
		"claims": []map[string]any{{"path": []string{avDocType, avMandatoryElement}}},
	}, func(request map[string]any) {
		delete(request, "nonce")
	})

	_, err := StartTestSessionAtEudiVerifier(testdata.OpenID4VP_DirectPost_Host, authRequest)
	require.Error(t, err, "the verifier should refuse to start a session with no nonce")
	require.Contains(t, err.Error(), "MissingNonce",
		"the refusal should name the reason, so a container change is visible here")
}

// testOpenID4VP_MdocAv_NonceAbsent removes the nonce from the signed request.
//
// OID4VP 1.0 §5.1 makes it REQUIRED, and for mdoc it is load-bearing rather than
// hygienic: the nonce goes into the session transcript deviceAuth signs over, so
// without one there is nothing tying the response to this request and a captured
// presentation would replay forever.
func testOpenID4VP_MdocAv_NonceAbsent(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		delete(claims, "nonce")
	})
}

// testOpenID4VP_MdocAv_NonceEmpty sends a nonce that is the empty string.
//
// The same property as above, one step subtler: a present-but-empty value passes
// any check that only asks whether the claim exists, and produces a transcript
// every session would share.
func testOpenID4VP_MdocAv_NonceEmpty(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		claims["nonce"] = ""
	})
}

// testOpenID4VP_MdocAv_ResponseTypeCode asks for an authorization code.
//
// AV Annex A §A.6: the response type MUST be vp_token. A wallet that honoured
// `code` here would be starting an OAuth authorization flow in answer to a
// presentation request — a different protocol with a different security model.
func testOpenID4VP_MdocAv_ResponseTypeCode(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		claims["response_type"] = "code"
	})
}

// testOpenID4VP_MdocAv_DcApiResponseModeOnRedirectPath asks for the dc_api
// response mode on a session the wallet was invoked for by URL.
//
// OID4VP 1.0 Appendix A.2: the dc_api modes exist for the Digital Credentials API,
// where the platform authenticates the origin and the transcript is built from it.
// Honouring one here would mean signing a DC API handover for a session that had
// no authenticated origin — the wrong transcript variant, which is exactly the
// confusion openid4vp_dc_api_mdoc_test.go exists to rule out from the other side.
func testOpenID4VP_MdocAv_DcApiResponseModeOnRedirectPath(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		claims["response_mode"] = "dc_api"
	})
}

// testOpenID4VP_MdocAv_UnknownResponseMode invents a response mode.
//
// OID4VP 1.0 §8 defines the modes; an unrecognised one has no defined handling, so
// there is no safe way to answer it. The failure mode this forecloses is a wallet
// that treats an unknown mode as its default and posts a response somewhere the
// request never specified.
//
// Refused when the wallet tries to answer rather than when it reads the request,
// so the user is asked to approve a disclosure that then cannot be made. Nothing
// is disclosed either way; the note is on requireMdocAvResponseRefused.
func testOpenID4VP_MdocAv_UnknownResponseMode(t *testing.T) {
	requireMdocAvResponseRefused(t, mdocAvRefusalCase{
		Mutate: func(hdr, claims map[string]any) {
			claims["response_mode"] = "direct_post.unknown"
		},
	})
}

// testOpenID4VP_MdocAv_IatFarFuture dates the request a year ahead.
//
// RFC 7519 §4.1.6. Tolerating this would mean a verifier could mint requests in
// advance that stay valid indefinitely, which is the opposite of what dating a
// request object is for. The wallet allows a couple of minutes of clock drift,
// which a year is not.
func testOpenID4VP_MdocAv_IatFarFuture(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		claims["iat"] = time.Now().Add(365 * 24 * time.Hour).Unix()
	})
}

// testOpenID4VP_MdocAv_LongExpired sends a request that was issued and expired a
// year ago.
//
// RFC 7519 §4.1.4. A request object is a single invitation, and an expired one
// that still works is a captured link that still works.
func testOpenID4VP_MdocAv_LongExpired(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		claims["iat"] = time.Now().Add(-365 * 24 * time.Hour).Unix()
		claims["exp"] = time.Now().Add(-364 * 24 * time.Hour).Unix()
	})
}

// testOpenID4VP_MdocAv_EncryptedResponseWithoutJwks asks for an encrypted response
// and supplies no key to encrypt it to.
//
// OID4VP 1.0 §8.3. Run against the direct_post.jwt container, since client_metadata
// carries a jwks only where the response is encrypted. What must not happen is the
// wallet falling back to sending the presentation in the clear: the verifier asked
// for encryption, and answering unencrypted would put the disclosed attributes on
// the wire exactly where the request said not to.
// Refused at response time, not at request time: the missing key is discovered
// when the wallet encrypts what it is about to send.
func testOpenID4VP_MdocAv_EncryptedResponseWithoutJwks(t *testing.T) {
	requireMdocAvResponseRefused(t, mdocAvRefusalCase{
		VerifierHost: testdata.OpenID4VP_DirectPostJwt_Host,
		Mutate: func(hdr, claims map[string]any) {
			metadata, ok := claims["client_metadata"].(map[string]any)
			require.True(t, ok, "the direct_post.jwt request should carry client_metadata")
			require.Contains(t, metadata, "jwks", "there should be a jwks to remove")
			delete(metadata, "jwks")
		},
	})
}

// testOpenID4VP_MdocAv_AudienceNotValidated points aud at another wallet and
// requires the session to complete.
//
// The one subtest here that asserts an acceptance, and deliberately so: §5.8 tells
// a verifier what to put in aud and places no validation duty on a wallet, and a
// check against the static-discovery value was written and removed because it
// refused the veramo reference verifier, which puts its own client_id there. The
// reasoning is in the CHANGELOG entry for the request-object claims.
//
// It is asserted rather than left untested because the decision is not obvious and
// the reverse looks like a missing check. What binds a presentation to one verifier
// is the client identifier in the mdoc session transcript, which this claim takes
// no part in — so if aud validation is ever added, this subtest failing is where
// that choice gets revisited on purpose.
func testOpenID4VP_MdocAv_AudienceNotValidated(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	testSession, _ := startMdocAvSessionServingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, createAvMdocAuthRequest(t),
		mdocAvRequestOverrides{Transform: func(t *testing.T, requestJwt string) string {
			return mintRequestVariant(t, requestJwt, func(hdr, claims map[string]any) {
				claims["aud"] = "https://someone.else.example"
			})
		}})

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 2, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
}

// testOpenID4VP_MdocAv_AttributeNotAuthorized asks for an age threshold the
// credential does not carry and the certificate does not authorize.
//
// The refusal is the authorization stage's, not the matching stage's, and that
// ordering is the point: a query is checked against what the relying party may ask
// before the wallet looks at what it holds, so an unauthorized request is refused
// whether or not the wallet could have answered it.
func testOpenID4VP_MdocAv_AttributeNotAuthorized(t *testing.T) {
	requireMdocAvQueryRefused(t, avDocType, string(clientmodels.Format_MsoMdoc),
		[]map[string]any{{"path": []string{avDocType, "age_over_99"}}})
}

// testOpenID4VP_MdocAv_ForbiddenAttribute asks a proof-of-age attestation for a
// date of birth.
//
// AV Annex A §A.4: the attestation SHALL carry the age_over_NN booleans and no
// other attribute, which is the whole privacy claim of the profile — a verifier
// learns "old enough" and not a birthday. Enforced here by the same authorized-set
// check, since birth_date is not in the certificate's set.
func testOpenID4VP_MdocAv_ForbiddenAttribute(t *testing.T) {
	requireMdocAvQueryRefused(t, avDocType, string(clientmodels.Format_MsoMdoc),
		[]map[string]any{{"path": []string{avDocType, "birth_date"}}})
}

// testOpenID4VP_MdocAv_WrongFormat asks for the AV credential as dc+sd-jwt.
//
// The wallet holds it as mso_mdoc, and the format in a DCQL credential query is
// not a hint: it decides which handler owns the query and how a claim path is read.
// A wallet that answered anyway would be presenting a credential in a format the
// verifier did not ask for and cannot verify.
func testOpenID4VP_MdocAv_WrongFormat(t *testing.T) {
	requireMdocAvQueryRefused(t, avDocType, string(clientmodels.Format_SdJwtVc),
		[]map[string]any{{"path": []string{avDocType, avMandatoryElement}}})
}

// testOpenID4VP_MdocAv_WrongNamespace asks for age_over_18 under the mDL
// namespace instead of the AV one.
//
// AV Annex A §A.4 puts every attribute of this attestation in the
// eu.europa.ec.av.1 namespace, and the credential the wallet holds has no
// org.iso.18013.5.1 namespace at all. The element name is one the certificate
// authorizes, so this passes the authorization stage and fails at matching —
// which makes it the one case in this group that is not a refusal.
func testOpenID4VP_MdocAv_WrongNamespace(t *testing.T) {
	requireMdocAvQueryYieldsNothingToDisclose(t, avDocType, string(clientmodels.Format_MsoMdoc),
		[]map[string]any{{"path": []string{"org.iso.18013.5.1", avMandatoryElement}}})
}

// testOpenID4VP_MdocAv_MalformedClaimPath sends an mdoc claim path with one
// element where the format requires two.
//
// OID4VP 1.0 §6.4.1. This one never reaches the wallet: the reference verifier
// refuses to create the session at all, which is worth asserting as the
// container's behaviour rather than the wallet's — it is why the wallet-side
// equivalent has to be tested through a minted request object instead, and it
// pins that the container we test everything else against enforces this.
func testOpenID4VP_MdocAv_MalformedClaimPath(t *testing.T) {
	authRequest := createAvMdocAuthRequestWithCredentialQuery(t, map[string]any{
		"id":     "age",
		"format": string(clientmodels.Format_MsoMdoc),
		"meta":   map[string]any{"doctype_value": avDocType},
		"claims": []map[string]any{{"path": []string{avMandatoryElement}}},
	})

	_, err := StartTestSessionAtEudiVerifier(testdata.OpenID4VP_DirectPost_Host, authRequest)
	require.Error(t, err, "the verifier should refuse a one-element mdoc claim path")
	require.Contains(t, err.Error(), "two elements",
		"the refusal should name the reason, so a future container change is visible here")
}

// testOpenID4VP_MdocAv_ControlMintedUnmodified is the control for the minting rig
// the refusal subtests below depend on.
//
// The request object is decoded, re-encoded and re-signed with the verifier's key
// without changing a single claim, so the wallet must accept it exactly as it
// accepts the container's own. A failure here means the rig is broken — a dropped
// claim, a re-encoding the wallet reads differently — and invalidates every
// refusal recorded after it.
func testOpenID4VP_MdocAv_ControlMintedUnmodified(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	testSession, _ := startMdocAvSessionServingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, createAvMdocAuthRequest(t),
		mdocAvRequestOverrides{Transform: func(t *testing.T, requestJwt string) string {
			return mintRequestVariant(t, requestJwt, func(hdr, claims map[string]any) {})
		}})

	session := testSession.ClientSession
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, 2, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	requireMdocVerifierResult(t, testSession.VerifierSession, "age", avDocType, avMandatoryElement, true)
}

// testOpenID4VP_MdocAv_CorruptSignature flips a bit in the signature over an
// otherwise genuine request object.
//
// The cheapest possible violation, and the one that proves the wallet verifies the
// signature at all rather than merely parsing the JWT and trusting its contents.
// Everything the wallet reads to decide who is asking — client_id, the x5c chain,
// the DCQL query — is inside the signed payload, so a request whose signature is
// not checked is a request from nobody.
func testOpenID4VP_MdocAv_CorruptSignature(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	testSession, _ := startMdocAvSessionServingRequest(t, c, 2, sessionHandler,
		testdata.OpenID4VP_DirectPost_Host, createAvMdocAuthRequest(t),
		mdocAvRequestOverrides{Transform: corruptJwtSignature})

	requireMdocViolationRefused(t, testSession.ClientSession)
}

// testOpenID4VP_MdocAv_AlgNone strips the signature and says so in the header.
//
// RFC 8725 §3.1. The attack this forecloses is the oldest one in JWT: a verifier
// that reads alg from the token it is verifying can be told not to verify. Since
// the whole request — who is asking, what for — is inside the payload, accepting
// alg:none would let anyone author a request from any relying party.
func testOpenID4VP_MdocAv_AlgNone(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		hdr["alg"] = "none"
	})
}

// testOpenID4VP_MdocAv_MissingTyp drops the typ header.
//
// OID4VP 1.0 §5.7 requires oauth-authz-req+jwt. An explicit type is what stops a
// JWT minted for one purpose being replayed as another: without it, any ES256 JWT
// the verifier ever signed — an access token, an ID token — is shaped like an
// authorization request.
func testOpenID4VP_MdocAv_MissingTyp(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		delete(hdr, "typ")
	})
}

// testOpenID4VP_MdocAv_NoX5c drops the certificate chain.
//
// The signature then verifies against nothing, which is the point: with no x5c
// there is no certificate to check the client_id against and no chain to walk to a
// trust anchor, so the request authenticates no one. A wallet that accepted it
// would be treating "signed by someone" as "signed by the party it names".
func testOpenID4VP_MdocAv_NoX5c(t *testing.T) {
	requireMdocAvRequestRefused(t, func(hdr, claims map[string]any) {
		delete(hdr, "x5c")
	})
}

// testOpenID4VP_MdocAv_ClientIdSanMismatch keeps the real certificate and
// signature and changes only the client_id, to a host that certificate has no SAN
// for.
//
// OID4VP 1.0 §5.10: with the x509_san_dns scheme the client_id must match a SAN of
// the signing certificate. This is the check that makes the certificate mean
// something — without it a relying party authenticated by a valid chain could
// claim to be any other party in it.
func testOpenID4VP_MdocAv_ClientIdSanMismatch(t *testing.T) {
	const impostor = "x509_san_dns:evil.example"

	requireMdocAvRequestRefusedWithClientId(t, impostor, func(hdr, claims map[string]any) {
		claims["client_id"] = impostor
	})
}

// testOpenID4VP_MdocAv_RedirectUriClientId uses the redirect_uri client_id scheme.
//
// A deliberate divergence rather than a defect, recorded here so it stays visible:
// the AV Blueprint's Annex A §A.6 *requires* this scheme, and this wallet refuses
// it, because a redirect_uri client_id is authenticated by nothing — there is no
// certificate, so nothing binds the request to a registered relying party or to
// the authorized attribute sets the trust model decides on. Accepting it would
// make every certificate check above optional in practice.
//
// If the profile's requirement is ever taken up, this subtest is what has to
// change, and its failure is where the decision surfaces.
func testOpenID4VP_MdocAv_RedirectUriClientId(t *testing.T) {
	const scheme = "redirect_uri:http://localhost:8090/wallet/direct_post"

	requireMdocAvRequestRefusedWithClientId(t, scheme, func(hdr, claims map[string]any) {
		claims["client_id"] = scheme
	})
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

	return startMdocAvSessionServingRequest(t, c, sessionId, sessionHandler, verifierHost,
		authRequestJson, mdocAvRequestOverrides{})
}

// mdocAvRequestOverrides changes what the wallet is handed, leaving the session at
// the verifier untouched. The zero value re-serves the request object verbatim
// under the verifier's own client_id, which is the capture case.
type mdocAvRequestOverrides struct {
	// Transform rewrites the request object on its way to the wallet. Nil serves
	// it unchanged.
	Transform func(t *testing.T, requestJwt string) string

	// LinkClientId replaces the client_id in the wallet link. Needed when a
	// mutation changes the client_id inside the request object: the wallet
	// compares the two, so leaving the link's alone would have it refuse for the
	// mismatch rather than for the thing the subtest is about.
	LinkClientId string

	// ServeRaw answers request_uri with something that is not a request object at
	// all, for the subtests about the fetch rather than its contents. Takes
	// precedence over Transform.
	ServeRaw *rawServedRequestObject
}

// rawServedRequestObject is what request_uri answers with when a subtest is about
// the transport: a body, its content type, and the status it arrives under.
type rawServedRequestObject struct {
	Body        string
	ContentType string
	Status      int
}

// startMdocAvSessionServingRequest is the same flow with the request object passed
// through transform on its way to the wallet.
//
// The identity transform is the capture case above. A transform that changes the
// object is how the violation subtests get a request the reference verifier would
// never send: the container signs a real one, exactly one thing about it is
// changed, and the result is re-signed and served in its place. Everything else —
// the session at the verifier, the link, the response endpoint — stays real, so a
// refusal is the wallet's and not an artifact of a hand-built request.
func startMdocAvSessionServingRequest(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
	verifierHost string,
	authRequestJson string,
	overrides mdocAvRequestOverrides,
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
	if overrides.Transform != nil {
		requestJwt = overrides.Transform(t, requestJwt)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if raw := overrides.ServeRaw; raw != nil {
			w.Header().Set("Content-Type", raw.ContentType)
			w.WriteHeader(raw.Status)
			_, _ = w.Write([]byte(raw.Body))
			return
		}
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(requestJwt))
	}))
	t.Cleanup(server.Close)

	query.Set("request_uri", server.URL)
	if overrides.LinkClientId != "" {
		query.Set("client_id", overrides.LinkClientId)
	}
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
