package sessiontest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/testdata"
)

// avDocType is the EU Age Verification profile's docType. Five dot-separated
// parts where a Yivi scheme identifier has three, which is what makes the
// relying party's authorized-set matching worth exercising against a real
// certificate rather than only in unit tests.
const avDocType = "eu.europa.ec.av.1"

// testSessionHandlerForOpenID4VPWithMdocAv covers an mso_mdoc age-verification
// presentation end to end against the EU reference verifier container.
//
// This is the only place the mdoc disclosure path runs against a real verifier:
// the wallet matches the DCQL query, signs a DeviceResponse with the credential's
// device key, and the verifier accepts it. The relying party certificate the
// container presents is testdata/eudi/verifier/verifier.crt, whose scheme
// extension authorizes eu.europa.ec.av.1 — so the authorization stage runs for
// real and passes because the certificate genuinely permits the query.
//
// The disclosure runs against both verifier containers, because the response
// mode changes the bytes deviceAuth signs over: direct_post.jwt puts the
// response encryption key's thumbprint in the handover, direct_post puts a CBOR
// null there. Only one of the two can be wrong at a time, and only the AV
// Blueprint's own choice — direct_post — matters for conformance.
func testSessionHandlerForOpenID4VPWithMdocAv(t *testing.T) {
	runEudiSessionTest(t,
		"age verification mdoc is disclosed to the verifier",
		testOpenID4VP_MdocAv_Disclosure,
	)

	runEudiSessionTest(t,
		"age verification mdoc is disclosed with response mode direct_post",
		testOpenID4VP_MdocAv_DisclosureDirectPost,
	)

	runEudiSessionTest(t,
		"an unauthorized mdoc doctype is refused",
		testOpenID4VP_MdocAv_UnauthorizedDocType,
	)

	runEudiSessionTest(t,
		"an expired credential is not offered",
		testOpenID4VP_MdocAv_ExpiredCredentialIsNotOffered,
	)

	runEudiSessionTest(t,
		"an exhausted batch is not offered",
		testOpenID4VP_MdocAv_ExhaustedBatchIsNotOffered,
	)
}

// testOpenID4VP_MdocAv_UnauthorizedDocType asks for a docType the verifier's
// certificate does not authorize, and is the check that keeps the test above
// honest: it proves the authorization stage really runs against the certificate's
// scheme extension, so the passing case passes because eu.europa.ec.av.1 was
// added to that authorized set and not because the check was skipped.
//
// The refusal happens before any credential matching, so no credential needs to
// be seeded for this one.
func testOpenID4VP_MdocAv_UnauthorizedDocType(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	dcql := `{
		"credentials": [
		  {
			"id": "age",
			"format": "mso_mdoc",
			"meta": { "doctype_value": "eu.europa.ec.av.2" },
			"claims": [
			  { "path": ["eu.europa.ec.av.2", "age_over_21"] }
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

func testOpenID4VP_MdocAv_Disclosure(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	runMdocAvDisclosure(t, c, sessionHandler, testdata.OpenID4VP_DirectPostJwt_Host)
}

// testOpenID4VP_MdocAv_DisclosureDirectPost runs the same disclosure against the
// direct_post verifier.
//
// This is the response mode the AV Blueprint's Annex A §A.6 requires, and it is
// not the same code path: the handover carries a CBOR null where direct_post.jwt
// carries the response encryption key's thumbprint, so a bug in either branch of
// that choice shows up in exactly one of these two subtests.
func testOpenID4VP_MdocAv_DisclosureDirectPost(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	runMdocAvDisclosure(t, c, sessionHandler, testdata.OpenID4VP_DirectPost_Host)
}

func runMdocAvDisclosure(
	t *testing.T,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	verifierHost string,
) {
	t.Helper()

	issuer := seedAvMdoc(t, c)

	testSession, requestJwt := startMdocAvSessionCapturingRequest(t, c, 1, sessionHandler,
		verifierHost, createMdocAvAuthRequestRequest(t, issuer))

	session := testSession.ClientSession
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)

	// No display metadata was stored with the credential (the AV profile does not
	// specify any), so the credential name falls back to the raw docType and the
	// claim has no label. The claim path is the two-component
	// [namespace, elementIdentifier] form mdoc matching requires.
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{
				Owned: []expectedPlanCredential{{
					CredentialId: avDocType,
					Name:         avDocType,
					IssuerName:   "",
					Attributes: []expectedAttr{
						{
							Path:  []any{avDocType, "age_over_18"},
							Value: boolVal(true),
						},
					},
				}},
			},
		},
	})

	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	// Kept for the log assertion below, which checks the entry is filed under the
	// verifier the permission screen actually named.
	approvedRequestor := session.Requestor
	grantPermission(t, c, 1, makeDisclosureChoice(choice))

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	response := requireMdocVerifierResult(t, testSession.VerifierSession, "age", avDocType, "age_over_18", true)

	// The assertions above only establish what the verifier *received*. They pass
	// whether or not deviceAuth actually verifies, because the container is not
	// known to check it — and a handover the verifier cannot reproduce is silent
	// in the wallet and fatal only at a verifier that does check. So verify the
	// signature here, against a transcript rebuilt from the request the wallet was
	// actually given.
	requireDeviceAuthVerifies(t, issuer, response, avSessionTranscript(t, requestJwt))

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
	// Exactly one disclosure entry, not one entry: the log also carries the IRMA
	// issuance of the keyshare credential that enrolling this client produced.
	// Counting disclosures is what rules out the session being logged twice, which
	// the merged read path across the two stores makes possible.
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
	// The AV profile publishes no display metadata, so the name falls back to the
	// raw docType — the same fallback the disclosure plan above asserts, and the
	// case where a read-time re-resolution against live credential metadata could
	// overwrite the snapshot with an empty string.
	require.Equal(t, avDocType, logged.Name)

	// The disclosed claim keeps its qualified path, with the value resolved from
	// the batch's namespaced claim map. requireAttrsInOrder also asserts the
	// absent DisplayName, which is correct here for the same reason as the name
	// fallback: no claim display metadata exists to label it with.
	requireAttrsInOrder(t, logged.Attributes, expectedAttr{
		Path:  []any{avDocType, "age_over_18"},
		Value: boolVal(true),
	})

	// The batch timestamps come along; they are what dates the entry in the UI.
	require.NotNil(t, logged.IssuanceDate, "disclosure log should carry the issuance date")
	require.NotNil(t, logged.ExpiryDate, "disclosure log should carry the expiry date")
}

// seedAvMdoc issues a real mso_mdoc age credential and stores it the way
// issuance does, returning the issuer so its IACA can be handed to the verifier
// as a trust anchor.
//
// The credential is genuinely signed rather than faked: stdmdoc.NewIssuer builds
// the two-tier IACA/document-signer PKI the AV Blueprint expects, so the stored
// bytes are a credential a verifier can actually check. The device key is stored
// as a holder binding key on the instance, which is what lets the wallet produce
// a DeviceSigned at presentation time — PrepareDisclosure refuses an instance
// without one.
func seedAvMdoc(t *testing.T, c *client.Client) *stdmdoc.Issuer {
	t.Helper()
	return seedAvMdocBatch(t, c, avSeedOptions{BatchSize: 1, RemainingCount: 1, ExpiresIn: 24 * time.Hour})
}

// avSeedOptions describes the batch seedAvMdocBatch writes, so a test can put
// the wallet in a state a real issuer will not hand out on demand — an expired
// credential, or a batch whose instances are all spent.
type avSeedOptions struct {
	BatchSize      uint
	RemainingCount uint
	// ExpiresIn is relative to now, and may be negative for an expired batch.
	ExpiresIn time.Duration
}

func seedAvMdocBatch(t *testing.T, c *client.Client, opts avSeedOptions) *stdmdoc.Issuer {
	t.Helper()

	issuer, err := stdmdoc.NewIssuer()
	require.NoError(t, err)

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issued, err := issuer.Issue(avDocType, avDocType, map[string]any{"age_over_18": true}, &deviceKey.PublicKey)
	require.NoError(t, err)

	rawCredential, err := cbor.Marshal(issued)
	require.NoError(t, err)

	devicePrivKey, err := x509.MarshalPKCS8PrivateKey(deviceKey)
	require.NoError(t, err)

	// The credential store rejects a holder binding key that carries neither a
	// thumbprint nor a DID, so derive the thumbprint exactly as
	// HolderBindingKeyService does at issuance: hex of the JWK's SHA-256
	// thumbprint over the public key.
	jwkPrivKey, err := jwk.Import(deviceKey)
	require.NoError(t, err)
	jwkPubKey, err := jwkPrivKey.PublicKey()
	require.NoError(t, err)
	require.NoError(t, jwkPubKey.Set(jwk.KeyUsageKey, jwk.ForSignature))
	thumbprintBytes, err := jwkPubKey.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	thumbprint := hex.EncodeToString(thumbprintBytes)

	// The namespace -> elementIdentifier -> value shape mdoc_dcql reads, which is
	// what the mso_mdoc format parser caches at issuance.
	resolvedClaims, err := json.Marshal(map[string]map[string]any{
		avDocType: {"age_over_18": true},
	})
	require.NoError(t, err)

	now := time.Now()
	batch := &models.CredentialBatch{
		IssuerURL:                "https://av-issuer.example.com",
		CredentialIssuer:         "https://av-issuer.example.com",
		VerifiableCredentialType: avDocType,
		Format:                   models.CredentialFormatMsoMdoc,
		Hash:                     "av-integration-batch-hash",
		ProcessedSdJwtPayload:    datatypes.JSON(resolvedClaims),
		IssuedAt:                 datatypes.NullTime{V: now.Add(-time.Hour), Valid: true},
		ExpiresAt:                datatypes.NullTime{V: now.Add(opts.ExpiresIn), Valid: true},
		BatchSize:                opts.BatchSize,
		RemainingCount:           opts.RemainingCount,
		Instances: []models.IssuedCredentialInstance{
			{
				RawCredential: rawCredential,
				HolderBindingKey: &models.HolderBindingKey{
					Algorithm:           models.KeyAlgorithmECDSA,
					PrivateKey:          devicePrivKey,
					PublicKeyThumbprint: datatypes.NullString{V: thumbprint, Valid: true},
					ECDSA: &models.ECDSAKeyMetadata{
						CurveName: deviceKey.Curve.Params().Name,
					},
				},
			},
		},
	}

	credStore := db.NewCredentialStore(c.EudiStorageForTesting().Db())
	require.NoError(t, credStore.StoreBatch(batch))

	return issuer
}

// createMdocAvAuthRequestRequest builds the verifier's session-creation request
// for the age query.
//
// Unlike createAuthRequestRequestWithDcql this passes the freshly generated IACA
// as issuer_chain rather than a fixture certificate: the credential is signed by
// a per-run PKI, so the verifier can only validate its issuer signature if it is
// told about that run's trust anchor. The body is marshalled rather than
// formatted into a template because a PEM block carries newlines, which have to
// be escaped to survive as a JSON string value.
func createMdocAvAuthRequestRequest(t *testing.T, issuer *stdmdoc.Issuer) string {
	t.Helper()

	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.IACACert().Raw})

	request := map[string]any{
		"type": "vp_token",
		"dcql_query": map[string]any{
			"credentials": []map[string]any{
				{
					"id":     "age",
					"format": string(clientmodels.Format_MsoMdoc),
					"meta":   map[string]any{"doctype_value": avDocType},
					"claims": []map[string]any{
						{"path": []string{avDocType, "age_over_18"}},
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
		"issuer_chain":       string(chain),
	}

	body, err := json.Marshal(request)
	require.NoError(t, err)
	return string(body)
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
		Qr: irma.Qr{
			Type: irma.ActionDisclosing,
			URL:  "eudi-openid4vp://?" + query.Encode(),
		},
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
	issuer *stdmdoc.Issuer,
	response stdmdoc.DeviceResponse,
	transcript stdmdoc.SessionTranscript,
) {
	t.Helper()

	verifier := stdmdoc.NewVerifier([]*x509.Certificate{issuer.IACACert()})
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

// testOpenID4VP_MdocAv_ExpiredCredentialIsNotOffered seeds a credential whose
// validity has already run out and checks the wallet does not put it forward.
//
// The AV profile leans on expiry as its only revocation lever — attestations are
// short-lived and there is no status list — so an expired one being offered is
// the closest thing to presenting a revoked credential. `dcql.IsBatchValid`
// implements the check, and until now nothing exercised it through a real
// session: a unit test cannot show that the disclosure planner consults it
// before building the permission screen.
func testOpenID4VP_MdocAv_ExpiredCredentialIsNotOffered(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issuer := seedAvMdocBatch(t, c, avSeedOptions{
		BatchSize:      1,
		RemainingCount: 1,
		ExpiresIn:      -time.Hour,
	})

	testSession := startOpenID4VPSessionWithAuthRequest(t, c, 1, sessionHandler,
		createMdocAvAuthRequestRequest(t, issuer))
	session := testSession.ClientSession

	// The session still reaches the permission screen — the user is told what was
	// asked for — but with nothing of theirs to answer it. Were the expiry check
	// skipped, this same plan would carry the seeded credential as an owned
	// option, which is what the assertion is really about.
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.NotNil(t, session.DisclosurePlan)
	for _, choice := range session.DisclosurePlan.DisclosureChoicesOverview {
		require.Empty(t, choice.OwnedOptions,
			"the wallet offered a credential whose validity window has passed")
	}
}

// testOpenID4VP_MdocAv_ExhaustedBatchIsNotOffered seeds a batch whose instances
// are all spent.
//
// Single-use is the property batch issuance exists to provide, and the wallet
// enforces it by refusing to reuse an instance rather than by re-presenting the
// last one. Reaching this state against a real issuer would take a hundred
// presentations, since that is the batch size it hands out, so it is seeded.
func testOpenID4VP_MdocAv_ExhaustedBatchIsNotOffered(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issuer := seedAvMdocBatch(t, c, avSeedOptions{
		BatchSize:      2,
		RemainingCount: 0,
		ExpiresIn:      24 * time.Hour,
	})

	testSession := startOpenID4VPSessionWithAuthRequest(t, c, 1, sessionHandler,
		createMdocAvAuthRequestRequest(t, issuer))
	session := testSession.ClientSession

	// Unlike an expired credential, an exhausted batch fails the session outright:
	// the wallet holds a credential of the right type and cannot spend it, which
	// is worth telling the user about rather than silently showing nothing.
	require.Equal(t, clientmodels.Status_Error, session.Status,
		"a batch with no unused instances left must not produce a presentable option")
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError, "exhausted",
		"the failure should name the exhausted batch rather than surface as a generic matching failure")
}
