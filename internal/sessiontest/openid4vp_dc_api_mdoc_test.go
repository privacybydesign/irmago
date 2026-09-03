package sessiontest

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwe"
	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
)

// These tests cover an mso_mdoc presented over the W3C Digital Credentials API,
// which signs a different session transcript than the URL flow does: OpenID4VP
// Annex B.2.6.2 hashes [origin, nonce, jwkThumbprint] under
// "OpenID4VPDCAPIHandover", where B.2.6.1 hashes
// [clientId, nonce, jwkThumbprint, responseUri] under "OpenID4VPHandover".
//
// They run through the app-facing client API rather than calling the DCQL
// handler directly, because the interesting part is precisely the wiring in
// between: the origin the platform authenticated has to reach the handler as a
// bare value, while the audience carries the same origin behind an "origin:"
// prefix. A unit test on the handler cannot catch that value going missing.
//
// Getting the variant wrong is invisible from the wallet's side — the response
// is built, transmitted and decrypted normally, and only the verifier's
// deviceAuth check fails — so these tests verify the presentation the way a
// conformant verifier would, against a transcript derived here from the spec
// formula rather than from the production helper.

const dcApiMdocQueryId = "av_credential"

func testSessionHandlerForOpenID4VPOverDcApiWithMdoc(t *testing.T) {
	t.Run("an mdoc disclosed over the dc api signs the dc api handover",
		testDcApiMdocDisclosure)
	t.Run("the url-flow handover does not verify an mdoc disclosed over the dc api",
		testDcApiMdocRejectsUrlFlowHandover)
	t.Run("an encrypted dc api response signs the key it is encrypted to",
		testDcApiMdocEncryptedDisclosure)
	t.Run("multiple lets the user present two mdocs over the dc api",
		testDcApiMdocMultiplePresentations)
	t.Run("two mdoc queries over the dc api are answered with two presentations",
		testDcApiMdocTwoQueries)
	t.Run("a skipped optional credential set over the dc api yields an empty vp_token",
		testDcApiMdocSkippedOptionalSet)
}

// seedDcApiMdocWallet returns a wallet holding a genuinely issued age credential.
//
// The credential is fetched from the reference issuer over OpenID4VCI rather than
// written into storage: what these subtests are about is the handover deviceAuth
// signs over, but they can only reach it through a stored credential, and a
// hand-built one asserts that the test agrees with itself about how issuance
// stores things -- the device key, the cached namespaced claims, the batch. The
// credential that comes back is signed by the issuer CA the containers are
// configured with, which is what requireDeviceAuthVerifies anchors on.
//
// Issuance runs as session 1, so every subtest below starts its disclosure at 2.
func seedDcApiMdocWallet(t *testing.T) (*client.Client, *MockSessionHandler) {
	t.Helper()

	c, sessionHandler := createPidIssuerTestClient(t)
	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	return c, sessionHandler
}

func testDcApiMdocDisclosure(t *testing.T) {
	c, sessionHandler := seedDcApiMdocWallet(t)
	defer c.Close()

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiMdocData(t, string(openid4vp.ResponseMode_DcApi), nil),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	require.NotEmpty(t, session.DcApiResponse, "the wallet must return a DC API response")

	response := requireDcApiDeviceResponse(t, session.DcApiResponse)
	requireDeviceAuthVerifies(t, response, dcApiSessionTranscript(t, dcApiOrigin, dcApiNonce, nil))

	// A DC API session leaves the same activity log a link-invoked one does. The
	// verifier is filed under the one fact the platform authenticated, its origin,
	// and as unverified, matching the permission screen.
	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, disclosureLog.Protocol)
	require.NotNil(t, disclosureLog.Verifier)
	require.Equal(t, dcApiOrigin, disclosureLog.Verifier.Name)
	require.False(t, disclosureLog.Verifier.Verified)
	require.Len(t, disclosureLog.Credentials, 1)
	requireLogCredential(t, disclosureLog.Credentials[0], avLogCredential(avAttrAgeOver18()), "dc api entry")
}

// testDcApiMdocMultiplePresentations sets the DCQL multiple flag on a query two
// age credentials answer, and the user hands over both through the platform.
//
// The plaintext response carries two DeviceResponses under the one query id,
// each signed over the same DC API handover, from two different attestations.
func testDcApiMdocMultiplePresentations(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)
	issueAvMdocWithElementsViaPythonIssuer(t, c, 2, sessionHandler, avElementsBoth())

	session := startDcApiSession(t, c, 3, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data: unsignedDcApiRequestData(t, string(openid4vp.ResponseMode_DcApi), `{
			"credentials": [
				{
					"id": "av_credential",
					"format": "mso_mdoc",
					"meta": { "doctype_value": "eu.europa.ec.av.1" },
					"claims": [
						{ "path": ["eu.europa.ec.av.1", "age_over_18"] }
					],
					"multiple": true
				}
			]
		}`, nil),
	})
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	pickOne := session.DisclosurePlan.DisclosureChoicesOverview[0]
	require.True(t, pickOne.Multiple, "the plan must carry the multiple flag")
	require.Len(t, pickOne.OwnedOptions, 2, "both credentials should be offered")

	grantAllOwnedOptions(t, c, 3, pickOne)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 3, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	vpToken := requireVpTokenFromResponse(t, session.DcApiResponse)
	presentations := vpToken[dcApiMdocQueryId]
	require.Len(t, presentations, 2, "one presentation per selected credential")

	transcript := dcApiSessionTranscript(t, dcApiOrigin, dcApiNonce, nil)
	responses := make([]stdmdoc.DeviceResponse, 0, 2)
	for _, presentation := range presentations {
		response := decodeDcApiDeviceResponse(t, presentation)
		requireDeviceAuthVerifies(t, response, transcript)
		responses = append(responses, response)
	}
	require.NotEqual(t,
		issuerAuthOf(t, responses[0].Documents[0]),
		issuerAuthOf(t, responses[1].Documents[0]),
		"two presentations must come from two attestations")

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Len(t, disclosureLog.Credentials, 2, "both presented credentials are logged")
}

// testDcApiMdocTwoQueries asks for two elements of one age credential as two
// credential queries, through the platform.
//
// The response object must key one DeviceResponse under each query id, each
// disclosing only its own element and each signed over the same DC API handover.
// Read here in the clear because the reference verifier refuses this shape over
// the redirect flow with RequiredCredentialSetNotSatisfied after validating both
// documents (see openid4vp_mdoc_av_dcql_shapes_test.go), so what the wallet
// actually produces can only be pinned where nothing sits between it and the test.
func testDcApiMdocTwoQueries(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocWithElementsViaPythonIssuer(t, c, 1, sessionHandler, avElementsBoth())
	remainingBefore := avMdocInstancesRemaining(t, c)

	dcql := `{
		"credentials": [
			{
				"id": "age18",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.av.1" },
				"claims": [
					{ "path": ["eu.europa.ec.av.1", "age_over_18"] }
				]
			},
			{
				"id": "age21",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.av.1" },
				"claims": [
					{ "path": ["eu.europa.ec.av.1", "age_over_21"] }
				]
			}
		]
	}`
	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiRequestData(t, string(openid4vp.ResponseMode_DcApi), dcql, nil),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{avPlanCredential(avAttrAgeOver18())}},
			{Owned: []expectedPlanCredential{avPlanCredential(avAttrAgeOver21())}},
		},
	})

	grantFirstOwnedOptions(t, c, 2, session)
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	vpToken := requireVpTokenFromResponse(t, session.DcApiResponse)
	require.Len(t, vpToken, 2, "one vp_token entry per query, got keys %v", vpTokenKeys(vpToken))

	transcript := dcApiSessionTranscript(t, dcApiOrigin, dcApiNonce, nil)

	presented18 := decodeDcApiDeviceResponse(t, requireSinglePresentation(t, vpToken, avQueryIdAgeOver18))
	requireDeviceAuthVerifiesElements(t, presented18, transcript, map[string]any{avMandatoryElement: true})

	presented21 := decodeDcApiDeviceResponse(t, requireSinglePresentation(t, vpToken, avQueryIdAgeOver21))
	requireDeviceAuthVerifiesElements(t, presented21, transcript, map[string]any{avSecondElement: true})

	require.Equal(t, remainingBefore-2, avMdocInstancesRemaining(t, c),
		"two presentations must spend two instances")

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Len(t, disclosureLog.Credentials, 2, "one log credential per presentation")
}

// testDcApiMdocSkippedOptionalSet marks the only query optional and has the user
// share nothing.
//
// The session completes, the response object carries an empty vp_token, no
// instance is spent, and the log records a session with this verifier in which
// nothing was disclosed. Over the redirect flow the reference verifier answers an
// empty vp_token with a 500 (a failed requirement in its response handling), which
// is why the wallet's side of this shape is pinned here rather than there.
func testDcApiMdocSkippedOptionalSet(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)
	remainingBefore := avMdocInstancesRemaining(t, c)

	dcql := `{
		"credentials": [
			{
				"id": "age",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.av.1" },
				"claims": [
					{ "path": ["eu.europa.ec.av.1", "age_over_18"] }
				]
			}
		],
		"credential_sets": [
			{ "options": [["age"]], "required": false }
		]
	}`
	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiRequestData(t, string(openid4vp.ResponseMode_DcApi), dcql, nil),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.True(t, session.DisclosurePlan.DisclosureChoicesOverview[0].Optional,
		"the only choice must be marked optional")

	grantPermission(t, c, 2, clientmodels.DisclosureDisconSelection{})
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	require.NotEmpty(t, session.DcApiResponse, "the wallet must still return a DC API response")

	var parsed struct {
		VpToken map[string][]string `json:"vp_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(session.DcApiResponse), &parsed))
	require.Empty(t, parsed.VpToken, "nothing was shared, so the vp_token carries no presentation")

	require.Equal(t, remainingBefore, avMdocInstancesRemaining(t, c),
		"skipping an optional set must not spend an instance")

	disclosureLog := requireSingleDisclosureLog(t, c)
	require.Equal(t, dcApiOrigin, disclosureLog.Verifier.Name)
	require.Empty(t, disclosureLog.Credentials,
		"a skipped optional set is a session with this verifier in which nothing was disclosed")
}

// testDcApiMdocRejectsUrlFlowHandover is the negative half. Without it the test
// above would still pass if the wallet signed the URL-flow handover and the two
// variants happened to agree on a digest.
func testDcApiMdocRejectsUrlFlowHandover(t *testing.T) {
	c, sessionHandler := seedDcApiMdocWallet(t)
	defer c.Close()

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiMdocData(t, string(openid4vp.ResponseMode_DcApi), nil),
	})
	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	response := requireDcApiDeviceResponse(t, session.DcApiResponse)

	// The URL-flow handover over the same session's values: over the DC API the
	// audience is the origin-prefixed one and there is no response_uri, which is
	// exactly what a wallet that never learned about the second variant signs.
	urlFlowHandoverInfo, err := cbor.Marshal([]any{
		openid4vp.OriginAudience(dcApiOrigin), dcApiNonce, nil, "",
	})
	require.NoError(t, err)
	urlFlowDigest := sha256.Sum256(urlFlowHandoverInfo)
	urlFlow := stdmdoc.SessionTranscript{
		Handover: []any{"OpenID4VPHandover", urlFlowDigest[:]},
	}

	verifier := stdmdoc.NewVerifier([]*x509.Certificate{eudiPidIssuerPyCACert(t)})
	results, err := verifier.VerifyDeviceResponse(response, avDocType, avDocType, urlFlow)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.False(t, results[0].DeviceAuthValid,
		"a presentation made over the DC API must not verify against the URL-flow handover")
}

// testDcApiMdocEncryptedDisclosure covers dc_api.jwt, which is the path the AV
// Blueprint actually uses and the only one where the handover's third element is
// not null: deviceAuth commits to the thumbprint of the key the response is
// encrypted to, so the wallet has to pick that key before signing and then
// encrypt to that very key. A mismatch decrypts fine and fails the signature.
func testDcApiMdocEncryptedDisclosure(t *testing.T) {
	c, sessionHandler := seedDcApiMdocWallet(t)
	defer c.Close()

	privateKey, clientMetadata := dcApiEncryptionClientMetadata(t)

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiMdocData(t, string(openid4vp.ResponseMode_DcApiJwt), clientMetadata),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	var envelope struct {
		Response string          `json:"response"`
		VpToken  json.RawMessage `json:"vp_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(session.DcApiResponse), &envelope))
	require.NotEmpty(t, envelope.Response, "the encrypted response goes in the response member")
	require.Empty(t, envelope.VpToken, "the vp_token must not be sent in the clear")

	decrypted, err := jwe.Decrypt([]byte(envelope.Response), jwe.WithKey(jwa.ECDH_ES(), privateKey))
	require.NoError(t, err)

	response := requireDcApiDeviceResponse(t, string(decrypted))

	// The thumbprint is derived from the public half of the key the verifier
	// published, independently of what the wallet selected — that agreement is
	// the property under test.
	publicKey, err := privateKey.PublicKey()
	require.NoError(t, err)
	thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	requireDeviceAuthVerifies(t, response,
		dcApiSessionTranscript(t, dcApiOrigin, dcApiNonce, thumbprint))
}

// unsignedDcApiMdocData builds the `data` member of an unsigned DC API request
// querying for the AV mdoc's age_over_18 element.
func unsignedDcApiMdocData(t *testing.T, responseMode string, clientMetadata map[string]any) json.RawMessage {
	t.Helper()
	return unsignedDcApiRequestData(t, responseMode, `{
		"credentials": [
			{
				"id": "av_credential",
				"format": "mso_mdoc",
				"meta": { "doctype_value": "eu.europa.ec.av.1" },
				"claims": [
					{ "path": ["eu.europa.ec.av.1", "age_over_18"] }
				]
			}
		]
	}`, clientMetadata)
}

// unsignedDcApiRequestData builds the `data` member of an unsigned DC API request
// for any dcql_query.
func unsignedDcApiRequestData(
	t *testing.T,
	responseMode string,
	dcql string,
	clientMetadata map[string]any,
) json.RawMessage {
	t.Helper()
	request := map[string]any{
		"response_type": "vp_token",
		"response_mode": responseMode,
		"nonce":         dcApiNonce,
		"dcql_query":    json.RawMessage(dcql),
	}
	if clientMetadata != nil {
		request["client_metadata"] = clientMetadata
	}
	data, err := json.Marshal(request)
	require.NoError(t, err)
	return data
}

// requireDcApiDeviceResponse reads the single mdoc presentation out of a DC API
// response. An mso_mdoc vp_token entry is base64url-encoded CBOR rather than the
// compact JWS the SD-JWT helpers expect.
func requireDcApiDeviceResponse(t *testing.T, dcApiResponse string) stdmdoc.DeviceResponse {
	t.Helper()
	return decodeDcApiDeviceResponse(t,
		requireSinglePresentation(t, requireVpTokenFromResponse(t, dcApiResponse), dcApiMdocQueryId))
}

// decodeDcApiDeviceResponse decodes one mso_mdoc vp_token entry.
func decodeDcApiDeviceResponse(t *testing.T, presentation string) stdmdoc.DeviceResponse {
	t.Helper()

	encoded, err := base64.RawURLEncoding.DecodeString(presentation)
	require.NoError(t, err, "an mso_mdoc vp_token entry is base64url-encoded CBOR")

	var response stdmdoc.DeviceResponse
	require.NoError(t, cbor.Unmarshal(encoded, &response))
	require.Len(t, response.Documents, 1)
	return response
}

// dcApiSessionTranscript spells out OpenID4VP Annex B.2.6.2 rather than calling
// the wallet's own helper, so a change to either side has to be made twice. This
// is the same reasoning avSessionTranscript follows for the URL flow.
func dcApiSessionTranscript(t *testing.T, origin, nonce string, thumbprint []byte) stdmdoc.SessionTranscript {
	t.Helper()

	handoverInfo, err := cbor.Marshal([]any{origin, nonce, encryptionKeyElement(thumbprint)})
	require.NoError(t, err)
	digest := sha256.Sum256(handoverInfo)

	return stdmdoc.SessionTranscript{
		Handover: []any{"OpenID4VPDCAPIHandover", digest[:]},
	}
}
