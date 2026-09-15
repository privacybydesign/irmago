package sessiontest

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/testdata"

	"github.com/stretchr/testify/require"
)

// These integration tests run OpenID4VP over the W3C Digital Credentials API against
// the EUDI reference verifier (the eudi_openid4vp_dcapi service), so both halves of the
// flow are handled by a real verifier: it signs the authorization request the wallet
// consumes, and it decrypts and validates the response the wallet produces.
//
// The tests in openid4vp_dc_api_disclosure_test.go build the request and inspect the
// response themselves, which covers the unsigned request type and the wiring from the
// app-facing client API. This file covers what only a verifier can tell us: that a
// request it signed passes the X.509 trust model, and that it accepts the presentation
// the wallet returns for it.
//
// The DC API endpoints of the verifier run the ETSI TS 119 472-2 profile, which forces
// response_mode dc_api.jwt and a client_id prefix of x509_hash. That is why this runs
// against a service of its own, eudi_openid4vp_dcapi in docker-compose.yml, rather than
// against eudi_openid4vp or eudi_openid4vp_jwt.

const (
	// dcApiVerifierOrigin is the caller origin the platform reports to the wallet. The
	// verifier signs it into expected_origins, and the presentation is bound to it.
	dcApiVerifierOrigin = "https://verifier.example.com"

	dcApiVerifierQueryId = "email_credential"
	dcApiVerifierNonce   = "nonce"
)

func testSessionHandlerForOpenID4VPOverDcApiWithEudiVerifier(t *testing.T) {
	runEudiSessionTest(t,
		"the verifier accepts the presentation for a request it signed",
		testDcApiDisclosureToEudiVerifier,
	)

	runEudiSessionTest(t,
		"a request the verifier signed for another origin is rejected",
		testDcApiRejectsRequestSignedForAnotherOrigin,
	)

	// Not under runEudiSessionTest: the wallet has to trust the reference issuer's
	// CA, which the IRMA-backed wallet that runner builds does not.
	t.Run("an mdoc presented over the dc api is accepted by the verifier",
		testDcApiMdocDisclosureToEudiVerifier)
}

// testDcApiMdocDisclosureToEudiVerifier is the first time an mdoc crosses the DC
// API to a verifier this repository did not write.
//
// The three mdoc DC API subtests in openid4vp_dc_api_mdoc_test.go verify the
// DeviceResponse in-process, against a transcript the test derives from the same
// formula the wallet uses. A shared misreading of the handover would pass all of
// them. Here the reference verifier signs the request, forces dc_api.jwt, decrypts
// the response and validates the presentation, so its acceptance is independent
// evidence. The DeviceAuth is still re-verified here, since the container is not
// known to check it, against a transcript built from the nonce and encryption key
// in the request it signed.
//
// Also the first DC API session whose permission screen and activity log are read
// at all: the redirect flow asserts both in every happy path, the DC API tests
// asserted the response only.
func testDcApiMdocDisclosureToEudiVerifier(t *testing.T) {
	c, sessionHandler := createPidIssuerTestClient(t)
	defer c.Close()

	issueAvMdocViaPythonIssuer(t, c, 1, sessionHandler)

	verifierSession, err := StartDcApiTestSessionAtEudiVerifier(
		testdata.OpenID4VP_DcApi_Host,
		createDcApiSessionRequestWithDcql(t, dcApiVerifierOrigin, avSingleElementDcql, readEudiPidIssuerPyCA(t)),
	)
	require.NoError(t, err)
	requireSignedForOrigin(t, verifierSession.Request, dcApiVerifierOrigin)

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolSigned,
		Origin:   dcApiVerifierOrigin,
		Data:     signedDcApiData(t, verifierSession.Request),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)
	require.Equal(t, "Yivi B.V.", session.Requestor.Name)
	require.True(t, session.Requestor.Verified)

	requireDisclosurePlan(t, session.DisclosurePlan, expectedDisclosurePlan{
		Choices: []expectedPickOneChoice{
			{Owned: []expectedPlanCredential{avPlanCredential(avAttrAgeOver18())}},
		},
	})

	approvedRequestor := session.Requestor
	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	require.NotEmpty(t, session.DcApiResponse, "the wallet must return a DC API response")

	require.NoError(t, PostDcApiWalletResponseToEudiVerifier(verifierSession, session.DcApiResponse))

	walletResponse := requireVerifierAccepted(t, verifierSession.EudiVerifierSession)
	presented := requireSingleDeviceResponse(t, walletResponse, avQueryIdDefault)
	requireDeviceAuthVerifies(t, presented,
		dcApiTranscriptFromSignedRequest(t, verifierSession.Request, dcApiVerifierOrigin))

	disclosureLog := requireSingleDisclosureLog(t, c)
	requireLogVerifier(t, disclosureLog, approvedRequestor)
	require.Len(t, disclosureLog.Credentials, 1)
	requireLogCredential(t, disclosureLog.Credentials[0], avLogCredential(avAttrAgeOver18()), "dc api entry")
}

// testDcApiDisclosureToEudiVerifier runs the whole flow: the verifier starts a DC API
// transaction and signs the request, the platform delivers it to the wallet along with
// the caller origin, the wallet discloses the email credential, and the response the
// wallet hands back to the platform is posted to the verifier, which decrypts it and
// reports the disclosed claims.
func testDcApiDisclosureToEudiVerifier(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issueEmailCredential(t, irmaServer, c, sessionHandler, 1)

	verifierSession, err := StartDcApiTestSessionAtEudiVerifier(
		testdata.OpenID4VP_DcApi_Host,
		createDcApiEmailAuthRequestRequest(t, dcApiVerifierOrigin),
	)
	require.NoError(t, err)
	requireSignedForOrigin(t, verifierSession.Request, dcApiVerifierOrigin)

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolSigned,
		Origin:   dcApiVerifierOrigin,
		Data:     signedDcApiData(t, verifierSession.Request),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)

	// The request is signed with the verifier's access certificate, so unlike an
	// unsigned request this one names the verifier from the certificate and is shown
	// as verified.
	require.Equal(t, "Yivi B.V.", session.Requestor.Name)
	require.True(t, session.Requestor.Verified)

	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	require.NotEmpty(t, session.DcApiResponse, "the wallet must return a DC API response")

	// The wallet transmits nothing itself: the platform is what carries the response
	// back to the verifier.
	require.NoError(t, PostDcApiWalletResponseToEudiVerifier(verifierSession, session.DcApiResponse))

	// The verifier decrypted the response, verified the presentation and its Key
	// Binding JWT against the origin it signed for, and recorded the disclosed claims.
	requireVerifierResult(t, verifierSession.EudiVerifierSession, expectedVpToken{
		dcApiVerifierQueryId: expectedClaims{"email": "test@gmail.com"},
	})
}

// testDcApiRejectsRequestSignedForAnotherOrigin checks the origin binding of a signed
// request against a real signature: the verifier signs a request for one origin, and the
// wallet is handed it by a platform reporting a different caller origin. Nothing about
// the request is malformed, so only the expected_origins check can catch this.
func testDcApiRejectsRequestSignedForAnotherOrigin(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	verifierSession, err := StartDcApiTestSessionAtEudiVerifier(
		testdata.OpenID4VP_DcApi_Host,
		createDcApiEmailAuthRequestRequest(t, "https://other.example.com"),
	)
	require.NoError(t, err)

	session := startDcApiSession(t, c, 1, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolSigned,
		Origin:   dcApiVerifierOrigin,
		Data:     signedDcApiData(t, verifierSession.Request),
	})

	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_Error, session.Status)
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError, "is not among the expected_origins of the request")
}

// ========================================================================
// Helpers
// ========================================================================

// signedDcApiData builds the `data` member of a signed DC API request: the request
// object as the verifier signed it (Appendix A.3.2.1).
func signedDcApiData(t *testing.T, requestJwt string) json.RawMessage {
	t.Helper()
	require.NotEmpty(t, requestJwt, "the verifier must return a signed request")

	data, err := json.Marshal(map[string]string{"request": requestJwt})
	require.NoError(t, err)
	return data
}

// requireSignedForOrigin checks that the verifier signed the request for exactly the
// origin the test reports as the caller. The verifier accepts the presentation only when
// the audience of its Key Binding JWT (origin:<origin>) matches the origin it signed for,
// and it compares those as strings, so a difference here would show up much later as a
// rejected presentation.
func requireSignedForOrigin(t *testing.T, requestJwt, origin string) {
	t.Helper()
	claims := decodeJwtClaims(t, requestJwt)
	require.Equal(t, []any{origin}, claims["expected_origins"])
}

// createDcApiEmailAuthRequestRequest builds the request that starts a DC API transaction
// at the EUDI verifier, querying for the email credential on behalf of the given origin.
func createDcApiEmailAuthRequestRequest(t *testing.T, origin string) string {
	t.Helper()
	return createDcApiSessionRequestWithDcql(
		t,
		origin,
		`{
			"credentials": [
				{
					"id": "email_credential",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": ["test.test.email"] },
					"claims": [
						{ "path": ["email"] }
					]
				}
			]
		}`,
		testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes,
	)
}

// createDcApiSessionRequestWithDcql builds the request that starts a DC API
// transaction at the EUDI verifier for any dcql_query, on behalf of the given
// origin. issuerChain is the CA the verifier validates the presentation against,
// the same way the request_uri-based tests hand it over.
func createDcApiSessionRequestWithDcql(
	t *testing.T,
	origin string,
	dcql string,
	issuerChain []byte,
) string {
	t.Helper()
	request, err := json.Marshal(map[string]any{
		"nonce":           dcApiVerifierNonce,
		"origin":          origin,
		"intended_use_id": eudiVerifierIntendedUseId,
		"dcql_query":      json.RawMessage(dcql),
		"issuer_chain":    string(issuerChain),
	})
	require.NoError(t, err)
	return string(request)
}

// dcApiTranscriptFromSignedRequest rebuilds the DC API session transcript from a
// request the verifier signed: the nonce it chose and the thumbprint of the key it
// asked the response to be encrypted to. The DC API endpoints of the reference
// verifier always run dc_api.jwt, so the thumbprint slot is never null here.
func dcApiTranscriptFromSignedRequest(t *testing.T, requestJwt, origin string) stdmdoc.SessionTranscript {
	t.Helper()

	claims := decodeJwtClaims(t, requestJwt)
	nonce, ok := claims["nonce"].(string)
	require.True(t, ok, "the signed request must carry a nonce")
	require.Equal(t, "dc_api.jwt", claims["response_mode"],
		"the reference verifier serves the DC API under dc_api.jwt only")

	clientMetadata, ok := claims["client_metadata"].(map[string]any)
	require.True(t, ok, "an encrypted response mode must publish client_metadata")
	jwks, err := json.Marshal(clientMetadata["jwks"])
	require.NoError(t, err)

	return dcApiSessionTranscript(t, origin, nonce, responseEncryptionKeyThumbprint(t, jwks))
}
