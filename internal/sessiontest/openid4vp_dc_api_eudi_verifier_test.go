package sessiontest

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
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

	// The request is signed with the verifier's access certificate, which validates
	// against the wallet's Yivi anchors, so unlike an unsigned request this one names
	// the verifier from the certificate and reaches the top rung.
	require.Equal(t, "Yivi B.V.", session.Requestor.Name)
	require.Equal(t, clientmodels.TrustLevel_High, session.Requestor.TrustLevel,
		"an X.509 verifier under the Yivi anchors reaches the top rung over the DC API too")

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
	request, err := json.Marshal(map[string]any{
		"nonce":           dcApiVerifierNonce,
		"origin":          origin,
		"intended_use_id": eudiVerifierIntendedUseId,
		"dcql_query": map[string]any{
			"credentials": []any{map[string]any{
				"id":     dcApiVerifierQueryId,
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []string{"test.test.email"},
				},
				"claims": []any{map[string]any{"path": []string{"email"}}},
			}},
		},
		// The verifier needs the issuer certificate to validate the presentation it
		// gets back, the same way the request_uri-based tests hand it over.
		"issuer_chain": string(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
	})
	require.NoError(t, err)
	return string(request)
}
