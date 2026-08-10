package sessiontest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp"

	"github.com/stretchr/testify/require"
)

// These integration tests exercise OpenID4VP over the W3C Digital Credentials
// API end to end through the real client: a credential is issued into the
// wallet, a DC API request is started with client.SessionRequestData.DcApi, and
// the Authorization Response the wallet builds is read back off
// SessionState.DcApiResponse. Unlike the request_uri-based OpenID4VP tests,
// nothing is transmitted to a verifier server here — the platform is the
// transport — so the whole flow is self-contained and needs no external verifier.
//
// The parsing/validation logic and the signed (JWS) request path are unit-tested
// against the trust models in eudi/openid4vp/dc_api_test.go; these tests cover
// the wiring from the app-facing client API through disclosure to the response.

const (
	// dcApiOrigin is the caller origin the platform authenticated. It is what an
	// unsigned request must be shown as, and what every response is bound to as
	// origin:<origin>.
	dcApiOrigin  = "https://verifier.example.com"
	dcApiNonce   = "n-0S6_WzA2Mj"
	dcApiQueryId = "email_credential"
)

func testSessionHandlerForOpenID4VPOverDcApi(t *testing.T) {
	runEudiSessionTest(t,
		"unsigned request returns the response through the platform",
		testDcApiUnsignedDisclosure,
	)

	runEudiSessionTest(t,
		"unsigned request with dc_api.jwt returns an encrypted response",
		testDcApiEncryptedDisclosure,
	)

	runEudiSessionTest(t,
		"client_name in an unsigned request cannot name the verifier",
		testDcApiUnsignedClientNameCannotNameVerifier,
	)

	runEudiSessionTest(t,
		"dc_api.jwt without an encryption key fails the session",
		testDcApiEncryptedWithoutKeyFails,
	)

	runEudiSessionTest(t,
		"malformed requests fail the session before permission",
		testDcApiRejectsInvalidRequests,
	)

	runEudiSessionTest(t,
		"the dismisser cancels the session",
		testDcApiDismisserCancelsSession,
	)
}

// testDcApiUnsignedDisclosure runs the happy path: an unsigned request with
// response_mode dc_api discloses the owned email credential and the wallet hands
// the plaintext vp_token back through the platform, bound to the caller origin.
func testDcApiUnsignedDisclosure(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issueEmailCredential(t, irmaServer, c, sessionHandler, 1)

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiData(t, string(openid4vp.ResponseMode_DcApi), nil),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, session.Protocol)

	// An unsigned request is backed by no trust framework, so the verifier is
	// shown by its origin and lands on the bottom rung.
	require.Equal(t, dcApiOrigin, session.Requestor.Name)
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel)

	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// The response is handed back over the platform, not POSTed to a response_uri.
	require.NotEmpty(t, session.DcApiResponse, "the wallet must return a DC API response")

	vpToken := requireVpTokenFromResponse(t, session.DcApiResponse)
	presentation := requireSinglePresentation(t, vpToken, dcApiQueryId)

	require.Equal(t, "test@gmail.com", extractDisclosedClaims(t, presentation)["email"])

	// Appendix A.4: the presentation is bound to origin:<origin>, never to a
	// client identifier, and it carries the request nonce.
	requireKeyBindingBoundToOrigin(t, presentation, openid4vp.OriginAudience(dcApiOrigin), dcApiNonce)
}

// testDcApiEncryptedDisclosure runs the response_mode dc_api.jwt path: the
// verifier passes an ephemeral encryption key in client_metadata.jwks and the
// wallet returns the vp_token encrypted to it, never in the clear.
func testDcApiEncryptedDisclosure(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issueEmailCredential(t, irmaServer, c, sessionHandler, 1)

	privateKey, clientMetadata := dcApiEncryptionClientMetadata(t)

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiData(t, string(openid4vp.ResponseMode_DcApiJwt), clientMetadata),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Success)
	require.NotEmpty(t, session.DcApiResponse)

	// The response carries the JWE in its `response` member and must not also
	// leak the vp_token in the clear.
	var envelope struct {
		Response string          `json:"response"`
		VpToken  json.RawMessage `json:"vp_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(session.DcApiResponse), &envelope))
	require.NotEmpty(t, envelope.Response, "the encrypted response goes in the response member")
	require.Empty(t, envelope.VpToken, "the vp_token must not be sent in the clear")

	decrypted, err := jwe.Decrypt([]byte(envelope.Response), jwe.WithKey(jwa.ECDH_ES(), privateKey))
	require.NoError(t, err)

	var payload struct {
		VpToken map[string][]string `json:"vp_token"`
	}
	require.NoError(t, json.Unmarshal(decrypted, &payload))

	presentation := requireSinglePresentation(t, payload.VpToken, dcApiQueryId)
	require.Equal(t, "test@gmail.com", extractDisclosedClaims(t, presentation)["email"])
	requireKeyBindingBoundToOrigin(t, presentation, openid4vp.OriginAudience(dcApiOrigin), dcApiNonce)
}

// testDcApiUnsignedClientNameCannotNameVerifier pins the security fix: nothing
// authenticates client_metadata in an unsigned request, so a client_name it
// carries must not become the display name. The wallet must keep showing the one
// fact the platform did authenticate — the origin host.
func testDcApiUnsignedClientNameCannotNameVerifier(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issueEmailCredential(t, irmaServer, c, sessionHandler, 1)

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data: unsignedDcApiData(t, string(openid4vp.ResponseMode_DcApi), map[string]any{
			"client_name": "Rijksoverheid",
		}),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	require.Equal(t, dcApiOrigin, session.Requestor.Name,
		"an unsigned request must never present itself under a self-chosen name")
	require.Equal(t, clientmodels.TrustLevel_Low, session.Requestor.TrustLevel)
}

// testDcApiEncryptedWithoutKeyFails checks that a dc_api.jwt request that carries
// no encryption key parses and reaches permission, but fails when the wallet
// tries to build the encrypted response it cannot encrypt.
func testDcApiEncryptedWithoutKeyFails(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issueEmailCredential(t, irmaServer, c, sessionHandler, 1)

	session := startDcApiSession(t, c, 2, sessionHandler, &openid4vp.DcApiRequest{
		Protocol: openid4vp.DcApiProtocolUnsigned,
		Origin:   dcApiOrigin,
		Data:     unsignedDcApiData(t, string(openid4vp.ResponseMode_DcApiJwt), nil),
	})
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	grantDcApiDisclosure(t, c, 2, session)

	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Disclosure, clientmodels.Status_Error)
	require.NotNil(t, session.Error)
	require.Contains(t, session.Error.WrappedError, "jwks")
}

// testDcApiRejectsInvalidRequests drives requests that must be rejected during
// parsing through the real client, and asserts each one fails the session before
// any permission is requested.
func testDcApiRejectsInvalidRequests(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	tests := []struct {
		name      string
		request   *openid4vp.DcApiRequest
		expectErr string
	}{
		{
			name: "a non-DC-API response mode",
			request: &openid4vp.DcApiRequest{
				Protocol: openid4vp.DcApiProtocolUnsigned,
				Origin:   dcApiOrigin,
				Data:     unsignedDcApiData(t, "direct_post", nil),
			},
			expectErr: `requires response_mode "dc_api" or "dc_api.jwt"`,
		},
		{
			name: "an unknown protocol",
			request: &openid4vp.DcApiRequest{
				Protocol: "openid4vp",
				Origin:   dcApiOrigin,
				Data:     unsignedDcApiData(t, string(openid4vp.ResponseMode_DcApi), nil),
			},
			expectErr: `unsupported digital credentials api protocol "openid4vp"`,
		},
		{
			name: "the multi-signed protocol we do not implement",
			request: &openid4vp.DcApiRequest{
				Protocol: openid4vp.DcApiProtocolMultiSigned,
				Origin:   dcApiOrigin,
				Data:     unsignedDcApiData(t, string(openid4vp.ResponseMode_DcApi), nil),
			},
			expectErr: "multi-signed digital credentials api requests",
		},
		{
			name: "a missing caller origin",
			request: &openid4vp.DcApiRequest{
				Protocol: openid4vp.DcApiProtocolUnsigned,
				Data:     unsignedDcApiData(t, string(openid4vp.ResponseMode_DcApi), nil),
			},
			expectErr: "missing the caller origin",
		},
	}

	sessionId := 1
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id := sessionId
			sessionId++
			session := startDcApiSession(t, c, id, sessionHandler, test.request)

			// A request rejected during parsing fails before any disclosure type is
			// assigned, so only the id, the error status and the reason are asserted.
			require.Equal(t, id, session.Id)
			require.Equal(t, clientmodels.Status_Error, session.Status)
			require.NotNil(t, session.Error)
			require.Contains(t, session.Error.WrappedError, test.expectErr)
		})
	}
}

// testDcApiDismisserCancelsSession checks that the dismisser returned for a DC
// API session unwinds its own session and reports it cancelled, matching the
// request_uri-based flow.
func testDcApiDismisserCancelsSession(
	t *testing.T,
	_ *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	sessionReq, err := json.Marshal(client.SessionRequestData{
		Protocol: clientmodels.Protocol_OpenID4VP,
		DcApi: &openid4vp.DcApiRequest{
			Protocol: openid4vp.DcApiProtocolUnsigned,
			Origin:   dcApiOrigin,
			Data:     unsignedDcApiData(t, string(openid4vp.ResponseMode_DcApi), nil),
		},
	})
	require.NoError(t, err)

	// The wallet owns no credential here, so the session parks awaiting the
	// permission answer that the dismissal delivers instead.
	c.NewSession(1, string(sessionReq))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: 1,
		Type:      clientmodels.UI_DismissSession,
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, 1, session.Id)
	require.Equal(t, clientmodels.Status_Dismissed, session.Status)
}

// ========================================================================
// Helpers
// ========================================================================

// issueEmailCredential issues the test.test.email SD-JWT credential into the
// wallet so a DC API request can disclose it.
func issueEmailCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
	sessionId int,
) {
	t.Helper()
	issue(t, irmaServer, c, sessionHandler, sessionId, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, sessionId, clientmodels.Type_Issuance, clientmodels.Status_Success)
}

// startDcApiSession starts an OpenID4VP session from a platform-delivered DC API
// request and returns the first session state it dispatches.
func startDcApiSession(
	t *testing.T,
	c *client.Client,
	sessionId int,
	sessionHandler *MockSessionHandler,
	request *openid4vp.DcApiRequest,
) clientmodels.SessionState {
	t.Helper()
	sessionReq, err := json.Marshal(client.SessionRequestData{
		Protocol: clientmodels.Protocol_OpenID4VP,
		DcApi:    request,
	})
	require.NoError(t, err)

	c.NewSession(sessionId, string(sessionReq))
	return awaitSessionState(t, sessionHandler)
}

// grantDcApiDisclosure grants the single owned option in the session's
// disclosure plan.
func grantDcApiDisclosure(t *testing.T, c *client.Client, sessionId int, session clientmodels.SessionState) {
	t.Helper()
	require.NotNil(t, session.DisclosurePlan, "session must carry a disclosure plan to grant")
	require.NotEmpty(t, session.DisclosurePlan.DisclosureChoicesOverview, "disclosure plan must offer a choice")
	choice := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, sessionId, makeDisclosureChoice(choice))
}

// unsignedDcApiData builds the `data` member of an unsigned DC API request: an
// authorization request whose parameters query for the email credential. An
// optional client_metadata object is merged in when provided.
func unsignedDcApiData(t *testing.T, responseMode string, clientMetadata map[string]any) json.RawMessage {
	t.Helper()
	request := map[string]any{
		"response_type": "vp_token",
		"response_mode": responseMode,
		"nonce":         dcApiNonce,
		"dcql_query": map[string]any{
			"credentials": []any{map[string]any{
				"id":     dcApiQueryId,
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []string{"test.test.email"},
				},
				"claims": []any{map[string]any{"path": []string{"email"}}},
			}},
		},
	}
	if clientMetadata != nil {
		request["client_metadata"] = clientMetadata
	}
	data, err := json.Marshal(request)
	require.NoError(t, err)
	return data
}

// dcApiEncryptionClientMetadata generates an ephemeral EC encryption key and
// returns it together with a client_metadata object carrying its public half as
// a jwks, the way a verifier requesting a dc_api.jwt response would.
func dcApiEncryptionClientMetadata(t *testing.T) (jwk.Key, map[string]any) {
	t.Helper()

	ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	privateKey, err := jwk.Import(ecPrivateKey)
	require.NoError(t, err)
	require.NoError(t, privateKey.Set(jwk.AlgorithmKey, jwa.ECDH_ES()))
	require.NoError(t, privateKey.Set(jwk.KeyUsageKey, "enc"))
	require.NoError(t, privateKey.Set(jwk.KeyIDKey, "enc-1"))

	publicKey, err := privateKey.PublicKey()
	require.NoError(t, err)

	jwks := jwk.NewSet()
	require.NoError(t, jwks.AddKey(publicKey))

	jwksJson, err := json.Marshal(jwks)
	require.NoError(t, err)
	var jwksMap map[string]any
	require.NoError(t, json.Unmarshal(jwksJson, &jwksMap))

	return privateKey, map[string]any{"jwks": jwksMap}
}

// requireVpTokenFromResponse parses a plaintext DC API response and returns its
// vp_token as a map of query id to the presentations disclosed for it.
func requireVpTokenFromResponse(t *testing.T, response string) map[string][]string {
	t.Helper()
	var parsed struct {
		VpToken map[string][]string `json:"vp_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(response), &parsed))
	require.NotEmpty(t, parsed.VpToken, "response must carry a vp_token")
	return parsed.VpToken
}

// requireSinglePresentation returns the single presentation the vp_token holds
// for the given query id.
func requireSinglePresentation(t *testing.T, vpToken map[string][]string, queryId string) string {
	t.Helper()
	presentations, ok := vpToken[queryId]
	require.True(t, ok, "vp_token must contain query %q, got %v", queryId, vpToken)
	require.Len(t, presentations, 1, "expected exactly one presentation for query %q", queryId)
	require.NotEmpty(t, presentations[0])
	return presentations[0]
}

// requireKeyBindingBoundToOrigin checks that the Key Binding JWT ending an
// SD-JWT presentation binds it to the expected audience (origin:<origin>) and
// carries the request nonce, so the response cannot be replayed to another
// audience.
func requireKeyBindingBoundToOrigin(t *testing.T, presentation, expectedAudience, expectedNonce string) {
	t.Helper()

	parts := strings.Split(presentation, "~")
	require.GreaterOrEqual(t, len(parts), 2, "SD-JWT presentation must end with a KB-JWT")
	kbJwt := parts[len(parts)-1]
	require.NotEmpty(t, kbJwt, "SD-JWT presentation must be key-bound")

	claims := decodeJwtClaims(t, kbJwt)

	// aud is serialized either as a single string or an array of strings.
	switch aud := claims["aud"].(type) {
	case string:
		require.Equal(t, expectedAudience, aud)
	case []any:
		require.Contains(t, aud, expectedAudience)
	default:
		t.Fatalf("KB-JWT aud has unexpected type %T: %v", aud, claims["aud"])
	}
	require.Equal(t, expectedNonce, claims["nonce"])
}

// decodeJwtClaims decodes the payload of a compact JWS without verifying it.
func decodeJwtClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	segments := strings.Split(token, ".")
	require.Len(t, segments, 3, "a compact JWS has three segments")

	payload, err := base64.RawURLEncoding.DecodeString(segments[1])
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}
