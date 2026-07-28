package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/stretchr/testify/require"
)

const (
	testOrigin      = "https://verifier.example.com"
	testDcqlQueryId = "my_credential"
)

// ========================================================================
// Test doubles
// ========================================================================

// mockVerifierValidator stands in for the trust-model-backed validators. The
// x509 and DID validators have their own tests; the DC API tests only need a
// verified request object to run the Appendix A checks against.
type mockVerifierValidator struct {
	request *AuthorizationRequest
	err     error
}

func (v *mockVerifierValidator) ParseAndVerifyAuthorizationRequest(requestJwt string) (
	*AuthorizationRequest,
	*x509.Certificate,
	*scheme.RelyingPartyRequestor,
	error,
) {
	if v.err != nil {
		return nil, nil, nil, v.err
	}
	requestor := &scheme.RelyingPartyRequestor{}
	requestor.Organization.LegalName = map[string]string{"en": "Verifier Example"}
	return v.request, nil, requestor, nil
}

// mockDcqlHandler answers a single DCQL credential query with one owned
// credential and records the audience the client bound the disclosure to.
type mockDcqlHandler struct {
	preparedForAudience string
	preparedForNonce    string
}

func (h *mockDcqlHandler) CanHandleCredentialQuery(_ dcql.CredentialQuery) bool { return true }

func (h *mockDcqlHandler) FindCandidates(query dcql.CredentialQuery) (*dcql.CredentialQueryResult, error) {
	return &dcql.CredentialQueryResult{
		OwnedCandidates: []*clientmodels.SelectableCredentialInstance{{
			CredentialId: "https://credentials.example.com/identity_credential",
			Hash:         "credential-hash",
			Format:       clientmodels.Format_SdJwtVc,
		}},
	}, nil
}

func (h *mockDcqlHandler) PrepareDisclosure(selections []dcql.DisclosureSelection, nonce string, clientId string) (*dcql.PreparedDisclosure, error) {
	h.preparedForAudience = clientId
	h.preparedForNonce = nonce
	return &dcql.PreparedDisclosure{
		QueryResponses: []dcql.QueryResponse{{
			QueryId:     selections[0].QueryId,
			Credentials: []string{"presented~sd~jwt"},
		}},
	}, nil
}

// testHandler captures the callbacks from the OpenID4VP client. Only the
// channels a test actually reads are set; the others stay nil so a callback the
// test does not care about never blocks the session goroutine.
type testHandler struct {
	failureCh   chan *clientmodels.SessionError
	successCh   chan string
	dcApiCh     chan string
	cancelledCh chan struct{}

	// grant answers the permission request with these selections. When nil, the
	// permission request is left unanswered.
	grant []dcql.DisclosureSelection
}

func (h *testHandler) Failure(err *clientmodels.SessionError) {
	h.failureCh <- err
}

func (h *testHandler) Cancelled() {
	if h.cancelledCh != nil {
		h.cancelledCh <- struct{}{}
	}
}

func (h *testHandler) Success(result string, _ []clientmodels.LogCredential) {
	if h.successCh != nil {
		h.successCh <- result
	}
}

func (h *testHandler) DeliverDcApiResponse(response string) {
	if h.dcApiCh != nil {
		h.dcApiCh <- response
	}
}

func (h *testHandler) RequestVerificationPermission(
	_ *clientmodels.DisclosurePlan,
	_ *clientmodels.TrustedParty,
	_ map[string]string,
	callback PermissionHandler,
) {
	if h.grant != nil {
		callback(true, h.grant)
	}
}

// ========================================================================
// Request fixtures
// ========================================================================

func unsignedRequestData(t *testing.T, overrides map[string]any) json.RawMessage {
	t.Helper()
	request := map[string]any{
		"response_type": "vp_token",
		"response_mode": "dc_api",
		"nonce":         "n-0S6_WzA2Mj",
		"dcql_query": map[string]any{
			"credentials": []any{map[string]any{
				"id":     testDcqlQueryId,
				"format": "dc+sd-jwt",
				"meta": map[string]any{
					"vct_values": []string{"https://credentials.example.com/identity_credential"},
				},
			}},
		},
	}
	for key, value := range overrides {
		if value == nil {
			delete(request, key)
			continue
		}
		request[key] = value
	}
	data, err := json.Marshal(request)
	require.NoError(t, err)
	return data
}

func signedRequestData(t *testing.T) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(map[string]any{"request": "eyJhbGciOiJFUzI1NiJ9.e30.signature"})
	require.NoError(t, err)
	return data
}

// signedAuthRequest is what the mock validator returns for a signed DC API request.
func signedAuthRequest(expectedOrigins []string) *AuthorizationRequest {
	return &AuthorizationRequest{
		ClientId:        "x509_san_dns:rp.example.com",
		ResponseType:    "vp_token",
		ResponseMode:    ResponseMode_DcApi,
		Nonce:           "n-0S6_WzA2Mj",
		ExpectedOrigins: expectedOrigins,
		DcqlQuery: dcql.DcqlQuery{Credentials: []dcql.CredentialQuery{{
			Id:     testDcqlQueryId,
			Format: "dc+sd-jwt",
		}}},
	}
}

// ========================================================================
// Request parsing and validation
// ========================================================================

func TestParseDcApiRequest_Unsigned_Succeeds(t *testing.T) {
	client := &Client{dcqlHandler: dcql.NewDcqlHandler(nil)}

	request, requestor, err := client.parseDcApiRequest(&DcApiRequest{
		Protocol: DcApiProtocolUnsigned,
		Origin:   testOrigin,
		Data:     unsignedRequestData(t, nil),
	})

	require.NoError(t, err)
	require.Equal(t, ResponseMode_DcApi, request.ResponseMode)
	require.Equal(t, "n-0S6_WzA2Mj", request.Nonce)
	require.Len(t, request.DcqlQuery.Credentials, 1)
	// An unsigned request is not backed by any trust framework, so the verifier is
	// shown by its origin host and never as verified.
	require.Equal(t, "verifier.example.com", requestor.Name)
	require.False(t, requestor.Verified)
}

func TestParseDcApiRequest_Unsigned_UsesClientNameWhenPresent(t *testing.T) {
	client := &Client{dcqlHandler: dcql.NewDcqlHandler(nil)}

	_, requestor, err := client.parseDcApiRequest(&DcApiRequest{
		Protocol: DcApiProtocolUnsigned,
		Origin:   testOrigin,
		Data: unsignedRequestData(t, map[string]any{
			"client_metadata": map[string]any{"client_name": "Verifier Example"},
		}),
	})

	require.NoError(t, err)
	require.Equal(t, "Verifier Example", requestor.Name)
	require.False(t, requestor.Verified)
}

// Appendix A.2: the wallet MUST ignore client_id and expected_origins in an
// unsigned request, because the verifier authenticated neither.
func TestParseDcApiRequest_Unsigned_IgnoresClientIdAndExpectedOrigins(t *testing.T) {
	client := &Client{dcqlHandler: dcql.NewDcqlHandler(nil)}

	request, _, err := client.parseDcApiRequest(&DcApiRequest{
		Protocol: DcApiProtocolUnsigned,
		Origin:   testOrigin,
		Data: unsignedRequestData(t, map[string]any{
			"client_id":        "x509_san_dns:attacker.example.com",
			"expected_origins": []string{"https://attacker.example.com"},
		}),
	})

	require.NoError(t, err)
	require.Empty(t, request.ClientId)
	require.Empty(t, request.ExpectedOrigins)
}

// response_uri and redirect_uri are not supported over the DC API, so they must
// never survive parsing into the code that transmits the response.
func TestParseDcApiRequest_Unsigned_ClearsResponseAndRedirectUri(t *testing.T) {
	client := &Client{dcqlHandler: dcql.NewDcqlHandler(nil)}

	request, _, err := client.parseDcApiRequest(&DcApiRequest{
		Protocol: DcApiProtocolUnsigned,
		Origin:   testOrigin,
		Data: unsignedRequestData(t, map[string]any{
			"response_uri": "https://attacker.example.com/collect",
			"redirect_uri": "https://attacker.example.com/return",
		}),
	})

	require.NoError(t, err)
	require.Empty(t, request.ResponseUri)
	require.Empty(t, request.RedirectUri)
}

func TestParseDcApiRequest_Unsigned_Rejects(t *testing.T) {
	tests := []struct {
		name      string
		overrides map[string]any
		expectErr string
	}{
		{
			name:      "response_type other than vp_token",
			overrides: map[string]any{"response_type": "code"},
			expectErr: `requires response_type "vp_token"`,
		},
		{
			name:      "a non-DC-API response mode",
			overrides: map[string]any{"response_mode": "direct_post"},
			expectErr: `requires response_mode "dc_api" or "dc_api.jwt"`,
		},
		{
			name:      "a missing nonce",
			overrides: map[string]any{"nonce": nil},
			expectErr: "nonce is required",
		},
		{
			name:      "a nonce with non-URL-safe characters",
			overrides: map[string]any{"nonce": "not a nonce"},
			expectErr: "nonce contains invalid character",
		},
		{
			name:      "scope instead of dcql_query",
			overrides: map[string]any{"scope": "identity_credential"},
			expectErr: "scope is not supported",
		},
		{
			name:      "a missing dcql_query",
			overrides: map[string]any{"dcql_query": nil},
			expectErr: "missing a non-empty dcql_query",
		},
		{
			name:      "an empty dcql_query",
			overrides: map[string]any{"dcql_query": map[string]any{"credentials": []any{}}},
			expectErr: "missing a non-empty dcql_query",
		},
	}

	client := &Client{dcqlHandler: dcql.NewDcqlHandler(nil)}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := client.parseDcApiRequest(&DcApiRequest{
				Protocol: DcApiProtocolUnsigned,
				Origin:   testOrigin,
				Data:     unsignedRequestData(t, test.overrides),
			})
			require.ErrorContains(t, err, test.expectErr)
		})
	}
}

func TestParseDcApiRequest_RejectsMalformedEnvelope(t *testing.T) {
	tests := []struct {
		name      string
		request   *DcApiRequest
		expectErr string
	}{
		{
			name:      "a nil request",
			request:   nil,
			expectErr: "request is nil",
		},
		{
			name:      "a missing origin",
			request:   &DcApiRequest{Protocol: DcApiProtocolUnsigned, Data: json.RawMessage(`{}`)},
			expectErr: "missing the caller origin",
		},
		{
			name:      "a missing data member",
			request:   &DcApiRequest{Protocol: DcApiProtocolUnsigned, Origin: testOrigin},
			expectErr: "missing its data member",
		},
		{
			name:      "data that is not an object",
			request:   &DcApiRequest{Protocol: DcApiProtocolUnsigned, Origin: testOrigin, Data: json.RawMessage(`"nope"`)},
			expectErr: "failed to parse unsigned digital credentials api request",
		},
		{
			name:      "an unknown protocol",
			request:   &DcApiRequest{Protocol: "openid4vp", Origin: testOrigin, Data: json.RawMessage(`{}`)},
			expectErr: `unsupported digital credentials api protocol "openid4vp"`,
		},
		{
			name:      "the multi-signed protocol we do not implement",
			request:   &DcApiRequest{Protocol: DcApiProtocolMultiSigned, Origin: testOrigin, Data: json.RawMessage(`{}`)},
			expectErr: "multi-signed digital credentials api requests",
		},
		{
			name:      "a signed request without a request member",
			request:   &DcApiRequest{Protocol: DcApiProtocolSigned, Origin: testOrigin, Data: json.RawMessage(`{}`)},
			expectErr: "missing its request member",
		},
	}

	client := &Client{dcqlHandler: dcql.NewDcqlHandler(nil)}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := client.parseDcApiRequest(test.request)
			require.ErrorContains(t, err, test.expectErr)
		})
	}
}

func TestParseDcApiRequest_Signed_Succeeds(t *testing.T) {
	client := &Client{
		dcqlHandler:       dcql.NewDcqlHandler(nil),
		verifierValidator: &mockVerifierValidator{request: signedAuthRequest([]string{testOrigin})},
	}

	request, requestor, err := client.parseDcApiRequest(&DcApiRequest{
		Protocol: DcApiProtocolSigned,
		Origin:   testOrigin,
		Data:     signedRequestData(t),
	})

	require.NoError(t, err)
	require.Equal(t, "x509_san_dns:rp.example.com", request.ClientId)
	require.Equal(t, "Verifier Example", requestor.Name)
}

// Appendix A.2: the wallet MUST return an error when the origin the platform
// reported is not among the signed expected_origins, to detect request replay.
func TestParseDcApiRequest_Signed_RejectsOriginMismatch(t *testing.T) {
	client := &Client{
		dcqlHandler:       dcql.NewDcqlHandler(nil),
		verifierValidator: &mockVerifierValidator{request: signedAuthRequest([]string{"https://other.example.com"})},
	}

	_, _, err := client.parseDcApiRequest(&DcApiRequest{
		Protocol: DcApiProtocolSigned,
		Origin:   testOrigin,
		Data:     signedRequestData(t),
	})

	require.ErrorContains(t, err, "is not among the expected_origins")
}

func TestParseDcApiRequest_Signed_RejectsMissingExpectedOrigins(t *testing.T) {
	client := &Client{
		dcqlHandler:       dcql.NewDcqlHandler(nil),
		verifierValidator: &mockVerifierValidator{request: signedAuthRequest(nil)},
	}

	_, _, err := client.parseDcApiRequest(&DcApiRequest{
		Protocol: DcApiProtocolSigned,
		Origin:   testOrigin,
		Data:     signedRequestData(t),
	})

	require.ErrorContains(t, err, "missing a non-empty expected_origins")
}

func TestParseDcApiRequest_Signed_ReportsVerificationFailure(t *testing.T) {
	client := &Client{
		dcqlHandler:       dcql.NewDcqlHandler(nil),
		verifierValidator: &mockVerifierValidator{err: fmt.Errorf("bad signature")},
	}

	_, _, err := client.parseDcApiRequest(&DcApiRequest{
		Protocol: DcApiProtocolSigned,
		Origin:   testOrigin,
		Data:     signedRequestData(t),
	})

	require.ErrorContains(t, err, "failed to verify authorization request")
}

func TestSameOrigin(t *testing.T) {
	tests := []struct {
		a, b   string
		expect bool
	}{
		{"https://verifier.example.com", "https://verifier.example.com", true},
		{"https://Verifier.Example.com", "https://verifier.example.com", true},
		{"HTTPS://verifier.example.com", "https://verifier.example.com", true},
		{"https://verifier.example.com", "https://verifier.example.com:8443", false},
		{"https://verifier.example.com", "http://verifier.example.com", false},
		{"https://verifier.example.com", "https://attacker.example.com", false},
		// The path is not part of an origin, but a verifier that signed for a
		// trailing slash still means the same origin.
		{"https://verifier.example.com/", "https://verifier.example.com", true},
		// Origins the platform reports for native callers do not parse as URLs
		// and are compared verbatim.
		{"android:apk-key-hash:abc", "android:apk-key-hash:abc", true},
		{"android:apk-key-hash:abc", "android:apk-key-hash:def", false},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s_vs_%s", test.a, test.b), func(t *testing.T) {
			require.Equal(t, test.expect, sameOrigin(test.a, test.b))
		})
	}
}

func TestOriginAudience(t *testing.T) {
	require.Equal(t, "origin:https://verifier.example.com", OriginAudience(testOrigin))
}

// ========================================================================
// Response building
// ========================================================================

func TestCreateDcApiResponse_DcApi(t *testing.T) {
	response, err := createDcApiResponse(authorizationResponseConfig{
		ResponseMode: ResponseMode_DcApi,
		// state is not defined for the DC API; setting it here proves it is dropped.
		State: "should-not-appear",
		QueryResponses: []dcql.QueryResponse{{
			QueryId:     testDcqlQueryId,
			Credentials: []string{"presented~sd~jwt"},
		}},
	})

	require.NoError(t, err)
	require.JSONEq(t, `{"vp_token":{"my_credential":["presented~sd~jwt"]}}`, response)
}

func TestCreateDcApiResponse_DcApiJwt(t *testing.T) {
	privateKey, jwks := testEncryptionKeys(t)

	response, err := createDcApiResponse(authorizationResponseConfig{
		ResponseMode:   ResponseMode_DcApiJwt,
		State:          "should-not-appear",
		EncryptionKeys: &jwks,
		QueryResponses: []dcql.QueryResponse{{
			QueryId:     testDcqlQueryId,
			Credentials: []string{"presented~sd~jwt"},
		}},
	})
	require.NoError(t, err)

	var envelope struct {
		Response string `json:"response"`
		VpToken  any    `json:"vp_token"`
	}
	require.NoError(t, json.Unmarshal([]byte(response), &envelope))
	require.NotEmpty(t, envelope.Response, "the encrypted response goes in the response member")
	require.Nil(t, envelope.VpToken, "the vp_token must not also be sent in the clear")

	decrypted, err := jwe.Decrypt([]byte(envelope.Response), jwe.WithKey(jwa.ECDH_ES(), privateKey))
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(decrypted, &payload))
	require.Equal(t,
		map[string]any{"my_credential": []any{"presented~sd~jwt"}},
		payload["vp_token"],
	)
	require.NotContains(t, payload, "state")
}

func TestCreateDcApiResponse_DcApiJwtWithoutEncryptionKey(t *testing.T) {
	_, err := createDcApiResponse(authorizationResponseConfig{ResponseMode: ResponseMode_DcApiJwt})
	require.ErrorContains(t, err, "the encryption key is nil")
}

func TestCreateDcApiResponse_RejectsNonDcApiResponseMode(t *testing.T) {
	_, err := createDcApiResponse(authorizationResponseConfig{ResponseMode: ResponseMode_DirectPost})
	require.ErrorContains(t, err, "is not a digital credentials api response mode")
}

// direct_post.jwt keeps carrying state, which the DC API response modes drop.
func TestCreateAuthorizationResponseHttpRequest_DirectPostJwtKeepsState(t *testing.T) {
	privateKey, jwks := testEncryptionKeys(t)

	request, err := createAuthorizationResponseHttpRequest(authorizationResponseConfig{
		ResponseMode:   ResponseMode_DirectPostJwt,
		ResponseUri:    "https://verifier.example.com/response",
		State:          "the-state",
		EncryptionKeys: &jwks,
		QueryResponses: []dcql.QueryResponse{{
			QueryId:     testDcqlQueryId,
			Credentials: []string{"presented~sd~jwt"},
		}},
	})
	require.NoError(t, err)
	require.NoError(t, request.ParseForm())

	decrypted, err := jwe.Decrypt([]byte(request.PostForm.Get("response")), jwe.WithKey(jwa.ECDH_ES(), privateKey))
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(decrypted, &payload))
	require.Equal(t, "the-state", payload["state"])
}

func testEncryptionKeys(t *testing.T) (jwk.Key, jwk.Set) {
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

	return privateKey, jwks
}

// ========================================================================
// End to end through the client
// ========================================================================

func TestNewDcApiSession_ReturnsResponseThroughThePlatform(t *testing.T) {
	dcqlHandler := &mockDcqlHandler{}
	client := &Client{dcqlHandler: dcql.NewDcqlHandler([]dcql.DcqlCredentialQueryHandler{dcqlHandler})}

	handler := &testHandler{
		failureCh: make(chan *clientmodels.SessionError, 1),
		successCh: make(chan string, 1),
		dcApiCh:   make(chan string, 1),
		grant: []dcql.DisclosureSelection{{
			QueryId:        testDcqlQueryId,
			CredentialHash: "credential-hash",
		}},
	}

	client.NewDcApiSession(&DcApiRequest{
		Protocol: DcApiProtocolUnsigned,
		Origin:   testOrigin,
		Data:     unsignedRequestData(t, nil),
	}, handler)

	select {
	case response := <-handler.dcApiCh:
		require.JSONEq(t, `{"vp_token":{"my_credential":["presented~sd~jwt"]}}`, response)
	case err := <-handler.failureCh:
		t.Fatalf("session failed: %v", err.WrappedError)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the digital credentials api response")
	}

	select {
	case <-handler.successCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the success callback")
	}

	// Appendix A.4: the presentations are bound to the origin, not to a client
	// identifier — even though this request carried none at all.
	require.Equal(t, "origin:"+testOrigin, dcqlHandler.preparedForAudience)
	require.Equal(t, "n-0S6_WzA2Mj", dcqlHandler.preparedForNonce)
}

// A signed request identifies the verifier through a trust framework, but the
// response is still bound to the origin rather than to the client identifier.
func TestNewDcApiSession_SignedRequestStillBindsToTheOrigin(t *testing.T) {
	dcqlHandler := &mockDcqlHandler{}
	client := &Client{
		dcqlHandler:       dcql.NewDcqlHandler([]dcql.DcqlCredentialQueryHandler{dcqlHandler}),
		verifierValidator: &mockVerifierValidator{request: signedAuthRequest([]string{testOrigin})},
	}

	handler := &testHandler{
		failureCh: make(chan *clientmodels.SessionError, 1),
		dcApiCh:   make(chan string, 1),
		grant: []dcql.DisclosureSelection{{
			QueryId:        testDcqlQueryId,
			CredentialHash: "credential-hash",
		}},
	}

	client.NewDcApiSession(&DcApiRequest{
		Protocol: DcApiProtocolSigned,
		Origin:   testOrigin,
		Data:     signedRequestData(t),
	}, handler)

	select {
	case <-handler.dcApiCh:
	case err := <-handler.failureCh:
		t.Fatalf("session failed: %v", err.WrappedError)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the digital credentials api response")
	}

	require.Equal(t, "origin:"+testOrigin, dcqlHandler.preparedForAudience)
}

// The dismisser NewDcApiSession returns is bound to its own session, like the one
// NewSession returns, so dismissing unwinds that session and reports Cancelled.
// Whether the dismissal arrives before or after the permission window opens, the
// session ends up cancelled exactly once.
func TestNewDcApiSession_DismisserIsBoundToItsOwnSession(t *testing.T) {
	client := &Client{dcqlHandler: dcql.NewDcqlHandler([]dcql.DcqlCredentialQueryHandler{&mockDcqlHandler{}})}

	// grant stays nil: the session parks awaiting the answer the dismissal delivers.
	handler := &testHandler{
		failureCh:   make(chan *clientmodels.SessionError, 1),
		cancelledCh: make(chan struct{}, 1),
	}

	dismisser := client.NewDcApiSession(&DcApiRequest{
		Protocol: DcApiProtocolUnsigned,
		Origin:   testOrigin,
		Data:     unsignedRequestData(t, nil),
	}, handler)

	dismisser.Dismiss()

	select {
	case <-handler.cancelledCh:
	case err := <-handler.failureCh:
		t.Fatalf("session failed: %v", err.WrappedError)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the dismissed session to be cancelled")
	}
}

func TestNewDcApiSession_ReportsFailureForAnInvalidRequest(t *testing.T) {
	client := newTestClient()
	handler := &testHandler{failureCh: make(chan *clientmodels.SessionError, 1)}

	client.NewDcApiSession(&DcApiRequest{
		Protocol: DcApiProtocolUnsigned,
		Origin:   testOrigin,
		Data:     unsignedRequestData(t, map[string]any{"response_mode": "direct_post"}),
	}, handler)

	err := awaitOn(t, handler.failureCh, "a failure callback")
	require.Contains(t, err.WrappedError, `requires response_mode "dc_api" or "dc_api.jwt"`)
}
