package openid4vp

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/stretchr/testify/require"
)

// ========================================================================
// Fixtures
// ========================================================================

// testDcqlQueryJson is the dcql_query a verifier serializes into the query
// string. It asks for the one credential mockDcqlHandler owns.
func testDcqlQueryJson() string {
	return fmt.Sprintf(
		`{"credentials":[{"id":%q,"format":"dc+sd-jwt","meta":{"vct_values":["https://credentials.example.com/identity_credential"]}}]}`,
		testDcqlQueryId,
	)
}

// unsignedSessionUrl builds the link of a verifier that sends its request
// parameters in the query string rather than in a request object. responseUri
// doubles as the client identifier, which is what the redirect_uri: prefix
// means. An override with an empty value drops the parameter.
func unsignedSessionUrl(responseUri string, overrides map[string]string) string {
	query := url.Values{}
	query.Set("client_id", string(ClientIdentifierPrefix_RedirectUri)+responseUri)
	query.Set("response_type", string(ResponseType_VpToken))
	query.Set("response_mode", string(ResponseMode_DirectPost))
	query.Set("response_uri", responseUri)
	query.Set("nonce", "n-0S6_WzA2Mj")
	query.Set("state", "state-42")
	query.Set("dcql_query", testDcqlQueryJson())

	for key, value := range overrides {
		if value == "" {
			query.Del(key)
			continue
		}
		query.Set(key, value)
	}
	return "openid4vp://?" + query.Encode()
}

// newUrlSessionClient builds a client that can run a URL-invoked session all the
// way to a response, with the given validator standing in for the trust models.
func newUrlSessionClient(validator VerifierValidator) (*Client, *mockDcqlHandler) {
	handler := &mockDcqlHandler{}
	return &Client{
		dcqlHandler:       dcql.NewDcqlHandler([]dcql.DcqlCredentialQueryHandler{handler}),
		verifierValidator: validator,
	}, handler
}

// newGrantingHandler answers the permission request the way a user who agrees to
// disclose does, and captures what the session reported.
func newGrantingHandler() *testHandler {
	return &testHandler{
		failureCh:   make(chan *clientmodels.SessionError, 1),
		successCh:   make(chan string, 1),
		requestorCh: make(chan *clientmodels.TrustedParty, 1),
		grant: []dcql.DisclosureSelection{{
			QueryId:        testDcqlQueryId,
			CredentialHash: "credential-hash",
		}},
	}
}

// responseCollector serves as the verifier's response_uri, recording the form the
// wallet posted so a test can tell a real disclosure from an empty POST.
type responseCollector struct {
	server *httptest.Server
	posted chan url.Values
}

func newResponseCollector(t *testing.T) *responseCollector {
	t.Helper()
	collector := &responseCollector{posted: make(chan url.Values, 1)}
	collector.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		collector.posted <- values
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.server.Close)
	return collector
}

func (c *responseCollector) uri() string { return c.server.URL }

// ========================================================================
// End-to-end: request parameters in the query string
// ========================================================================

// The wallet used to refuse every link without a request_uri, which left out the
// plainest form OpenID4VP defines: the request parameters in the query string,
// with no request object anywhere. Such a request runs to a real response here.
func TestNewSession_UnsignedQueryString_CompletesSession(t *testing.T) {
	collector := newResponseCollector(t)
	client, dcqlHandler := newUrlSessionClient(nil)
	handler := newGrantingHandler()

	client.NewSession(unsignedSessionUrl(collector.uri(), nil), handler)

	require.Equal(t, "managed to complete openid4vp session", awaitOn(t, handler.successCh, "success"))

	posted := awaitOn(t, collector.posted, "the authorization response")
	require.Contains(t, posted.Get("vp_token"), "presented~sd~jwt")
	require.Equal(t, "state-42", posted.Get("state"))

	// The presentation is bound to the client identifier, exactly as it is for a
	// signed request arriving over a link.
	require.Equal(t, string(ClientIdentifierPrefix_RedirectUri)+collector.uri(), dcqlHandler.preparedForAudience)
	require.Equal(t, "n-0S6_WzA2Mj", dcqlHandler.preparedForNonce)
}

// Nothing in an unsigned request is authenticated, so the user must not be told
// the verifier was: the party shown is the response location, unverified.
func TestNewSession_UnsignedQueryString_ShowsAnUnverifiedRequestor(t *testing.T) {
	collector := newResponseCollector(t)
	client, _ := newUrlSessionClient(nil)
	handler := newGrantingHandler()

	client.NewSession(unsignedSessionUrl(collector.uri(), nil), handler)

	requestor := awaitOn(t, handler.requestorCh, "a permission request")
	require.False(t, requestor.Verified, "an unsigned request authenticates nobody")
	require.Nil(t, requestor.Image, "no logo was ever authenticated for this verifier")
	require.Equal(t, string(ClientIdentifierPrefix_RedirectUri)+collector.uri(), requestor.Id)

	parsed, err := url.Parse(collector.uri())
	require.NoError(t, err)
	require.Equal(t, parsed.Scheme+"://"+parsed.Host, requestor.Name)
}

// The client identifier is what the user is shown and what the presentation is
// bound to, so a request whose response location contradicts it is refused
// rather than answered towards one of the two.
func TestNewSession_UnsignedQueryString_ResponseUriMismatch_ReportsFailure(t *testing.T) {
	collector := newResponseCollector(t)
	client, _ := newUrlSessionClient(nil)
	handler := newGrantingHandler()

	client.NewSession(unsignedSessionUrl(collector.uri(), map[string]string{
		"response_uri": "https://elsewhere.example.com/response",
	}), handler)

	err := awaitOn(t, handler.failureCh, "a failure callback")
	require.Contains(t, err.WrappedError, "does not match the response location")
	require.Empty(t, collector.posted, "nothing may be posted anywhere")
	require.Empty(t, handler.successCh)
}

// A verifier may leave the response location out when the client identifier
// already states it (Section 5.10), so it is filled in from there.
func TestNewSession_UnsignedQueryString_OmittedResponseUri_IsTakenFromClientId(t *testing.T) {
	collector := newResponseCollector(t)
	client, _ := newUrlSessionClient(nil)
	handler := newGrantingHandler()

	client.NewSession(unsignedSessionUrl(collector.uri(), map[string]string{"response_uri": ""}), handler)

	require.Equal(t, "managed to complete openid4vp session", awaitOn(t, handler.successCh, "success"))
	posted := awaitOn(t, collector.posted, "the authorization response")
	require.Contains(t, posted.Get("vp_token"), "presented~sd~jwt")
}

// Every other client identifier prefix names something a signature is checked
// against, so it says nothing on a request nobody signed.
func TestNewSession_UnsignedQueryString_RejectsSignedOnlyClientIdPrefix(t *testing.T) {
	prefixes := []ClientIdentifierPrefix{
		ClientIdentifierPrefix_X509SanDns,
		ClientIdentifierPrefix_X509Hash,
		ClientIdentifierPrefix_DecentralizedDid,
		ClientIdentifierPrefix_Origin,
	}

	for _, prefix := range prefixes {
		t.Run(string(prefix), func(t *testing.T) {
			collector := newResponseCollector(t)
			client, _ := newUrlSessionClient(nil)
			handler := newGrantingHandler()

			client.NewSession(unsignedSessionUrl(collector.uri(), map[string]string{
				"client_id": string(prefix) + "verifier.example.com",
			}), handler)

			err := awaitOn(t, handler.failureCh, "a failure callback")
			require.Contains(t, err.WrappedError, "can only be used with a signed request object")
			require.Empty(t, collector.posted)
		})
	}
}

// A response mode the wallet cannot answer in used to reach the transport, which
// posted an empty form and reported whatever the verifier said about it.
func TestNewSession_RejectsUnanswerableResponseMode(t *testing.T) {
	tests := []struct {
		name         string
		responseMode string
		wantError    string
	}{
		{"fragment", "fragment", `response_mode "fragment" is not supported`},
		{"query", "query", `response_mode "query" is not supported`},
		{"absent", "", "carries no response_mode"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := newResponseCollector(t)
			client, _ := newUrlSessionClient(nil)
			handler := newGrantingHandler()

			client.NewSession(unsignedSessionUrl(collector.uri(), map[string]string{
				"response_mode": test.responseMode,
			}), handler)

			err := awaitOn(t, handler.failureCh, "a failure callback")
			require.Contains(t, err.WrappedError, test.wantError)
			require.Empty(t, collector.posted, "no empty response may be posted")
			require.Empty(t, handler.successCh)
		})
	}
}

// The DC API response modes stay out of reach from a link however the request
// arrived: an unsigned request must not reach the delivery branch either.
func TestNewSession_UnsignedQueryString_RejectsDcApiResponseMode(t *testing.T) {
	for _, mode := range []ResponseMode{ResponseMode_DcApi, ResponseMode_DcApiJwt} {
		t.Run(string(mode), func(t *testing.T) {
			collector := newResponseCollector(t)
			client, _ := newUrlSessionClient(nil)
			handler := newGrantingHandler()
			handler.dcApiCh = make(chan string, 1)

			client.NewSession(unsignedSessionUrl(collector.uri(), map[string]string{
				"response_mode": string(mode),
			}), handler)

			err := awaitOn(t, handler.failureCh, "a failure callback")
			require.Contains(t, err.WrappedError, "only valid for a session started over the digital credentials api")
			require.Empty(t, handler.dcApiCh, "there is no platform to hand a response to")
		})
	}
}

// A malformed dcql_query is reported as such rather than silently becoming an
// empty query the wallet has no candidates for.
func TestNewSession_UnsignedQueryString_MalformedDcqlQuery_ReportsFailure(t *testing.T) {
	collector := newResponseCollector(t)
	client, _ := newUrlSessionClient(nil)
	handler := newGrantingHandler()

	client.NewSession(unsignedSessionUrl(collector.uri(), map[string]string{
		"dcql_query": "{not json",
	}), handler)

	err := awaitOn(t, handler.failureCh, "a failure callback")
	require.Contains(t, err.WrappedError, "failed to parse the dcql_query parameter")
}

// ========================================================================
// End-to-end: request object by value
// ========================================================================

// A request object may be passed by value in `request` instead of being fetched
// from a request_uri. It is the same signed object, so it takes the same
// verification path -- there is just no HTTP round trip to make.
func TestNewSession_InlineRequestObject_IsVerifiedAndAnswered(t *testing.T) {
	collector := newResponseCollector(t)

	// The client identifier names the host the response goes to, which
	// validateResponseUriBinding holds an x509_san_dns: verifier to.
	parsed, err := url.Parse(collector.uri())
	require.NoError(t, err)

	signed := signedAuthRequest(nil)
	signed.ClientId = string(ClientIdentifierPrefix_X509SanDns) + parsed.Hostname()
	signed.ResponseMode = ResponseMode_DirectPost
	signed.ResponseUri = collector.uri()
	signed.State = "state-42"

	client, dcqlHandler := newUrlSessionClient(&mockVerifierValidator{request: signed})
	handler := newGrantingHandler()

	query := url.Values{}
	query.Set("request", "eyJhbGciOiJFUzI1NiJ9.e30.signature")
	client.NewSession("openid4vp://?"+query.Encode(), handler)

	require.Equal(t, "managed to complete openid4vp session", awaitOn(t, handler.successCh, "success"))
	require.Equal(t, signed.ClientId, dcqlHandler.preparedForAudience)

	requestor := awaitOn(t, handler.requestorCh, "a permission request")
	require.Equal(t, "Verifier Example", requestor.Name, "a verified request names the verifier, not its URL")
}

// The link's own client_id is unauthenticated, but it must still agree with the
// signed one -- for a request object passed by value just as for a fetched one.
func TestNewSession_InlineRequestObject_ClientIdMismatch_ReportsFailure(t *testing.T) {
	signed := signedAuthRequest(nil)
	signed.ResponseMode = ResponseMode_DirectPost
	signed.ResponseUri = "https://rp.example.com/response"

	client, _ := newUrlSessionClient(&mockVerifierValidator{request: signed})
	handler := newGrantingHandler()

	query := url.Values{}
	query.Set("request", "eyJhbGciOiJFUzI1NiJ9.e30.signature")
	query.Set("client_id", "x509_san_dns:someone.else.example.com")
	client.NewSession("openid4vp://?"+query.Encode(), handler)

	err := awaitOn(t, handler.failureCh, "a failure callback")
	require.Contains(t, err.WrappedError, "but the signed request names")
}

// The two ways of passing a request object can name different requests, and
// nothing but read order would decide which one the wallet acts on.
func TestNewSession_RequestAndRequestUri_ReportsFailure(t *testing.T) {
	client, _ := newUrlSessionClient(&mockVerifierValidator{request: signedAuthRequest(nil)})
	handler := newGrantingHandler()

	query := url.Values{}
	query.Set("request", "eyJhbGciOiJFUzI1NiJ9.e30.signature")
	query.Set("request_uri", "https://rp.example.com/request")
	client.NewSession("openid4vp://?"+query.Encode(), handler)

	err := awaitOn(t, handler.failureCh, "a failure callback")
	require.Contains(t, err.WrappedError, "request and request_uri must not both be present")
}

// ========================================================================
// Parsing
// ========================================================================

func TestParseUnsignedUrlRequest_ReadsTheRequestParameters(t *testing.T) {
	query, err := url.ParseQuery(url.Values{
		"client_id":       {"redirect_uri:https://rp.example.com/response"},
		"response_type":   {"vp_token"},
		"response_mode":   {"direct_post.jwt"},
		"response_uri":    {"https://rp.example.com/response"},
		"nonce":           {"n-0S6_WzA2Mj"},
		"state":           {"state-42"},
		"dcql_query":      {testDcqlQueryJson()},
		"client_metadata": {`{"encrypted_response_enc_values_supported":["A256GCM"],"client_name":"Not shown"}`},
	}.Encode())
	require.NoError(t, err)

	request, err := parseUnsignedUrlRequest(query)

	require.NoError(t, err)
	require.Equal(t, "redirect_uri:https://rp.example.com/response", request.ClientId)
	require.Equal(t, "vp_token", request.ResponseType)
	require.Equal(t, ResponseMode_DirectPostJwt, request.ResponseMode)
	require.Equal(t, "https://rp.example.com/response", request.ResponseUri)
	require.Equal(t, "n-0S6_WzA2Mj", request.Nonce)
	require.Equal(t, "state-42", request.State)
	require.Len(t, request.DcqlQuery.Credentials, 1)
	require.Equal(t, testDcqlQueryId, request.DcqlQuery.Credentials[0].Id)
	require.NotNil(t, request.ClientMetadata)
	require.Equal(t, []string{"A256GCM"}, request.ClientMetadata.EncryptedResponseEncValuesSupported)
}

// expected_origins is for signed requests over the Digital Credentials API. Read
// from a query string it would let an unauthenticated caller state which origins
// to trust, so there is nothing that reads it.
func TestParseUnsignedUrlRequest_IgnoresExpectedOrigins(t *testing.T) {
	query := url.Values{"expected_origins": {`["https://evil.example.com"]`}}

	request, err := parseUnsignedUrlRequest(query)

	require.NoError(t, err)
	require.Empty(t, request.ExpectedOrigins)
}

func TestValidateUnsignedUrlRequest(t *testing.T) {
	const location = "https://rp.example.com/response"

	tests := []struct {
		name            string
		request         *AuthorizationRequest
		wantError       string
		wantResponseUri string
	}{
		{
			name: "the response uri matching the client id is accepted",
			request: &AuthorizationRequest{
				ClientId:     "redirect_uri:" + location,
				ResponseMode: ResponseMode_DirectPost,
				ResponseUri:  location,
			},
			wantResponseUri: location,
		},
		{
			name: "an omitted response uri is taken from the client id",
			request: &AuthorizationRequest{
				ClientId:     "redirect_uri:" + location,
				ResponseMode: ResponseMode_DirectPost,
			},
			wantResponseUri: location,
		},
		{
			name: "a redirect uri matching the client id is accepted",
			request: &AuthorizationRequest{
				ClientId:     "redirect_uri:" + location,
				ResponseMode: ResponseMode_DirectPost,
				RedirectUri:  location,
			},
		},
		{
			name:      "a request without a client id is refused",
			request:   &AuthorizationRequest{ResponseMode: ResponseMode_DirectPost},
			wantError: "no client_id",
		},
		{
			name: "a client id that is not a URL is refused",
			request: &AuthorizationRequest{
				ClientId:     "redirect_uri:rp.example.com/response",
				ResponseMode: ResponseMode_DirectPost,
			},
			wantError: "does not name an absolute URL",
		},
		{
			name: "an empty client id location is refused",
			request: &AuthorizationRequest{
				ClientId:     "redirect_uri:",
				ResponseMode: ResponseMode_DirectPost,
			},
			wantError: "names no response location",
		},
		{
			name: "a response uri the client id does not name is refused",
			request: &AuthorizationRequest{
				ClientId:     "redirect_uri:" + location,
				ResponseMode: ResponseMode_DirectPost,
				ResponseUri:  "https://elsewhere.example.com/response",
			},
			wantError: "does not match the response location",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateUnsignedUrlRequest(test.request)

			if test.wantError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.wantError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.wantResponseUri, test.request.ResponseUri)
		})
	}
}

// No response location is invented for a response mode that sends the response
// nowhere: such a request is refused for its response mode, and filling one in
// would only hide which parameter the verifier got wrong.
func TestValidateUnsignedUrlRequest_DoesNotInventAResponseUriForOtherModes(t *testing.T) {
	request := &AuthorizationRequest{
		ClientId:     "redirect_uri:https://rp.example.com/response",
		ResponseMode: "fragment",
	}

	require.NoError(t, validateUnsignedUrlRequest(request))
	require.Empty(t, request.ResponseUri)
	require.Empty(t, request.RedirectUri)
}

// The response location is the only thing an unsigned request binds, so the name
// shown for it must not collapse locations the response would go to separately.
// The path is dropped -- it names an endpoint, not a party -- but the scheme and
// a non-default port are not.
func TestUnsignedUrlRequestor_DisplayName(t *testing.T) {
	tests := []struct{ clientId, displayName string }{
		{"redirect_uri:https://rp.example.com/response", "https://rp.example.com"},
		{"redirect_uri:http://rp.example.com/response", "http://rp.example.com"},
		{"redirect_uri:https://rp.example.com:8443/response", "https://rp.example.com:8443"},
		{"redirect_uri:https://rp.example.com:443/response", "https://rp.example.com"},
		{"redirect_uri:http://rp.example.com:80/response", "http://rp.example.com"},
	}

	for _, test := range tests {
		t.Run(test.clientId, func(t *testing.T) {
			requestor := unsignedUrlRequestor(&AuthorizationRequest{ClientId: test.clientId})

			require.Equal(t, test.displayName, requestor.Name)
			require.Equal(t, test.clientId, requestor.Id)
			require.False(t, requestor.Verified)
		})
	}
}
