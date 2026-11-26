package openid4vci

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/oauth2"
	"github.com/privacybydesign/irmago/eudi/oauth2/dpoptest"
)

// dpopAuthorizationServer is a strict authorization server: it demands a DPoP
// nonce first, then verifies every proof and binds the token it issues to the
// proof key. jkt records the thumbprint of the key the token is bound to.
type dpopAuthorizationServer struct {
	*httptest.Server
	calls atomic.Int32
	jkt   atomic.Value
	// requests records the form of every token and PAR request.
	requests []url.Values
}

func newDPoPAuthorizationServer(t *testing.T) *dpopAuthorizationServer {
	as := &dpopAuthorizationServer{}
	as.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		as.calls.Add(1)
		require.NoError(t, r.ParseForm())
		as.requests = append(as.requests, r.PostForm)

		proof, err := dpoptest.Verify(r, "", "as-nonce")
		if err != nil {
			w.Header().Set("DPoP-Nonce", "as-nonce")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		as.jkt.Store(proof.Thumbprint)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/par":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"request_uri":"urn:par:1","expires_in":60}`))
		case "/token":
			_, _ = w.Write([]byte(`{"access_token":"dpop-bound","token_type":"DPoP"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return as
}

func newDPoPTestSession(t *testing.T, as *dpopAuthorizationServer, withPAR bool) *session {
	d, err := oauth2.NewDPoP()
	require.NoError(t, err)
	asMetadata := &oauth2.AuthorizationServerMetadata{
		Issuer:                        as.URL,
		AuthorizationEndpoint:         as.URL + "/authorize",
		TokenEndpoint:                 as.URL + "/token",
		DPoPSigningAlgValuesSupported: []string{"ES256"},
	}
	if withPAR {
		par := as.URL + "/par"
		asMetadata.PushedAuthorizationRequestEndpoint = &par
	}
	return &session{
		httpClient:      as.Client(),
		handler:         newMockSessionHandler(t),
		redirectUri:     "https://open.yivi.app/-/auth-callback",
		dpop:            d,
		credentialOffer: &CredentialOffer{CredentialIssuer: as.URL, CredentialConfigurationIds: []string{"cred"}},
		credentialIssuerMetadata: &metadata.CredentialIssuerMetadata{
			CredentialIssuer:                  as.URL,
			CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"cred": {}},
		},
		issuerSettings: openid4vciSessionIssuerSettings{authorizationServerMetadata: asMetadata},
	}
}

func TestConfigureIssuerSettingsCreatesDPoPOnlyWhenSupported(t *testing.T) {
	for name, algs := range map[string][]string{"supported": {"ES256"}, "not advertised": nil, "no ES256": {"RS256"}} {
		t.Run(name, func(t *testing.T) {
			var asServer *httptest.Server
			asServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(oauth2.AuthorizationServerMetadata{
					Issuer:                        asServer.URL,
					TokenEndpoint:                 asServer.URL + "/token",
					DPoPSigningAlgValuesSupported: algs,
				})
			}))
			defer asServer.Close()

			s := &session{
				credentialOffer: &CredentialOffer{
					CredentialIssuer: asServer.URL,
					Grants:           &Grants{PreAuthorizedCodeGrant: &PreAuthorizedCodeGrant{PreAuthorizedCode: "code"}},
				},
				credentialIssuerMetadata: &metadata.CredentialIssuerMetadata{CredentialIssuer: asServer.URL},
			}
			require.NoError(t, s.configureIssuerSettings())
			require.Equal(t, name == "supported", s.dpop != nil)
		})
	}
}

func TestPreAuthorizedTokenRequestIsDPoPBound(t *testing.T) {
	as := newDPoPAuthorizationServer(t)
	defer as.Close()
	s := newDPoPTestSession(t, as, false)

	resp, err := (&PreAuthorizedCodeFlowHandler{}).doTokenRequest(s, &PreAuthorizedCodeGrant{PreAuthorizedCode: "code"}, nil)
	require.NoError(t, err)
	require.Equal(t, "DPoP", resp.GetTokenType())
	require.EqualValues(t, 2, as.calls.Load(), "the nonce demand is answered with one retry")

	jkt, err := s.dpop.Thumbprint()
	require.NoError(t, err)
	require.Equal(t, jkt, as.jkt.Load(), "the token is bound to the session's DPoP key")
}

func TestAuthorizationCodeFlowIsDPoPBound(t *testing.T) {
	for _, withPAR := range []bool{true, false} {
		name := "without PAR"
		if withPAR {
			name = "with PAR"
		}
		t.Run(name, func(t *testing.T) {
			as := newDPoPAuthorizationServer(t)
			defer as.Close()
			s := newDPoPTestSession(t, as, withPAR)
			s.issuerSettings.grantType = &AuthorizationCodeGrant{}
			h := &AuthorizationCodeFlowHandler{httpClient: s.httpClient, dpop: s.dpop}
			jkt, err := s.dpop.Thumbprint()
			require.NoError(t, err)

			type result struct {
				resp AccessTokenResponse
				err  error
			}
			done := make(chan result, 1)
			go func() {
				resp, err := h.HandleGrant(s)
				done <- result{resp, err}
			}()

			req := s.handler.(*MockSessionHandler).AwaitAuthCodeRequest()
			if withPAR {
				// The PAR request carried the proof; the browser only gets the request_uri.
				require.Equal(t, "urn:par:1", url.Values(req.request.AuthorizationParameters).Get("request_uri"))
				require.Empty(t, url.Values(req.request.AuthorizationParameters).Get("dpop_jkt"))
			} else {
				require.Equal(t, jkt, url.Values(req.request.AuthorizationParameters).Get("dpop_jkt"))
			}
			callback := "https://open.yivi.app/-/auth-callback?code=c&state=" + req.state
			req.callback(true, &callback)

			r := <-done
			require.NoError(t, r.err)
			require.Equal(t, "DPoP", r.resp.GetTokenType())
			require.Equal(t, jkt, as.jkt.Load())
		})
	}
}

func TestDPoPTokenRequiresAProof(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"access_token":"t","token_type":"DPoP"}`)),
	}
	_, err := handleTokenResponse(resp, false)
	require.ErrorContains(t, err, "token type", "a DPoP token for a request without a proof")

	resp.Body = io.NopCloser(strings.NewReader(`{"access_token":"t","token_type":"Bearer"}`))
	tok, err := handleTokenResponse(resp, true)
	require.NoError(t, err, "an AS that got a proof may still issue a bearer token")
	require.Equal(t, "Bearer", tok.GetTokenType())
}

func TestCredentialRequestPresentsTheDPoPToken(t *testing.T) {
	var calls atomic.Int32
	credentialEndpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		require.Equal(t, "DPoP dpop-bound", r.Header.Get("Authorization"))
		if _, err := dpoptest.Verify(r, "dpop-bound", "rs-nonce"); err != nil {
			w.Header().Set("DPoP-Nonce", "rs-nonce")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Past the DPoP checks; end the request here rather than issuing.
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"dpop accepted"}`))
	})
	s, ts := setupTestEnvironment(t, NonceNotRequired, credentialEndpoint)
	defer ts.Close()
	var err error
	s.dpop, err = oauth2.NewDPoP()
	require.NoError(t, err)
	s.accessTokenType = "DPoP"

	_, err = s.obtainCredential("credential-config-1", nil, "dpop-bound")
	require.ErrorContains(t, err, "dpop accepted")
	require.EqualValues(t, 2, calls.Load(), "the resource server's nonce demand is answered with one retry")
}

func TestBearerTokenIsSentWithoutAProof(t *testing.T) {
	credentialEndpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer plain", r.Header.Get("Authorization"))
		require.Empty(t, r.Header.Get("DPoP"))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"bearer accepted"}`))
	})
	s, ts := setupTestEnvironment(t, NonceNotRequired, credentialEndpoint)
	defer ts.Close()
	var err error
	s.dpop, err = oauth2.NewDPoP()
	require.NoError(t, err)
	s.accessTokenType = "Bearer"

	_, err = s.obtainCredential("credential-config-1", nil, "plain")
	require.ErrorContains(t, err, "bearer accepted")
}
