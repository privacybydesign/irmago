package openid4vci

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/metadata"
	"github.com/privacybydesign/irmago/eudi/oauth2"
	"github.com/privacybydesign/irmago/eudi/oauth2/clientattestationtest"
	"github.com/privacybydesign/irmago/eudi/oauth2/dpoptest"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/walletprovider"
	"github.com/privacybydesign/irmago/walletprovider/fake"
	"github.com/privacybydesign/irmago/walletprovider/providertest"
)

// activeFakeAttester is a client attester over an activated fake wallet
// provider, whose WIAs chain to the returned CA.
func activeFakeAttester(t *testing.T) (*services.WalletProviderClientAttester, *fake.Provider, *fake.AttestationCA) {
	t.Helper()
	ca, err := fake.NewAttestationCA()
	require.NoError(t, err)
	p, err := fake.New(fake.Options{AttestationCA: ca})(providertest.NewHost())
	require.NoError(t, err)
	require.NoError(t, p.Activate(context.Background(), "12345"))
	return services.NewClientAttester(p), p.(*fake.Provider), ca
}

// challengeMode is how a strict authorization server hands out attestation
// challenges.
type challengeMode int

const (
	noChallenge challengeMode = iota
	// challengeEndpoint: from its challenge endpoint.
	challengeEndpoint
	// challengeOnError: by refusing a PoP without one with
	// use_attestation_challenge and a challenge header.
	challengeOnError
)

// attestingAuthorizationServer is a strict authorization server that
// authenticates every PAR and token request with client attestation
// (clientattestationtest.Verify against the fake provider's CA), and checks
// DPoP too when dpop is set.
type attestingAuthorizationServer struct {
	*httptest.Server
	ca       *fake.AttestationCA
	mode     challengeMode
	dpop     bool
	requests atomic.Int32

	mu        sync.Mutex
	challenge string
	counter   int
	// verified records every authenticated request, in order.
	verified []*clientattestationtest.Result
}

func newAttestingAuthorizationServer(t *testing.T, ca *fake.AttestationCA, mode challengeMode, dpop bool) *attestingAuthorizationServer {
	as := &attestingAuthorizationServer{ca: ca, mode: mode, dpop: dpop}
	as.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/challenge" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"attestation_challenge": as.newChallenge()})
			return
		}
		as.requests.Add(1)

		as.mu.Lock()
		want := as.challenge
		as.mu.Unlock()
		if as.mode != noChallenge && want == "" {
			want = "none-issued-yet"
		}
		result, err := clientattestationtest.Verify(r, as.ca.Roots(), as.URL, want)
		if err != nil {
			if as.mode == challengeOnError {
				w.Header().Set(headerClientAttestationChallenge, as.newChallenge())
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"use_attestation_challenge"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprintf(w, `{"error":"invalid_client","error_description":%q}`, err.Error())
			return
		}
		if as.dpop {
			if _, err := dpoptest.Verify(r, "", ""); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprintf(w, `{"error":"invalid_dpop_proof","error_description":%q}`, err.Error())
				return
			}
		}
		as.mu.Lock()
		as.verified = append(as.verified, result)
		as.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/par":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"request_uri":"urn:par:1","expires_in":60}`))
		case "/token":
			tokenType := "Bearer"
			if as.dpop {
				tokenType = "DPoP"
			}
			_, _ = fmt.Fprintf(w, `{"access_token":"t","token_type":%q}`, tokenType)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return as
}

func (as *attestingAuthorizationServer) newChallenge() string {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.counter++
	as.challenge = fmt.Sprintf("challenge-%d", as.counter)
	return as.challenge
}

func (as *attestingAuthorizationServer) results() []*clientattestationtest.Result {
	as.mu.Lock()
	defer as.mu.Unlock()
	return append([]*clientattestationtest.Result(nil), as.verified...)
}

func newAttestingSession(t *testing.T, as *attestingAuthorizationServer, attester ClientAttester, withPAR bool) *session {
	asMetadata := &oauth2.AuthorizationServerMetadata{
		Issuer:                            as.URL,
		AuthorizationEndpoint:             as.URL + "/authorize",
		TokenEndpoint:                     as.URL + "/token",
		TokenEndpointAuthMethodsSupported: []string{authMethodAttestJwtClientAuth},
	}
	if withPAR {
		par := as.URL + "/par"
		asMetadata.PushedAuthorizationRequestEndpoint = &par
	}
	if as.mode == challengeEndpoint {
		endpoint := as.URL + "/challenge"
		asMetadata.ChallengeEndpoint = &endpoint
	}
	s := &session{
		ctx:             context.Background(),
		httpClient:      as.Client(),
		handler:         newMockSessionHandler(t),
		redirectUri:     "https://open.yivi.app/-/auth-callback",
		clientAttester:  attester,
		credentialOffer: &CredentialOffer{CredentialIssuer: as.URL, CredentialConfigurationIds: []string{"cred"}},
		credentialIssuerMetadata: &metadata.CredentialIssuerMetadata{
			CredentialIssuer:                  as.URL,
			CredentialConfigurationsSupported: map[string]metadata.CredentialConfiguration{"cred": {}},
		},
		issuerSettings: openid4vciSessionIssuerSettings{
			authorizationServer:         as.URL,
			authorizationServerMetadata: asMetadata,
			useClientAttestation:        true,
		},
	}
	if as.dpop {
		var err error
		s.dpop, err = oauth2.NewDPoP()
		require.NoError(t, err)
	}
	return s
}

func preAuthorizedTokenRequest(s *session, txCode *string) (AccessTokenResponse, error) {
	return (&PreAuthorizedCodeFlowHandler{}).doTokenRequest(s, &PreAuthorizedCodeGrant{PreAuthorizedCode: "code"}, txCode)
}

func TestConfigureClientAttestation(t *testing.T) {
	attester, _, _ := activeFakeAttester(t)
	unavailable := services.NewClientAttester(nil)

	for name, tc := range map[string]struct {
		methods  []string
		popAlgs  []string
		attester ClientAttester
		use      bool
		fails    bool
	}{
		"not asked for":                       {methods: []string{"none"}, attester: attester},
		"asked for and available":             {methods: []string{authMethodAttestJwtClientAuth}, attester: attester, use: true},
		"required but unavailable":            {methods: []string{authMethodAttestJwtClientAuth}, attester: unavailable, fails: true},
		"required and no attester":            {methods: []string{authMethodAttestJwtClientAuth}, fails: true},
		"optional and unavailable":            {methods: []string{authMethodAttestJwtClientAuth, "none"}, attester: unavailable},
		"required but not with ES256":         {methods: []string{authMethodAttestJwtClientAuth}, popAlgs: []string{"RS256"}, attester: attester, fails: true},
		"optional, ES256 among the PoP algs":  {methods: []string{authMethodAttestJwtClientAuth, "public"}, popAlgs: []string{"RS256", "ES256"}, attester: attester, use: true},
		"optional, not with ES256, continues": {methods: []string{authMethodAttestJwtClientAuth, "none"}, popAlgs: []string{"RS256"}, attester: attester},
	} {
		t.Run(name, func(t *testing.T) {
			s := &session{
				ctx:            context.Background(),
				clientAttester: tc.attester,
				issuerSettings: openid4vciSessionIssuerSettings{authorizationServerMetadata: &oauth2.AuthorizationServerMetadata{
					TokenEndpointAuthMethodsSupported:             tc.methods,
					ClientAttestationPopSigningAlgValuesSupported: tc.popAlgs,
				}},
			}
			err := s.configureClientAttestation()
			if tc.fails {
				require.ErrorContains(t, err, "requires a wallet instance attestation")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.use, s.issuerSettings.useClientAttestation)
		})
	}
}

// TestRequiredClientAttestationIsRefusedBeforeConsent runs a whole session
// against an authorization server that requires client attestation, with a
// wallet that cannot provide one: it fails without asking the user anything.
func TestRequiredClientAttestationIsRefusedBeforeConsent(t *testing.T) {
	var asServer *httptest.Server
	asServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oauth2.AuthorizationServerMetadata{
			Issuer:                            asServer.URL,
			TokenEndpoint:                     asServer.URL + "/token",
			TokenEndpointAuthMethodsSupported: []string{authMethodAttestJwtClientAuth},
		})
	}))
	defer asServer.Close()

	handler := newMockSessionHandler(t)
	s := &session{
		ctx:            context.Background(),
		handler:        handler,
		clientAttester: services.NewClientAttester(nil),
		credentialOffer: &CredentialOffer{
			CredentialIssuer: asServer.URL,
			Grants:           &Grants{PreAuthorizedCodeGrant: &PreAuthorizedCodeGrant{PreAuthorizedCode: "code"}},
		},
		credentialIssuerMetadata: &metadata.CredentialIssuerMetadata{CredentialIssuer: asServer.URL},
	}
	s.perform()
	require.False(t, handler.AwaitSessionEnd(), "the session failed")
	require.Empty(t, handler.tokenPermissionRequestChannel, "the user was never asked")
}

func TestPreAuthorizedTokenRequestIsAuthenticatedWithAWIA(t *testing.T) {
	for name, mode := range map[string]challengeMode{"no challenge": noChallenge, "challenge endpoint": challengeEndpoint, "challenge on error": challengeOnError} {
		t.Run(name, func(t *testing.T) {
			attester, provider, ca := activeFakeAttester(t)
			as := newAttestingAuthorizationServer(t, ca, mode, true)
			defer as.Close()
			s := newAttestingSession(t, as, attester, false)

			resp, err := preAuthorizedTokenRequest(s, nil)
			require.NoError(t, err)
			require.Equal(t, "DPoP", resp.GetTokenType(), "client attestation and DPoP together")

			results := as.results()
			require.Len(t, results, 1)
			require.Equal(t, "yivi-wallet", results[0].ClientID)
			require.True(t, results[0].Attestation.Key.Equal(&s.clientAttestation.key.PublicKey), "the WIA binds the session's key")
			require.Equal(t, 1, provider.InstanceAttestations())
			if mode == challengeOnError {
				require.EqualValues(t, 2, as.requests.Load(), "the challenge demand is answered with one retry")
			}
		})
	}
}

func TestTheWIAIsFetchedOncePerSession(t *testing.T) {
	attester, provider, ca := activeFakeAttester(t)
	as := newAttestingAuthorizationServer(t, ca, noChallenge, false)
	defer as.Close()
	s := newAttestingSession(t, as, attester, false)

	// As after a wrong transaction code: a second token request.
	for range 2 {
		_, err := preAuthorizedTokenRequest(s, nil)
		require.NoError(t, err)
	}
	results := as.results()
	require.Len(t, results, 2)
	require.Equal(t, 1, provider.InstanceAttestations(), "one WIA for the session")
	require.NotEqual(t, results[0].JwtID, results[1].JwtID, "a fresh PoP per request")
}

func TestSessionsDoNotShareAWIAKey(t *testing.T) {
	attester, _, ca := activeFakeAttester(t)
	as := newAttestingAuthorizationServer(t, ca, noChallenge, false)
	defer as.Close()
	var keys []*ecdsa.PublicKey
	for range 2 {
		s := newAttestingSession(t, as, attester, false)
		_, err := preAuthorizedTokenRequest(s, nil)
		require.NoError(t, err)
		keys = append(keys, &s.clientAttestation.key.PublicKey)
	}
	require.False(t, keys[0].Equal(keys[1]), "each session binds a key of its own")
}

func TestAuthorizationCodeFlowIsAuthenticatedWithAWIA(t *testing.T) {
	for _, withPAR := range []bool{true, false} {
		t.Run(fmt.Sprintf("PAR %v", withPAR), func(t *testing.T) {
			attester, provider, ca := activeFakeAttester(t)
			as := newAttestingAuthorizationServer(t, ca, challengeEndpoint, true)
			defer as.Close()
			s := newAttestingSession(t, as, attester, withPAR)
			s.issuerSettings.grantType = &AuthorizationCodeGrant{}
			h := &AuthorizationCodeFlowHandler{httpClient: s.httpClient, dpop: s.dpop}

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
			require.Equal(t, "yivi-wallet", url.Values(req.request.AuthorizationParameters).Get("client_id"), "the authorization request names the WIA's sub")
			callback := "https://open.yivi.app/-/auth-callback?code=c&state=" + req.state
			req.callback(true, &callback)
			r := <-done
			require.NoError(t, r.err)

			results := as.results()
			if withPAR {
				require.Len(t, results, 2, "PAR and token request")
				require.True(t, results[0].Attestation.Key.Equal(results[1].Attestation.Key), "one WIA for both")
			} else {
				require.Len(t, results, 1, "the token request")
			}
			require.Equal(t, 1, provider.InstanceAttestations())
		})
	}
}

func TestARefusedWIAFailsTheTokenRequestBeforeItIsSent(t *testing.T) {
	attester, provider, ca := activeFakeAttester(t)
	as := newAttestingAuthorizationServer(t, ca, noChallenge, false)
	defer as.Close()
	require.NoError(t, provider.Revoke(context.Background()))
	s := newAttestingSession(t, as, attester, false)

	_, err := preAuthorizedTokenRequest(s, nil)
	require.ErrorContains(t, err, "wallet instance attestation")
	require.True(t, errors.Is(err, walletprovider.ErrNotActivated))
	require.Zero(t, as.requests.Load())
}
