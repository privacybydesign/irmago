package didweb

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func Test_didWebToURL(t *testing.T) {
	tests := []struct {
		name        string
		did         string
		expectedURL string
		expectError bool
	}{
		{
			name:        "domain only uses well-known path",
			did:         "did:web:example.com",
			expectedURL: "https://example.com/.well-known/did.json",
		},
		{
			name:        "domain with port uses well-known path",
			did:         "did:web:example.com%3A8080",
			expectedURL: "https://example.com:8080/.well-known/did.json",
		},
		{
			name:        "domain with path",
			did:         "did:web:example.com:user:alice",
			expectedURL: "https://example.com/user/alice/did.json",
		},
		{
			name:        "domain with single path segment",
			did:         "did:web:example.com:issuer",
			expectedURL: "https://example.com/issuer/did.json",
		},
		{
			name:        "missing did:web prefix",
			did:         "did:jwk:abc",
			expectError: true,
		},
		{
			name:        "empty method-specific identifier",
			did:         "did:web:",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := didWebToURL(tt.did)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expectedURL, got)
		})
	}
}

func Test_Resolve_AllowInsecure_FallsBackToHTTP(t *testing.T) {
	doc := did.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      "did:web:example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer server.Close()

	resolver := &DocumentResolver{
		HTTPClient: &http.Client{
			Transport: &hostOverrideTransport{
				base:       http.DefaultTransport,
				targetHost: server.Listener.Addr().String(),
				useHTTP:    true,
			},
		},
		AllowInsecure: true,
	}

	result, err := resolver.Resolve("did:web:example.com")
	require.NoError(t, err)
	require.Equal(t, "did:web:example.com", result.ID)
}

func Test_Resolve_ReturnsDocument(t *testing.T) {
	doc := did.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      "did:web:example.com",
		VerificationMethod: []did.VerificationMethod{
			{
				ID:         "did:web:example.com#key-1",
				Type:       "JsonWebKey2020",
				Controller: "did:web:example.com",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/.well-known/did.json", r.URL.Path)
		w.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer server.Close()

	// Override the URL by resolving a loopback DID and swapping the host via a custom transport.
	resolver := &DocumentResolver{
		HTTPClient: &http.Client{
			Transport: &hostOverrideTransport{
				base:       http.DefaultTransport,
				targetHost: server.Listener.Addr().String(),
				useHTTP:    true,
			},
		},
	}

	result, err := resolver.Resolve("did:web:example.com")
	require.NoError(t, err)
	require.Equal(t, "did:web:example.com", result.ID)
	require.Len(t, result.VerificationMethod, 1)
}

func Test_Resolve_HTTPErrorReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	resolver := &DocumentResolver{
		HTTPClient: &http.Client{
			Transport: &hostOverrideTransport{
				base:       http.DefaultTransport,
				targetHost: server.Listener.Addr().String(),
				useHTTP:    true,
			},
		},
	}

	_, err := resolver.Resolve("did:web:example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "did:web: DID document not found")
}

func Test_Resolve_UnmarshalDocumentCorrectly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(testdata.ValidDidDocument)
	}))
	defer server.Close()

	resolver := &DocumentResolver{
		HTTPClient: &http.Client{
			Transport: &hostOverrideTransport{
				base:       http.DefaultTransport,
				targetHost: server.Listener.Addr().String(),
				useHTTP:    true,
			},
		},
	}

	// Resolver does not resolve from actual domain, but host is overridden to point to the test server, so the content of the document is determined by the test server's response.
	doc, err := resolver.Resolve("did:web:issuer.dev.eduid.nl")
	require.NoError(t, err)
	require.Equal(t, "did:web:issuer.dev.eduid.nl", doc.ID)
	require.Len(t, doc.VerificationMethod, 1)
	require.Equal(t, "did:web:issuer.dev.eduid.nl#0", doc.VerificationMethod[0].ID)
	require.Equal(t, did.VerificationMethodType_JsonWebKey2020, doc.VerificationMethod[0].Type)
	require.Equal(t, "did:web:issuer.dev.eduid.nl", doc.VerificationMethod[0].Controller)
	require.NotNil(t, doc.VerificationMethod[0].PublicKeyJwk)
}

// ─── insecure HTTP fallback ───────────────────────────────────────────────────
// The fallback is deliberately narrow: only a 404 from the HTTPS endpoint means
// "this host serves its DID document over plain HTTP instead". Every other
// failure mode must surface as-is, so a hostile or broken HTTPS host cannot
// downgrade key resolution to an unauthenticated channel.

func Test_Resolve_AllowInsecure_NotFound_FallsBackToHTTP(t *testing.T) {
	httpsSrv, httpsHits := newDidDocumentServer(t, http.StatusNotFound, nil)
	httpSrv, httpHits := newDidDocumentServer(t, http.StatusOK, didDocumentBytes(t, "did:web:example.com"))

	resolver := newSchemeRoutingResolver(httpsSrv, httpSrv, true)

	doc, err := resolver.Resolve("did:web:example.com")
	require.NoError(t, err)
	require.Equal(t, "did:web:example.com", doc.ID)
	require.Equal(t, int64(1), httpsHits.Load())
	require.Equal(t, int64(1), httpHits.Load(), "404 over HTTPS must trigger exactly one plain-HTTP retry")
}

func Test_Resolve_AllowInsecure_ServerError_DoesNotFallBackToHTTP(t *testing.T) {
	httpsSrv, _ := newDidDocumentServer(t, http.StatusInternalServerError, nil)
	httpSrv, httpHits := newDidDocumentServer(t, http.StatusOK, didDocumentBytes(t, "did:web:example.com"))

	resolver := newSchemeRoutingResolver(httpsSrv, httpSrv, true)

	_, err := resolver.Resolve("did:web:example.com")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected HTTP status 500")
	require.Zero(t, httpHits.Load(), "a non-404 HTTPS response must not be retried over plain HTTP")
}

func Test_Resolve_AllowInsecure_TransportError_DoesNotFallBackToHTTP(t *testing.T) {
	// Pins current behaviour: when the HTTPS request never completes (no TLS
	// listener, dial refused, handshake failure) there is no 404 to observe, so
	// no fallback happens. Note this is exactly the shape of a dev host that
	// only listens on plain HTTP — if that flow must keep working, the fallback
	// condition needs to widen, and this expectation flips.
	httpSrv, httpHits := newDidDocumentServer(t, http.StatusOK, didDocumentBytes(t, "did:web:example.com"))

	resolver := newSchemeRoutingResolver(nil, httpSrv, true)

	_, err := resolver.Resolve("did:web:example.com")
	require.Error(t, err)
	require.Zero(t, httpHits.Load())
}

func Test_Resolve_WithoutAllowInsecure_NotFound_DoesNotFallBackToHTTP(t *testing.T) {
	httpsSrv, _ := newDidDocumentServer(t, http.StatusNotFound, nil)
	httpSrv, httpHits := newDidDocumentServer(t, http.StatusOK, didDocumentBytes(t, "did:web:example.com"))

	resolver := newSchemeRoutingResolver(httpsSrv, httpSrv, false)

	_, err := resolver.Resolve("did:web:example.com")
	require.Error(t, err)
	require.Zero(t, httpHits.Load(), "the plain-HTTP retry requires AllowInsecure")
}

func didDocumentBytes(t *testing.T, id string) []byte {
	t.Helper()
	body, err := json.Marshal(did.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      id,
	})
	require.NoError(t, err)
	return body
}

// newDidDocumentServer serves body with the given status and counts requests.
func newDidDocumentServer(t *testing.T, status int, body []byte) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	hits := &atomic.Int64{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/did+json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)
	return server, hits
}

// newSchemeRoutingResolver builds a resolver whose HTTPS and plain-HTTP
// attempts land on separate backends, so a test can observe which one was used.
// A nil httpsSrv makes the HTTPS attempt fail at the transport level.
func newSchemeRoutingResolver(httpsSrv, httpSrv *httptest.Server, allowInsecure bool) *DocumentResolver {
	transport := &schemeRoutingTransport{httpHost: httpSrv.Listener.Addr().String()}
	if httpsSrv != nil {
		transport.httpsHost = httpsSrv.Listener.Addr().String()
	}
	return &DocumentResolver{
		HTTPClient:    &http.Client{Transport: transport},
		AllowInsecure: allowInsecure,
	}
}

// schemeRoutingTransport sends a request to a different backend depending on the
// scheme the resolver chose. Both backends are plain-HTTP test servers; the
// https branch only stands in for "the HTTPS attempt". An empty httpsHost makes
// the https attempt fail before it reaches any server.
type schemeRoutingTransport struct {
	httpsHost string
	httpHost  string
}

func (t *schemeRoutingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	if req.URL.Scheme == "https" {
		if t.httpsHost == "" {
			return nil, fmt.Errorf("simulated TLS dial failure")
		}
		clone.URL.Host = t.httpsHost
	} else {
		clone.URL.Host = t.httpHost
	}
	clone.URL.Scheme = "http"
	return http.DefaultTransport.RoundTrip(clone)
}

// hostOverrideTransport redirects all requests to a test server.
type hostOverrideTransport struct {
	base       http.RoundTripper
	targetHost string
	useHTTP    bool
}

func (t *hostOverrideTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	scheme := "https"
	if t.useHTTP {
		scheme = "http"
	}
	clone.URL.Scheme = scheme
	clone.URL.Host = t.targetHost
	return t.base.RoundTrip(clone)
}
