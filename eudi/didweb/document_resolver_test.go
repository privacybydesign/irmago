package didweb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/privacybydesign/irmago/eudi/did"
	"github.com/privacybydesign/irmago/eudi/dnssec"
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
	require.Contains(t, err.Error(), "404")
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

// fakeDnssecVerifier records the hosts it was asked to verify and returns a fixed result.
type fakeDnssecVerifier struct {
	result dnssec.Result
	hosts  []string
}

func (f *fakeDnssecVerifier) Verify(host string) dnssec.Result {
	f.hosts = append(f.hosts, host)
	return f.result
}

func Test_ResolveWithDnssec_ReportsResultForDidDomain(t *testing.T) {
	doc := did.Document{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      "did:web:example.com",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/did+json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer server.Close()

	verifier := &fakeDnssecVerifier{result: dnssec.Result{Status: dnssec.StatusBogus, Detail: "tampered"}}
	resolver := &DocumentResolver{
		HTTPClient: &http.Client{
			Transport: &hostOverrideTransport{
				base:       http.DefaultTransport,
				targetHost: server.Listener.Addr().String(),
				useHTTP:    true,
			},
		},
		DnssecVerifier: verifier,
	}

	result, dnssecResult, err := resolver.ResolveWithDnssec("did:web:example.com")
	require.NoError(t, err)
	require.Equal(t, "did:web:example.com", result.ID)
	require.NotNil(t, dnssecResult)
	require.Equal(t, dnssec.StatusBogus, dnssecResult.Status)
	// The check must run against the DID's domain, not the overridden test server.
	require.Equal(t, []string{"example.com"}, verifier.hosts)
}

func Test_ResolveWithDnssec_WithoutVerifier_ReturnsNilResult(t *testing.T) {
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
	}

	result, dnssecResult, err := resolver.ResolveWithDnssec("did:web:example.com")
	require.NoError(t, err)
	require.Equal(t, "did:web:example.com", result.ID)
	require.Nil(t, dnssecResult)
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
