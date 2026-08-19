package irma

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestJsonRequest_NonRemoteErrorBodyReportsStatus covers issue #695: on a binary
// (CBOR) transport, a non-2xx body that is not a RemoteError used to be reported
// as the CBOR decoding failure, which hid the status that actually explains what
// went wrong.
func TestJsonRequest_NonRemoteErrorBodyReportsStatus(t *testing.T) {
	tests := []struct {
		name        string
		binary      bool
		status      int
		body        []byte
		contains    []string
		notContains []string
	}{
		{
			name:     "binary transport, plain text 404 body",
			binary:   true,
			status:   http.StatusNotFound,
			body:     []byte("404 page not found\n"),
			contains: []string{"unexpected response, status 404", "404 page not found"},
		},
		{
			name:   "binary transport, unprintable body",
			binary: true,
			status: http.StatusBadGateway,
			body:   []byte{0x00, 0x01, 0x02, 0x03},
			// Nothing printable is left, so no snippet is appended: the ": " that
			// separates the status from the snippet must be absent.
			contains:    []string{"unexpected response, status 502"},
			notContains: []string{":"},
		},
		{
			name:        "binary transport, empty body",
			binary:      true,
			status:      http.StatusNotFound,
			body:        nil,
			contains:    []string{"unexpected response, status 404"},
			notContains: []string{":"},
		},
		{
			name:     "json transport, html error page",
			binary:   false,
			status:   http.StatusServiceUnavailable,
			body:     []byte("<html>\n<body>Service Unavailable</body>\n</html>"),
			contains: []string{"unexpected response, status 503", "<html> <body>Service Unavailable</body> </html>"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write(test.body)
			}))
			defer server.Close()

			transport := NewHTTPTransport(server.URL, false)
			transport.Binary = test.binary

			err := transport.Get("revocation/update", &struct{}{})

			var serr *SessionError
			require.ErrorAs(t, err, &serr)
			require.Equal(t, ErrorServerResponse, serr.ErrorType)
			require.Equal(t, test.status, serr.RemoteStatus)
			require.NotNil(t, serr.Err)
			for _, substr := range test.contains {
				require.Contains(t, serr.Err.Error(), substr)
			}
			for _, substr := range test.notContains {
				require.NotContains(t, serr.Err.Error(), substr)
			}
			require.NotContains(t, serr.Err.Error(), "cbor")
			require.NotContains(t, serr.Err.Error(), "RemoteError")
		})
	}
}

// TestJsonRequest_LongBodyIsTruncated asserts that an error message stays short
// even when the server returns a large body.
func TestJsonRequest_LongBodyIsTruncated(t *testing.T) {
	body := make([]byte, 5000)
	for i := range body {
		body[i] = 'a'
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(body)
	}))
	defer server.Close()

	err := NewHTTPTransport(server.URL, false).Get("foo", &struct{}{})

	var serr *SessionError
	require.ErrorAs(t, err, &serr)
	require.Less(t, len(serr.Err.Error()), 200)
	require.Contains(t, serr.Err.Error(), "unexpected response, status 500")
	require.Contains(t, serr.Err.Error(), "...")
}

// TestJsonRequest_RemoteErrorBodyIsPreserved asserts that a body that _is_ a
// RemoteError still ends up in the SessionError untouched.
func TestJsonRequest_RemoteErrorBodyIsPreserved(t *testing.T) {
	for _, binary := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "binary"}[binary], func(t *testing.T) {
			apierr := &RemoteError{
				Status:      http.StatusNotFound,
				ErrorName:   "UNKNOWN_REVOCATION_KEY",
				Description: "Unknown revocation key",
			}
			var body []byte
			var err error
			if binary {
				body, err = MarshalBinary(apierr)
			} else {
				body, err = json.Marshal(apierr)
			}
			require.NoError(t, err)

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write(body)
			}))
			defer server.Close()

			transport := NewHTTPTransport(server.URL, false)
			transport.Binary = binary

			err = transport.Get("foo", &struct{}{})

			var serr *SessionError
			require.ErrorAs(t, err, &serr)
			require.Equal(t, ErrorApi, serr.ErrorType)
			require.Equal(t, http.StatusNotFound, serr.RemoteStatus)
			require.Equal(t, apierr, serr.RemoteError)
		})
	}
}

// TestNewHTTPTransport_UsesEnvironmentProxy covers issue #423: HTTPTransport was the
// only outbound transport in irmago that left http.Transport.Proxy unset, so it ignored
// the HTTP_PROXY/HTTPS_PROXY environment variables that everything routed through
// http.DefaultTransport already honours.
//
// The proxy function is inspected directly rather than exercised against a real proxy,
// because net/http reads the environment once behind a sync.Once: a test setting
// HTTP_PROXY would only take effect if it happened to run before any other code in the
// process resolved a proxy.
func TestNewHTTPTransport_UsesEnvironmentProxy(t *testing.T) {
	inner, ok := NewHTTPTransport("https://example.com", true).client.HTTPClient.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, inner.Proxy, "outbound transport must honour HTTP_PROXY/HTTPS_PROXY")

	// Loopback destinations are never proxied, whatever the environment says, so local
	// servers (including the ones in these tests) keep being dialled directly.
	for _, dest := range []string{"http://localhost:8080/foo", "http://127.0.0.1:8080/foo"} {
		u, err := url.Parse(dest)
		require.NoError(t, err)
		proxy, err := inner.Proxy(&http.Request{URL: u})
		require.NoError(t, err)
		require.Nil(t, proxy, "loopback destination %s must not be proxied", dest)
	}
}
