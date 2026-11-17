package myirmaserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCORSHeadersOnIrmaEndpoints is a regression test for
// https://github.com/privacybydesign/irmago/issues/368: the myirmaserver mounts
// the IRMA session server under /irma/, and those endpoints must inherit the
// same CORS configuration as the rest of the myirmaserver endpoints.
//
// The CORS middleware is registered on the root router before the /irma/ mount,
// so it wraps every route including the mounted IRMA session server. This test
// asserts that an /irma/ route returns the configured CORS headers, identically
// to a non-/irma/ route, so the coverage cannot silently regress to a subset of
// the endpoints again.
func TestCORSHeadersOnIrmaEndpoints(t *testing.T) {
	const allowedOrigin = "https://myirma.example.com"

	conf := newTestConfiguration(t, newMemoryDB(), "")
	conf.CORSAllowedOrigins = []string{allowedOrigin}

	s, err := New(conf)
	require.NoError(t, err)
	defer s.Stop()

	handler := s.Handler()

	// Both a regular myirmaserver endpoint and an /irma/ endpoint must echo the
	// configured allowed origin. The /irma/ path does not need to resolve to a
	// real session: CORS runs as middleware before routing, so the assertion
	// holds regardless of the mounted handler's response.
	for _, tc := range []struct {
		name string
		path string
	}{
		{"non-irma endpoint", "/checksession"},
		{"irma endpoint", "/irma/session/abc/status"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Preflight request.
			preflight := httptest.NewRequest(http.MethodOptions, tc.path, nil)
			preflight.Header.Set("Origin", allowedOrigin)
			preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, preflight)
			require.Equal(t, allowedOrigin, rec.Header().Get("Access-Control-Allow-Origin"),
				"preflight on %s must echo the configured allowed origin", tc.path)
			require.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"),
				"preflight on %s must allow credentials", tc.path)

			// Actual request.
			actual := httptest.NewRequest(http.MethodGet, tc.path, nil)
			actual.Header.Set("Origin", allowedOrigin)
			rec = httptest.NewRecorder()
			handler.ServeHTTP(rec, actual)
			require.Equal(t, allowedOrigin, rec.Header().Get("Access-Control-Allow-Origin"),
				"actual request on %s must echo the configured allowed origin", tc.path)
		})
	}

	// A disallowed origin must not be echoed back on the /irma/ endpoints either,
	// confirming the configured policy (not a permissive default) governs them.
	t.Run("disallowed origin on irma endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/irma/session/abc/status", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.NotEqual(t, "https://evil.example.com", rec.Header().Get("Access-Control-Allow-Origin"),
			"a disallowed origin must not be echoed on /irma/ endpoints")
	})
}
