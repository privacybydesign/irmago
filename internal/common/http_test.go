package common

import "testing"

// TestHTTPClientConfig pins the configuration of the shared HTTP client so the
// "single source of truth" it provides stays intact: it must exist, use the
// default transport (nil Transport => http.DefaultTransport, the shared
// connection pool), and set no client-level Timeout (which would interrupt
// response-body reads; see issue #606, callers use per-request context
// deadlines instead).
func TestHTTPClientConfig(t *testing.T) {
	if HTTPClient == nil {
		t.Fatal("common.HTTPClient must not be nil")
	}
	if HTTPClient.Transport != nil {
		t.Errorf("common.HTTPClient.Transport = %v, want nil (http.DefaultTransport)", HTTPClient.Transport)
	}
	if HTTPClient.Timeout != 0 {
		t.Errorf("common.HTTPClient.Timeout = %v, want 0 (no client-level timeout)", HTTPClient.Timeout)
	}
}
