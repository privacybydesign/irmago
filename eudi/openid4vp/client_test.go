package openid4vp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func init() {
	eudi.Logger = logrus.New()
}

// testHandler captures the Failure callback from the OpenID4VP client.
type testHandler struct {
	failureCh chan *clientmodels.SessionError
}

func (h *testHandler) Failure(err *clientmodels.SessionError) {
	h.failureCh <- err
}

func (h *testHandler) Cancelled() {}

func (h *testHandler) Success(_ string, _ []clientmodels.LogCredential) {}

func (h *testHandler) RequestVerificationPermission(
	_ *clientmodels.DisclosurePlan,
	_ *clientmodels.TrustedParty,
	_ map[string]string,
	_ PermissionHandler,
) {
}

func awaitFailure(t *testing.T, h *testHandler) *clientmodels.SessionError {
	t.Helper()
	select {
	case err := <-h.failureCh:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for failure callback")
		return nil
	}
}

func TestNewSession_NonOKHttpStatus_ReportsFailure(t *testing.T) {
	codes := []int{
		http.StatusNotFound,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
		http.StatusForbidden,
	}

	for _, code := range codes {
		t.Run(fmt.Sprintf("HTTP_%d", code), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))
			defer server.Close()

			client := &Client{dcqlHandler: dcql.NewDcqlHandler(nil)}
			handler := &testHandler{failureCh: make(chan *clientmodels.SessionError, 1)}

			client.NewSession(fmt.Sprintf("openid4vp://?request_uri=%s", server.URL), handler)

			err := awaitFailure(t, handler)
			require.Contains(t, err.WrappedError, fmt.Sprintf("HTTP %d", code))
		})
	}
}

func TestNewSession_MissingRequestUri_ReportsFailure(t *testing.T) {
	client := &Client{dcqlHandler: dcql.NewDcqlHandler(nil)}
	handler := &testHandler{failureCh: make(chan *clientmodels.SessionError, 1)}

	client.NewSession("openid4vp://", handler)

	err := awaitFailure(t, handler)
	require.Contains(t, err.WrappedError, "request_uri")
}
