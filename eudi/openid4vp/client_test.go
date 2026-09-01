package openid4vp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp/dcql"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func init() {
	eudi.Logger = logrus.New()
}

// newTestClient builds a Client with the collaborators a session needs.
func newTestClient() *Client {
	return &Client{
		dcqlHandler:    dcql.NewDcqlHandler(nil),
		trustEvaluator: services.NewTrustService(nil, nil, nil),
	}
}

// awaitOn returns the next value sent on ch, failing the test if none arrives.
func awaitOn[T any](t *testing.T, ch chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

// spyHandler records what the client reported, so a test can tell a legitimate
// re-ask from the runaway re-asking of a dead session.
type spyHandler struct {
	requests  atomic.Int32
	cancels   atomic.Int32
	successes atomic.Int32
	requested chan PermissionHandler
	// requestors carries the party each permission request was asked about, so
	// a test can assert what the session decided about the verifier.
	requestors chan *clientmodels.TrustedParty
	failed     chan *clientmodels.SessionError
}

func newSpyHandler() *spyHandler {
	return &spyHandler{
		requested:  make(chan PermissionHandler, 16),
		requestors: make(chan *clientmodels.TrustedParty, 16),
		failed:     make(chan *clientmodels.SessionError, 1),
	}
}

func (h *spyHandler) Failure(err *clientmodels.SessionError) { h.failed <- err }

func (h *spyHandler) Cancelled() { h.cancels.Add(1) }

func (h *spyHandler) Success(_ string, _ []clientmodels.LogCredential) { h.successes.Add(1) }

// DeliverDcApiResponse is never called for the URL-invoked sessions this handler
// serves; sessions started over the Digital Credentials API use testHandler.
func (h *spyHandler) DeliverDcApiResponse(_ string) {}

func (h *spyHandler) RequestVerificationPermission(
	_ *clientmodels.DisclosurePlan,
	requestor *clientmodels.TrustedParty,
	_ map[string]string,
	callback PermissionHandler,
) {
	h.requests.Add(1)
	h.requestors <- requestor
	h.requested <- callback
}

// awaitRequestor returns the verifier the session asked permission about.
func (h *spyHandler) awaitRequestor(t *testing.T) *clientmodels.TrustedParty {
	t.Helper()
	return awaitOn(t, h.requestors, "a permission request")
}

// awaitRequest returns the callback the session handed out with its latest
// permission request, so a test can answer as the UI would.
func (h *spyHandler) awaitRequest(t *testing.T) PermissionHandler {
	t.Helper()
	return awaitOn(t, h.requested, "a permission request")
}

func (h *spyHandler) awaitFailure(t *testing.T) *clientmodels.SessionError {
	t.Helper()
	return awaitOn(t, h.failed, "a failure callback")
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

			client := newTestClient()
			handler := newSpyHandler()

			client.NewSession(fmt.Sprintf("openid4vp://?request_uri=%s", server.URL), handler)

			err := handler.awaitFailure(t)
			require.Contains(t, err.WrappedError, fmt.Sprintf("HTTP %d", code))
		})
	}
}

func TestNewSession_MissingRequestUri_ReportsFailure(t *testing.T) {
	client := newTestClient()
	handler := newSpyHandler()

	client.NewSession("openid4vp://", handler)

	err := handler.awaitFailure(t)
	require.Contains(t, err.WrappedError, "request_uri")
}
