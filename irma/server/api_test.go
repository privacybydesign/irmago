package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/common"

	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/require"
)

func TestParseSessionRequest(t *testing.T) {
	requestJson := `{"@context":"https://irma.app/ld/request/disclosure/v2","context":"AQ==","nonce":"M3LYmTr3CZDYZkMNK2uCCg==","protocolVersion":"2.5","disclose":[[["irma-demo.RU.studentCard.studentID"]]],"labels":{"0":null}}`
	requestorRequestJson := fmt.Sprintf(`{"request": %s}`, requestJson)
	t.Run("valid json string", func(t *testing.T) {
		res, err := ParseSessionRequest(requestJson)
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
	})

	t.Run("valid byte array", func(t *testing.T) {
		res, err := ParseSessionRequest([]byte(requestJson))
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
	})

	t.Run("valid struct", func(t *testing.T) {
		request := &irma.DisclosureRequest{}
		require.NoError(t, json.Unmarshal([]byte(requestJson), request))
		res, err := ParseSessionRequest(request)
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
	})

	t.Run("correct default validity", func(t *testing.T) {
		res, err := ParseSessionRequest(requestJson)
		require.NoError(t, err)
		require.Equal(t, irma.DefaultJwtValidity, res.Base().ResultJwtValidity)
	})

	t.Run("requestor request string", func(t *testing.T) {
		res, err := ParseSessionRequest(requestorRequestJson)
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
	})

	t.Run("requestor request struct", func(t *testing.T) {
		request := &irma.DisclosureRequest{}
		require.NoError(t, json.Unmarshal([]byte(requestJson), request))
		sessionRequest := &irma.ServiceProviderRequest{
			Request: request,
		}

		res, err := ParseSessionRequest(sessionRequest)
		require.NoError(t, err)
		require.Equal(t,
			"irma-demo.RU.studentCard.studentID",
			res.SessionRequest().Disclosure().Disclose[0][0][0].Type.String())
		req, ok := res.(*irma.ServiceProviderRequest)
		require.True(t, ok)
		require.Equal(t, request, req.Request)
	})

	t.Run("invalid type", func(t *testing.T) {
		_, err := ParseSessionRequest(42)
		require.Error(t, err)
	})

	t.Run("invalid string", func(t *testing.T) {
		_, err := ParseSessionRequest(`{"foo": "bar"}`)
		require.Error(t, err)
	})
}

type readerFunc func(p []byte) (int, error)

func (r readerFunc) Read(p []byte) (int, error) { return r(p) }

func TestServerTimeouts(t *testing.T) {
	timeout := 250 * time.Millisecond
	var called bool

	tests := []struct {
		name        string
		handler     http.Handler
		body        io.Reader
		readTimeout time.Duration
	}{
		{
			name: "write",
			handler: TimeoutMiddleware(nil, timeout)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				time.Sleep(2 * timeout)
			})),
			body:        nil,
			readTimeout: ReadTimeout,
		},
		{
			name: "read",
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				start := time.Now()
				_, err := io.ReadAll(r.Body)
				defer common.Close(r.Body)
				// check that reading has halted with an error just after the deadline
				require.Error(t, err)
				require.Greater(t, int64(timeout+50*time.Millisecond), int64(time.Since(start)))
				w.WriteHeader(400)
			}),
			body: readerFunc(func(p []byte) (int, error) {
				time.Sleep(2 * timeout)
				return 0, io.EOF
			}),
			readTimeout: timeout,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// start server
			s := startServer(t, test.handler, test.readTimeout)
			defer stopServer(t, s)

			// do request
			called = false
			req, err := http.NewRequest(http.MethodPost, "http://localhost:34534", test.body)
			require.NoError(t, err)
			start := time.Now()
			res, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			require.NoError(t, res.Body.Close())

			// Check whether an error is returned when the context deadline exceeds and the handler
			// does not act upon this within 200 ms. We add 50 ms slack to prevent race conditions.
			require.Greater(t, int64(timeout+250*time.Millisecond), int64(time.Since(start)))
			require.GreaterOrEqual(t, res.StatusCode, 400)
			require.True(t, called)
		})
	}
}

func startServer(t *testing.T, handler http.Handler, timeout time.Duration) *http.Server {
	s := &http.Server{
		Addr:        "localhost:34534",
		Handler:     handler,
		ReadTimeout: timeout,
	}
	go func() {
		err := s.ListenAndServe()
		require.Equal(t, http.ErrServerClosed, err)
	}()
	time.Sleep(50 * time.Millisecond) // give server time to start
	return s
}

func stopServer(t *testing.T, server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	require.NoError(t, server.Shutdown(ctx))
	cancel()
}

func TestFilterHeaders(t *testing.T) {
	headers := http.Header{
		"Authorization":       []string{"Bearer supersecret-token"},
		"Proxy-Authorization": []string{"Basic c2VjcmV0"},
		"Cookie":              []string{"session=abc123"},
		"Set-Cookie":          []string{"session=def456; HttpOnly"},
		"X-Auth-Token":        []string{"another-secret"},
		"X-Api-Key":           []string{"key-secret"},
		"Api-Key":             []string{"key-secret"},
		"X-Csrf-Token":        []string{"csrf-secret"},
		"X-Xsrf-Token":        []string{"xsrf-secret"},
		"Content-Type":        []string{"application/json"},
		"User-Agent":          []string{"irma-test"},
	}

	filtered := filterHeaders(headers)

	// Sensitive headers must be redacted, regardless of header-name casing.
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
		"X-Auth-Token", "X-Api-Key", "Api-Key", "X-Csrf-Token", "X-Xsrf-Token",
	} {
		require.Equal(t, []string{"[redacted]"}, filtered[name], "header %s should be redacted", name)
	}

	// Non-sensitive headers must pass through unchanged.
	require.Equal(t, []string{"application/json"}, filtered["Content-Type"])
	require.Equal(t, []string{"irma-test"}, filtered["User-Agent"])

	// The original headers must not be mutated by filtering.
	require.Equal(t, []string{"Bearer supersecret-token"}, headers["Authorization"])
}

func TestFilterHeadersCaseInsensitive(t *testing.T) {
	// http.Header keys are canonicalized, but verify lookups are case-insensitive
	// in case headers are constructed directly with lower-case keys.
	headers := http.Header{"authorization": []string{"secret"}}
	filtered := filterHeaders(headers)
	// filterHeaders preserves the original (lower-case) key, so look it up via the
	// underlying map type to avoid http.Header key canonicalization (SA1008).
	require.Equal(t, []string{"[redacted]"}, map[string][]string(filtered)["authorization"])
}

func TestFilterHeadersSanitizesValues(t *testing.T) {
	// Non-sensitive header values are user-controlled and must have CR/LF removed
	// before logging to prevent log injection (forging of fake log entries).
	headers := http.Header{
		"X-Forwarded-For": []string{"1.2.3.4\r\nFATAL injected log line"},
		"X-Multi":         []string{"a\nb", "c\rd"},
	}

	filtered := filterHeaders(headers)

	require.Equal(t, []string{`1.2.3.4\r\nFATAL injected log line`}, filtered["X-Forwarded-For"])
	require.Equal(t, []string{`a\nb`, `c\rd`}, filtered["X-Multi"])
	// The original headers must not be mutated by filtering.
	require.Equal(t, []string{"1.2.3.4\r\nFATAL injected log line"}, headers["X-Forwarded-For"])
}
