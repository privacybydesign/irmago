package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/privacybydesign/irmago"
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
		require.Equal(t, 120, res.Base().ResultJwtValidity)
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
				_, err := ioutil.ReadAll(r.Body)
				// check that reading has halted with an error just after the deadline
				require.Error(t, err)
				require.Greater(t, int64(timeout+50*time.Millisecond), int64(time.Now().Sub(start)))
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

			// check that request was aborted after the timeout and before the handler finished
			require.Greater(t, int64(timeout+50*time.Millisecond), int64(time.Now().Sub(start)))
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
