package walletconfig

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFetch_ReturnsTheBody(t *testing.T) {
	server := NewTestServer(t)
	server.SetBody([]byte("signed config"))

	body, err := Fetch(context.Background(), nil, server.URL)
	require.NoError(t, err)
	require.Equal(t, []byte("signed config"), body)
	require.Equal(t, 1, server.Hits())
}

func TestFetch_RejectsANon2xxResponse(t *testing.T) {
	server := NewTestServer(t)
	for _, status := range []int{http.StatusNotFound, http.StatusInternalServerError, http.StatusMovedPermanently} {
		server.SetStatus(status)
		_, err := Fetch(context.Background(), server.Client(), server.URL)
		require.ErrorContains(t, err, "non-2xx", "status %d", status)
	}
}

func TestFetch_RejectsABodyOverTheCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, MaxDocumentBytes+1))
	}))
	t.Cleanup(server.Close)

	_, err := Fetch(context.Background(), server.Client(), server.URL)
	require.ErrorContains(t, err, "exceeds cap")
}

func TestFetch_AcceptsABodyAtTheCap(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, MaxDocumentBytes))
	}))
	t.Cleanup(server.Close)

	body, err := Fetch(context.Background(), server.Client(), server.URL)
	require.NoError(t, err)
	require.Len(t, body, int(MaxDocumentBytes))
}

func TestFetch_HonoursCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()
	_, err := Fetch(ctx, server.Client(), server.URL)
	require.ErrorIs(t, err, context.Canceled)
}

func TestFetch_RejectsAnUnusableURL(t *testing.T) {
	_, err := Fetch(context.Background(), nil, "://not a url")
	require.ErrorContains(t, err, "build request")
}
