package statuslist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_FetchStatusListToken_SendsAcceptHeader(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", StatusListTokenContentType)
		_, _ = w.Write([]byte("body"))
	}))
	defer srv.Close()

	_, err := fetchStatusListToken(context.Background(), VerificationContext{}, srv.URL)
	require.NoError(t, err)
	require.Equal(t, StatusListTokenContentType, gotAccept)
}

func Test_FetchStatusListToken_ReadsBodyAndCacheControl(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", StatusListTokenContentType)
		w.Header().Set("Cache-Control", "max-age=300, public")
		_, _ = w.Write([]byte("body-bytes"))
	}))
	defer srv.Close()

	res, err := fetchStatusListToken(context.Background(), VerificationContext{}, srv.URL)
	require.NoError(t, err)
	require.Equal(t, []byte("body-bytes"), res.rawJwt)
	require.Equal(t, 300*time.Second, res.httpMaxAge)
}

func Test_FetchStatusListToken_RejectsWrongContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, err := fetchStatusListToken(context.Background(), VerificationContext{}, srv.URL)
	require.ErrorIs(t, err, ErrFetch)
	require.Contains(t, err.Error(), "Content-Type")
}

func Test_FetchStatusListToken_AcceptsContentTypeWithParameters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", StatusListTokenContentType+"; charset=utf-8")
		_, _ = w.Write([]byte("body"))
	}))
	defer srv.Close()

	_, err := fetchStatusListToken(context.Background(), VerificationContext{}, srv.URL)
	require.NoError(t, err)
}

func Test_FetchStatusListToken_RejectsNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", StatusListTokenContentType)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := fetchStatusListToken(context.Background(), VerificationContext{}, srv.URL)
	require.ErrorIs(t, err, ErrFetch)
}

func Test_FetchStatusListToken_BodySizeCap_ReturnsErrFetch(t *testing.T) {
	big := strings.Repeat("X", 10000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", StatusListTokenContentType)
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()

	_, err := fetchStatusListToken(context.Background(), VerificationContext{MaxBodyBytes: 100}, srv.URL)
	require.ErrorIs(t, err, ErrFetch)
	require.Contains(t, err.Error(), "exceeds cap")
}

func Test_FetchStatusListToken_TimeoutHonoured(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.Header().Set("Content-Type", StatusListTokenContentType)
		_, _ = w.Write([]byte("late"))
	}))
	defer srv.Close()
	defer close(release)

	_, err := fetchStatusListToken(context.Background(), VerificationContext{FetchTimeout: 50 * time.Millisecond}, srv.URL)
	require.ErrorIs(t, err, ErrFetch)
}

func Test_FetchStatusListToken_ConcurrentFetches_AllSucceed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", StatusListTokenContentType)
		_, _ = w.Write([]byte("body"))
	}))
	defer srv.Close()

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			_, err := fetchStatusListToken(context.Background(), VerificationContext{}, srv.URL)
			require.NoError(t, err)
		}()
	}
	wg.Wait()
}

func Test_ParseMaxAge_Variants(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"max-age=60", 60 * time.Second},
		{"public, max-age=120", 120 * time.Second},
		{"  Max-Age=30  ", 30 * time.Second}, // case-insensitive
		{"", 0},
		{"no-store", 0},
		{"max-age=-1", 0}, // negative is invalid → ignored
		{"max-age=notanumber", 0},
	}
	for _, c := range cases {
		require.Equalf(t, c.want, parseMaxAge(c.in), "input %q", c.in)
	}
}
