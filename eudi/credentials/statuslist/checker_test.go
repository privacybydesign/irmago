package statuslist

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// makeSignerServerChecker builds a (signer, server, checker) triple
// where the server serves whatever the signer produces.
func makeSignerServerChecker(t *testing.T) (*TestStatusListSigner, *TestStatusListServer, *Checker) {
	t.Helper()
	signer := NewTestStatusListSigner(t)
	srv := NewTestStatusListServer(t, nil)
	checker := NewChecker(VerificationContext{X509Context: signer.X509VerificationContext()}, NewInMemoryCache())
	return signer, srv, checker
}

func Test_Checker_Check_1Bit_AllValid(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 0, 2: 0, 3: 0},
	})

	s, err := checker.Check(context.Background(), Reference{Index: 2, URI: srv.URL()})
	require.NoError(t, err)
	require.Equal(t, StatusValid, s)
}

func Test_Checker_Check_1Bit_Invalid(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{5: 1},
	})

	s, err := checker.Check(context.Background(), Reference{Index: 5, URI: srv.URL()})
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, s)
}

func Test_Checker_Check_2Bit_Suspended(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     2,
		Statuses: map[uint64]uint8{3: 2},
	})

	s, err := checker.Check(context.Background(), Reference{Index: 3, URI: srv.URL()})
	require.NoError(t, err)
	require.Equal(t, StatusSuspended, s)
}

func Test_Checker_Check_4Bit_ApplicationSpecific(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     4,
		Statuses: map[uint64]uint8{0: 7},
	})

	s, err := checker.Check(context.Background(), Reference{Index: 0, URI: srv.URL()})
	require.NoError(t, err)
	require.Equal(t, StatusApplicationSpecific, s)
}

// failingPutCache always errors on Put, simulating a transient cache-write
// failure (e.g. a locked/full DB). Get/Delete delegate to the wrapped cache.
type failingPutCache struct{ Cache }

func (failingPutCache) Put(string, []byte, time.Time) error {
	return fmt.Errorf("simulated cache write failure")
}

// A cache-write failure must NOT fail-closed: the token is already verified,
// so Check must still return the decoded status rather than an error.
func Test_Checker_Check_CacheWriteFailure_NotFatal(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	srv := NewTestStatusListServer(t, nil)
	checker := NewChecker(
		VerificationContext{X509Context: signer.X509VerificationContext()},
		failingPutCache{NewInMemoryCache()},
	)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{2: 0},
	})

	s, err := checker.Check(context.Background(), Reference{Index: 2, URI: srv.URL()})
	require.NoError(t, err)
	require.Equal(t, StatusValid, s)
}

func Test_Checker_Check_8Bit_FullRange(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     8,
		Statuses: map[uint64]uint8{0: 0, 1: 1, 2: 2, 3: 200},
	})

	for idx, want := range map[uint64]Status{0: StatusValid, 1: StatusInvalid, 2: StatusSuspended, 3: StatusApplicationSpecific} {
		s, err := checker.Check(context.Background(), Reference{Index: idx, URI: srv.URL()})
		require.NoError(t, err)
		require.Equalf(t, want, s, "idx %d", idx)
	}
}

func Test_Checker_Check_CachesAcrossCalls(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 3600,
	})

	for range 5 {
		_, err := checker.Check(context.Background(), Reference{Index: 0, URI: srv.URL()})
		require.NoError(t, err)
	}
	require.Equal(t, int64(1), srv.Hits(), "checker should hit backend once and cache subsequent reads")
}

func Test_Checker_Refresh_BypassesCache(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 3600,
	})

	_, err := checker.Check(context.Background(), Reference{Index: 0, URI: srv.URL()})
	require.NoError(t, err)
	require.Equal(t, int64(1), srv.Hits())

	_, err = checker.Refresh(context.Background(), Reference{Index: 0, URI: srv.URL()})
	require.NoError(t, err)
	require.Equal(t, int64(2), srv.Hits())
}

func Test_Checker_Check_Singleflight_CollapsesConcurrentFetches(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	var hits int64
	release := make(chan struct{})
	// body is assigned after the server exists so its `sub` can be set
	// to the server URL (the §5.1 sub == uri binding). The handler
	// closure reads body only at request time, after assignment.
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		<-release // hold the request open while concurrent callers pile up
		w.Header().Set("Content-Type", StatusListTokenContentType)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	body = signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  srv.URL,
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	checker := NewChecker(VerificationContext{X509Context: signer.X509VerificationContext()}, NewInMemoryCache())

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			_, err := checker.Check(context.Background(), Reference{URI: srv.URL})
			require.NoError(t, err)
		}()
	}

	// Let the held request complete.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	require.Equal(t, int64(1), atomic.LoadInt64(&hits), "singleflight should fold concurrent callers into one fetch")
}

func Test_Checker_Check_FetchFailure_FailsClosed(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	checker := NewChecker(VerificationContext{X509Context: signer.X509VerificationContext()}, NewInMemoryCache())

	_, err := checker.Check(context.Background(), Reference{URI: "http://127.0.0.1:0/nope"})
	require.ErrorIs(t, err, ErrFetch)
}

func Test_Checker_Check_DelegatedIssuer_Accepted(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:   "https://delegated-status-issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	// sub matches the fetch URI and the signature is trusted; the iss
	// differs from the credential issuer but is accepted because the spec
	// binds the token via sub + signature (§11.3).
	s, err := checker.Check(context.Background(), Reference{URI: srv.URL()})
	require.NoError(t, err)
	require.Equal(t, StatusValid, s)
}

func Test_Checker_Check_SubMismatch_FailsClosed(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	// Sign with a sub that is NOT this server's URL. The token is
	// otherwise valid (correct iss, signature), but the sub != uri
	// binding must reject it (§5.1 / §8.3).
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  "https://issuer.example/some-other-list",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	}))

	_, err := checker.Check(context.Background(), Reference{URI: srv.URL()})
	require.ErrorIs(t, err, ErrUnauthorized)
	require.Contains(t, err.Error(), "sub")
}

func Test_Checker_Check_IndexOutOfBounds_FailsClosed(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 0, 2: 0},
	})

	// Status array has 3 entries (= 1 byte at 1 bit each = 8 entries
	// total). idx 999 must be rejected.
	_, err := checker.Check(context.Background(), Reference{Index: 999, URI: srv.URL()})
	require.ErrorIs(t, err, ErrIndexBounds)
}

func Test_Checker_Check_TTLClampedToMinimum(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 1, // below TTLMin (60s)
	})

	_, err := checker.Check(context.Background(), Reference{URI: srv.URL()})
	require.NoError(t, err)
	_, expires, ok := checker.cache.Get(srv.URL())
	require.True(t, ok)
	now := checker.nowFn()
	require.GreaterOrEqual(t, expires.Sub(now), TTLMin-time.Second)
}

func Test_Checker_Check_TTLClampedToMaximum(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 7 * 24 * 3600, // above TTLMax (24h)
	})

	_, err := checker.Check(context.Background(), Reference{URI: srv.URL()})
	require.NoError(t, err)
	_, expires, ok := checker.cache.Get(srv.URL())
	require.True(t, ok)
	now := checker.nowFn()
	require.LessOrEqual(t, expires.Sub(now), TTLMax+time.Second)
}

func Test_Checker_Check_PrioritizesJwtTtlOverHttpMaxAge(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetMaxAge(120)
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 3600,
	})

	before := checker.nowFn()
	_, err := checker.Check(context.Background(), Reference{URI: srv.URL()})
	require.NoError(t, err)
	_, expires, ok := checker.cache.Get(srv.URL())
	require.True(t, ok)
	// §8.2: the JWT ttl (3600 s) takes priority over the HTTP max-age
	// (120 s), so the effective TTL is ~3600 s, not 120 s.
	require.InDelta(t, 3600*time.Second, expires.Sub(before), float64(5*time.Second))
}

func Test_Checker_Check_FallsBackToHttpMaxAgeWhenNoJwtTtl(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetMaxAge(300)
	// No ttl and no exp on the token → the HTTP max-age is the only
	// caching signal and is used as the fallback.
	srv.Serve(t, signer, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	before := checker.nowFn()
	_, err := checker.Check(context.Background(), Reference{URI: srv.URL()})
	require.NoError(t, err)
	_, expires, ok := checker.cache.Get(srv.URL())
	require.True(t, ok)
	require.InDelta(t, 300*time.Second, expires.Sub(before), float64(5*time.Second))
}

func Test_Checker_Check_EmptyURI_FailsClosed(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	checker := NewChecker(VerificationContext{X509Context: signer.X509VerificationContext()}, NewInMemoryCache())
	_, err := checker.Check(context.Background(), Reference{Index: 0})
	require.ErrorIs(t, err, ErrUnauthorized)
}
