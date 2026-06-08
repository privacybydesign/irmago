package statuslist

import (
	"context"
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
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 0, 2: 0, 3: 0},
	}))

	s, err := checker.Check(context.Background(), Reference{Index: 2, URI: srv.URL()}, "https://issuer.example")
	require.NoError(t, err)
	require.Equal(t, StatusValid, s)
}

func Test_Checker_Check_1Bit_Invalid(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{5: 1},
	}))

	s, err := checker.Check(context.Background(), Reference{Index: 5, URI: srv.URL()}, "https://issuer.example")
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, s)
}

func Test_Checker_Check_2Bit_Suspended(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     2,
		Statuses: map[uint64]uint8{3: 2},
	}))

	s, err := checker.Check(context.Background(), Reference{Index: 3, URI: srv.URL()}, "https://issuer.example")
	require.NoError(t, err)
	require.Equal(t, StatusSuspended, s)
}

func Test_Checker_Check_4Bit_ApplicationSpecific(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     4,
		Statuses: map[uint64]uint8{0: 7},
	}))

	s, err := checker.Check(context.Background(), Reference{Index: 0, URI: srv.URL()}, "https://issuer.example")
	require.NoError(t, err)
	require.Equal(t, StatusApplicationSpecific, s)
}

func Test_Checker_Check_8Bit_FullRange(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     8,
		Statuses: map[uint64]uint8{0: 0, 1: 1, 2: 2, 3: 200},
	}))

	for idx, want := range map[uint64]Status{0: StatusValid, 1: StatusInvalid, 2: StatusSuspended, 3: StatusApplicationSpecific} {
		s, err := checker.Check(context.Background(), Reference{Index: idx, URI: srv.URL()}, "https://issuer.example")
		require.NoError(t, err)
		require.Equalf(t, want, s, "idx %d", idx)
	}
}

func Test_Checker_Check_CachesAcrossCalls(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 3600,
	}))

	for range 5 {
		_, err := checker.Check(context.Background(), Reference{Index: 0, URI: srv.URL()}, "https://issuer.example")
		require.NoError(t, err)
	}
	require.Equal(t, int64(1), srv.Hits(), "checker should hit backend once and cache subsequent reads")
}

func Test_Checker_Refresh_BypassesCache(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 3600,
	}))

	_, err := checker.Check(context.Background(), Reference{Index: 0, URI: srv.URL()}, "https://issuer.example")
	require.NoError(t, err)
	require.Equal(t, int64(1), srv.Hits())

	_, err = checker.Refresh(context.Background(), Reference{Index: 0, URI: srv.URL()}, "https://issuer.example")
	require.NoError(t, err)
	require.Equal(t, int64(2), srv.Hits())
}

func Test_Checker_Check_Singleflight_CollapsesConcurrentFetches(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})
	var hits int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		<-release // hold the request open while concurrent callers pile up
		w.Header().Set("Content-Type", StatusListTokenContentType)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	checker := NewChecker(VerificationContext{X509Context: signer.X509VerificationContext()}, NewInMemoryCache())

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			_, err := checker.Check(context.Background(), Reference{URI: srv.URL}, "https://issuer.example")
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

	_, err := checker.Check(context.Background(), Reference{URI: "http://127.0.0.1:0/nope"}, "https://issuer.example")
	require.ErrorIs(t, err, ErrFetch)
}

func Test_Checker_Check_IssMismatch_FailsClosed(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://attacker.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	}))

	_, err := checker.Check(context.Background(), Reference{URI: srv.URL()}, "https://issuer.example")
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_Checker_Check_IndexOutOfBounds_FailsClosed(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 0, 2: 0},
	}))

	// Status array has 3 entries (= 1 byte at 1 bit each = 8 entries
	// total). idx 999 must be rejected.
	_, err := checker.Check(context.Background(), Reference{Index: 999, URI: srv.URL()}, "https://issuer.example")
	require.ErrorIs(t, err, ErrIndexBounds)
}

func Test_Checker_Check_TTLClampedToMinimum(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 1, // below TTLMin (60s)
	}))

	_, err := checker.Check(context.Background(), Reference{URI: srv.URL()}, "https://issuer.example")
	require.NoError(t, err)
	_, expires, ok := checker.cache.Get(srv.URL())
	require.True(t, ok)
	now := checker.nowFn()
	require.GreaterOrEqual(t, expires.Sub(now), TTLMin-time.Second)
}

func Test_Checker_Check_TTLClampedToMaximum(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 7 * 24 * 3600, // above TTLMax (24h)
	}))

	_, err := checker.Check(context.Background(), Reference{URI: srv.URL()}, "https://issuer.example")
	require.NoError(t, err)
	_, expires, ok := checker.cache.Get(srv.URL())
	require.True(t, ok)
	now := checker.nowFn()
	require.LessOrEqual(t, expires.Sub(now), TTLMax+time.Second)
}

func Test_Checker_Check_TakesMinOfHttpMaxAgeAndJwtTtl(t *testing.T) {
	signer, srv, checker := makeSignerServerChecker(t)
	srv.SetMaxAge(120)
	srv.SetBody(signer.SignToken(t, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 3600,
	}))

	before := checker.nowFn()
	_, err := checker.Check(context.Background(), Reference{URI: srv.URL()}, "https://issuer.example")
	require.NoError(t, err)
	_, expires, ok := checker.cache.Get(srv.URL())
	require.True(t, ok)
	// Effective TTL should be close to 120 s (the http max-age), not 3600 (the jwt ttl).
	require.InDelta(t, 120*time.Second, expires.Sub(before), float64(5*time.Second))
}

func Test_Checker_Check_EmptyURI_FailsClosed(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	checker := NewChecker(VerificationContext{X509Context: signer.X509VerificationContext()}, NewInMemoryCache())
	_, err := checker.Check(context.Background(), Reference{Index: 0}, "https://issuer.example")
	require.ErrorIs(t, err, ErrUnauthorized)
}
