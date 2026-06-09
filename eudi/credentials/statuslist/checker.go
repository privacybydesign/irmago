package statuslist

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/singleflight"
)

// Checker is the only public verb of this package. It orchestrates
// cache lookup, HTTP fetch, JWT signature verification, and bit
// extraction for a single status reference, with singleflight dedup
// across concurrent callers requesting the same URI.
//
// A Checker is safe for concurrent use.
type Checker struct {
	ctx   VerificationContext
	cache Cache
	sf    singleflight.Group

	// nowFn lets tests inject a deterministic clock without touching
	// VerificationContext.Clock (which jwx consumes for skew checks).
	nowFn func() time.Time
}

// NewChecker returns a Checker bound to a verification context and
// a cache. If cache is nil an in-memory cache is used.
func NewChecker(ctx VerificationContext, cache Cache) *Checker {
	if cache == nil {
		cache = NewInMemoryCache()
	}
	return &Checker{ctx: ctx, cache: cache, nowFn: time.Now}
}

// Check fetches/verifies the status list for ref (using the cache
// when fresh) and returns the status at ref.Index.
//
// expectedIss MUST equal the iss claim of the Status List Token,
// which by trust-model rule equals the iss of the credential being
// checked.
func (c *Checker) Check(ctx context.Context, ref Reference, expectedIss string) (Status, error) {
	return c.check(ctx, ref, expectedIss, false)
}

// Refresh ignores any cached entry and re-fetches the list. Used by
// the background sweep to bring stored credential statuses up to
// date independent of the Check-side TTL.
func (c *Checker) Refresh(ctx context.Context, ref Reference, expectedIss string) (Status, error) {
	return c.check(ctx, ref, expectedIss, true)
}

func (c *Checker) check(ctx context.Context, ref Reference, expectedIss string, bypassCache bool) (Status, error) {
	if ref.URI == "" {
		return StatusUnknown, fmt.Errorf("%w: empty URI", ErrUnauthorized)
	}

	now := c.nowFn()

	// Cache fast-path.
	if !bypassCache {
		if raw, expires, ok := c.cache.Get(ref.URI); ok && now.Before(expires) {
			return c.verifyAndDecode(raw, ref, expectedIss, now)
		}
	}

	// Singleflight: collapse concurrent fetches for the same URI.
	resAny, err, _ := c.sf.Do(ref.URI, func() (any, error) {
		return c.fetchVerifyStore(ctx, ref.URI, expectedIss, now)
	})
	if err != nil {
		return StatusUnknown, err
	}
	v := resAny.(*verifiedStatusList)

	return decodeStatusFromVerified(v, ref, c.ctx.MaxBodyBytes)
}

// fetchVerifyStore runs one fetch+verify cycle and writes the raw
// JWT into the cache with the computed expiry.
func (c *Checker) fetchVerifyStore(ctx context.Context, uri, expectedIss string, now time.Time) (*verifiedStatusList, error) {
	res, err := fetchStatusListToken(ctx, c.ctx, uri)
	if err != nil {
		return nil, err
	}

	v, err := verifyStatusListToken(res.rawJwt, c.ctx, expectedIss, now)
	if err != nil {
		return nil, err
	}

	// TTL = min(http max-age, jwt ttl/exp) before clamping. If only
	// one signal is present, ClampTTL handles the missing-signal case.
	httpSig := res.httpMaxAge
	jwtSig := v.ttlFromPayload()
	ttl := minTTL(httpSig, jwtSig)
	expires := now.Add(ClampTTL(ttl))

	if err := c.cache.Put(uri, res.rawJwt, expires); err != nil {
		// Cache failures aren't fatal — log via err wrap but proceed.
		return nil, fmt.Errorf("%w: cache write: %v", ErrFetch, err)
	}
	return v, nil
}

// verifyAndDecode runs the verify+decode path against an already
// cached raw JWT.
func (c *Checker) verifyAndDecode(raw []byte, ref Reference, expectedIss string, now time.Time) (Status, error) {
	v, err := verifyStatusListToken(raw, c.ctx, expectedIss, now)
	if err != nil {
		// Cached value failed re-verification — drop it so the
		// next call re-fetches.
		_ = c.cache.Delete(ref.URI)
		return StatusUnknown, err
	}
	return decodeStatusFromVerified(v, ref, c.ctx.MaxBodyBytes)
}

func decodeStatusFromVerified(v *verifiedStatusList, ref Reference, maxBytes int64) (Status, error) {
	bits, err := decodeBits(v.payload.StatusList.Lst, maxBytes)
	if err != nil {
		return StatusUnknown, err
	}
	return statusAtIndex(bits, v.payload.StatusList.Bits, ref.Index)
}

// minTTL returns the smaller of two positive durations; if one is
// non-positive (no signal), the other wins.
func minTTL(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}
