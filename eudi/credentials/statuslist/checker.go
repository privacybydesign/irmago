package statuslist

import (
	"context"
	"fmt"
	"time"

	"github.com/privacybydesign/irmago/internal/common"
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
func (c *Checker) Check(ctx context.Context, ref Reference) (Status, error) {
	return c.check(ctx, ref, false)
}

// Refresh ignores any cached entry and re-fetches the list. Used by
// the background sweep to bring stored credential statuses up to
// date independent of the Check-side TTL.
func (c *Checker) Refresh(ctx context.Context, ref Reference) (Status, error) {
	return c.check(ctx, ref, true)
}

func (c *Checker) check(ctx context.Context, ref Reference, bypassCache bool) (Status, error) {
	if ref.URI == "" {
		return StatusUnknown, fmt.Errorf("%w: empty URI", ErrUnauthorized)
	}

	now := c.nowFn()

	// Cache and singleflight are keyed on ref.URI alone; the verified list
	// content does not depend on the caller.

	// Cache fast-path.
	if !bypassCache {
		if raw, expires, ok := c.cache.Get(ref.URI); ok && now.Before(expires) {
			return c.verifyAndDecode(raw, ref, now)
		}
	}

	// Singleflight: collapse concurrent fetches for the same URI.
	resAny, err, _ := c.sf.Do(ref.URI, func() (any, error) {
		return c.fetchVerifyStore(ctx, ref.URI, now)
	})
	if err != nil {
		return StatusUnknown, err
	}
	v := resAny.(*verifiedStatusList)

	return decodeStatusFromVerified(v, ref, c.ctx.MaxBodyBytes)
}

// fetchVerifyStore runs one fetch+verify cycle and writes the raw
// JWT into the cache with the computed expiry.
func (c *Checker) fetchVerifyStore(ctx context.Context, uri string, now time.Time) (*verifiedStatusList, error) {
	res, err := fetchStatusListToken(ctx, c.ctx, uri)
	if err != nil {
		return nil, err
	}

	v, err := verifyStatusListToken(res.rawJwt, c.ctx, uri, now)
	if err != nil {
		return nil, err
	}

	// Caching lifetime. draft-ietf-oauth-status-list-15 §8.2 requires
	// the token's own ttl/exp claims to take priority over HTTP caching
	// headers, so the HTTP max-age is only a fallback used when the
	// token advertises no lifetime of its own. ClampTTL bounds the
	// result and supplies the default when neither signal is present.
	ttl, ok := v.payloadTTLSignal()
	if !ok {
		ttl = res.httpMaxAge
	}
	expires := now.Add(ClampTTL(ttl))

	if err := c.cache.Put(uri, res.rawJwt, expires); err != nil {
		// Cache failures aren't fatal — the token is already verified.
		// Log and proceed rather than fail-closed on a transient cache
		// error (e.g. a locked/full DB), which would otherwise reject an
		// otherwise-valid credential at issuance and disclosure.
		if common.Logger != nil { // nil when this package is used without irma (e.g. unit tests)
			common.Logger.Warnf("statuslist: cache write for %q failed, proceeding: %v", common.SanitizeForLog(uri), err)
		}
	}
	return v, nil
}

// verifyAndDecode runs the verify+decode path against an already
// cached raw JWT.
func (c *Checker) verifyAndDecode(raw []byte, ref Reference, now time.Time) (Status, error) {
	v, err := verifyStatusListToken(raw, c.ctx, ref.URI, now)
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
