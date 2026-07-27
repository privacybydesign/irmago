package statuslist

import (
	"sync"
	"time"
)

// Cache stores fetched Status List Tokens by URI. The interface
// intentionally exchanges raw JWT bytes (not decoded bit arrays) so
// that re-verification on read happens against the current trust
// anchors instead of trusting a decoded payload from an earlier run.
type Cache interface {
	// Get returns the cached raw JWT for uri together with its
	// scheduled expiry. ok is false when the URI is not cached.
	Get(uri string) (rawJwt []byte, expiresAt time.Time, ok bool)

	// Put stores the raw JWT under uri with the given expiry.
	Put(uri string, rawJwt []byte, expiresAt time.Time) error

	// Delete removes any cached entry for uri.
	Delete(uri string) error
}

// TTL bounds applied to the lifetime signal (the token's own ttl/exp, or the
// HTTP max-age as fallback) to defend against pathological providers (ttl=1s
// would hammer us; ttl=10y would make revocation effectively impossible).
const (
	TTLMin              = 60 * time.Second
	TTLMax              = 24 * time.Hour
	TTLDefault          = 1 * time.Hour
	MaxBodyDefault      = 5 * 1024 * 1024
	FetchTimeoutDefault = 10 * time.Second
)

// ClampTTL applies the [TTLMin, TTLMax] bounds. A non-positive input
// (no signal from the provider) is treated as TTLDefault before
// clamping.
func ClampTTL(d time.Duration) time.Duration {
	if d <= 0 {
		d = TTLDefault
	}
	if d < TTLMin {
		return TTLMin
	}
	if d > TTLMax {
		return TTLMax
	}
	return d
}

// inMemoryCache is the default in-process Cache used by relying-party
// verifiers (long-lived processes that don't need persistence). The
// wallet wires the DB-backed implementation from eudi/storage/db.
type inMemoryCache struct {
	mu      sync.RWMutex
	entries map[string]inMemoryEntry
}

type inMemoryEntry struct {
	rawJwt    []byte
	expiresAt time.Time
}

// NewInMemoryCache returns a Cache backed by an in-process map. Safe
// for concurrent use.
func NewInMemoryCache() Cache {
	return &inMemoryCache{entries: map[string]inMemoryEntry{}}
}

func (c *inMemoryCache) Get(uri string) ([]byte, time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[uri]
	if !ok {
		return nil, time.Time{}, false
	}
	return e.rawJwt, e.expiresAt, true
}

func (c *inMemoryCache) Put(uri string, rawJwt []byte, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[uri] = inMemoryEntry{rawJwt: rawJwt, expiresAt: expiresAt}
	return nil
}

func (c *inMemoryCache) Delete(uri string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, uri)
	return nil
}
