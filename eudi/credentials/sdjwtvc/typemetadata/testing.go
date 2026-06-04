package typemetadata

// PrimeCacheForTesting inserts a raw document into the resolver's cache without
// performing a fetch. Tests that exercise post-issuance flows (e.g. integrity
// verification) need a cache populated against arbitrary URLs without
// standing up an HTTP server per URL. Production code paths must not call
// this — Resolver.Resolve is the only legitimate way to populate the cache.
func PrimeCacheForTesting(r *Resolver, url string, rawBytes []byte) {
	parsed, err := ParseVctTypeMetadata(rawBytes)
	if err != nil {
		// In tests, malformed input is a test bug. Store an empty parsed view
		// so the cache still contains an entry; callers asserting via
		// RawDocument will see the raw bytes regardless.
		parsed = &VctTypeMetadata{}
	}
	r.cache[url] = cachedDoc{rawBytes: rawBytes, parsed: parsed}
}
