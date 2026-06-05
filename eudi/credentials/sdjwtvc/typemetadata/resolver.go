package typemetadata

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// DefaultMaxExtendsDepth caps the extends chain length to prevent runaway
// fetching. The number is a safety stop; real chains are typically very short.
const DefaultMaxExtendsDepth = 10

// SupportedIntegrityAlgorithm is the only integrity hash algorithm currently
// supported. The wallet rejects credentials whose vct#integrity (or chain
// extends#integrity) declares any other algorithm — see verifyIntegrity.
const SupportedIntegrityAlgorithm = "sha256"

// Resolver resolves an SD-JWT VC type-metadata document by following the
// extends chain, caching both raw bytes (for post-issuance integrity
// verification) and the parsed VctTypeMetadata for each URL visited.
//
// A Resolver is intended for use within a single OID4VCI session — the cache
// is not shared across sessions or instances.
type Resolver struct {
	client   *http.Client
	maxDepth int
	mu       sync.Mutex
	cache    map[string]cachedDoc
}

type cachedDoc struct {
	rawBytes []byte
	parsed   *VctTypeMetadata
}

// NewResolver returns a Resolver that fetches over the given http.Client. Pass
// nil to use a fresh client with the package default timeout.
func NewResolver(client *http.Client) *Resolver {
	if client == nil {
		client = &http.Client{Timeout: defaultRequestTimeout}
	}
	return &Resolver{
		client:   client,
		maxDepth: DefaultMaxExtendsDepth,
		cache:    make(map[string]cachedDoc),
	}
}

// Resolve fetches the VCT type-metadata document at vctURL and walks its
// extends chain. Returns the resolved view: parent fields are inherited by
// the child unless overridden. The returned document's Extends/ExtendsIntegrity
// fields are zeroed to reflect that the chain has been collapsed.
//
// vctURL must use https://; http:// is accepted only when devMode is true.
// Returns an error on: scheme rejection, fetch failure, parse failure,
// extends-chain depth overflow, extends-chain cycle, or extends#integrity
// mismatch.
//
// The cache (raw bytes + parsed) is populated for every URL visited. Use
// RawDocument to retrieve the raw bytes later (e.g. for post-issuance
// integrity verification against the issued JWT's vct#integrity claim).
func (r *Resolver) Resolve(ctx context.Context, vctURL string, devMode bool) (*VctTypeMetadata, error) {
	visited := make(map[string]struct{})
	chain, err := r.collectChain(ctx, vctURL, "", devMode, visited, 0)
	if err != nil {
		return nil, err
	}
	return mergeChain(chain), nil
}

// RawDocument returns the raw bytes of a VCT type-metadata document previously
// fetched by this Resolver. The second return is false if the URL was not
// fetched (or fetching failed).
func (r *Resolver) RawDocument(vctURL string) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cached, ok := r.cache[vctURL]
	if !ok {
		return nil, false
	}
	return cached.rawBytes, true
}

// collectChain walks the extends chain depth-first starting at currentURL.
// Returns the chain ordered from root (most ancestral) to leaf (currentURL).
// expectedIntegrity, if non-empty, is the integrity hash that the document at
// currentURL must match — supplied by the child's extends#integrity.
func (r *Resolver) collectChain(
	ctx context.Context,
	currentURL string,
	expectedIntegrity string,
	devMode bool,
	visited map[string]struct{},
	depth int,
) ([]*VctTypeMetadata, error) {
	if depth >= r.maxDepth {
		return nil, fmt.Errorf("extends chain exceeded maximum depth %d", r.maxDepth)
	}
	if _, seen := visited[currentURL]; seen {
		return nil, fmt.Errorf("extends chain cycle detected at %q", currentURL)
	}
	visited[currentURL] = struct{}{}

	if err := validateURL(currentURL, devMode); err != nil {
		return nil, err
	}

	r.mu.Lock()
	cached, ok := r.cache[currentURL]
	r.mu.Unlock()
	if !ok {
		body, err := getJSON(ctx, r.client, currentURL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch %q: %w", currentURL, err)
		}
		parsed, err := ParseVctTypeMetadata(body)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %q: %w", currentURL, err)
		}
		cached = cachedDoc{rawBytes: body, parsed: parsed}
		r.mu.Lock()
		r.cache[currentURL] = cached
		r.mu.Unlock()
	}

	if expectedIntegrity != "" {
		if err := verifyIntegrity(cached.rawBytes, expectedIntegrity); err != nil {
			return nil, fmt.Errorf("integrity check failed for %q: %w", currentURL, err)
		}
	}

	chain := []*VctTypeMetadata{cached.parsed}
	if cached.parsed.Extends != "" {
		parentChain, err := r.collectChain(ctx, cached.parsed.Extends, cached.parsed.ExtendsIntegrity, devMode, visited, depth+1)
		if err != nil {
			return nil, err
		}
		chain = append(parentChain, chain...) // root-first order
	}
	return chain, nil
}

// mergeChain folds an ordered (root → leaf) chain into a single document
// where the leaf's non-empty fields override its parents'. Per-array fields
// (Display, Claims) are full-replaced if the child has them set — partial
// merging within arrays is intentionally not supported.
func mergeChain(chain []*VctTypeMetadata) *VctTypeMetadata {
	out := &VctTypeMetadata{}
	for _, doc := range chain {
		if doc.Name != "" {
			out.Name = doc.Name
		}
		if doc.IssuerURL != "" {
			out.IssuerURL = doc.IssuerURL
		}
		if len(doc.Display) > 0 {
			out.Display = doc.Display
		}
		if len(doc.Claims) > 0 {
			out.Claims = doc.Claims
		}
	}
	return out
}

// validateURL accepts https:// always and http:// only when devMode is true.
// Other schemes (data:, file:, did:, etc.) and non-absolute strings are
// rejected.
func validateURL(rawURL string, devMode bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("vct URL %q is malformed: %w", rawURL, err)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !devMode {
			return fmt.Errorf("vct URL %q uses http; only https is allowed outside developer mode", rawURL)
		}
	case "":
		return fmt.Errorf("vct URL %q has no scheme", rawURL)
	default:
		return fmt.Errorf("vct URL %q uses unsupported scheme %q", rawURL, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("vct URL %q has no host", rawURL)
	}
	return nil
}

// VerifyIntegrity hashes body and compares it to the provided integrity
// string (format: "<algo>-<base64>"). Only sha256 is supported; any other
// algorithm prefix returns an error so the caller can refuse the credential.
func VerifyIntegrity(body []byte, integrity string) error {
	return verifyIntegrity(body, integrity)
}

func verifyIntegrity(body []byte, integrity string) error {
	algo, encoded, ok := strings.Cut(integrity, "-")
	if !ok {
		return fmt.Errorf("integrity %q is not in <algo>-<base64> form", integrity)
	}
	if algo != SupportedIntegrityAlgorithm {
		return fmt.Errorf("unsupported integrity algorithm %q (only %q is supported)", algo, SupportedIntegrityAlgorithm)
	}
	expected, err := decodeIntegrityHash(encoded)
	if err != nil {
		return fmt.Errorf("failed to base64-decode integrity hash: %w", err)
	}
	actual := sha256.Sum256(body)
	if !bytes.Equal(expected, actual[:]) {
		return fmt.Errorf("integrity hash mismatch")
	}
	return nil
}

// decodeIntegrityHash decodes a base64 hash string accepting both padded
// and unpadded variants, in std and url-safe alphabets. SRI mandates
// padded base64, but the OpenID4VCI / SD-JWT VC drafts are silent and
// producers in the wild emit either form.
func decodeIntegrityHash(encoded string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		decoded, err := enc.DecodeString(encoded)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
