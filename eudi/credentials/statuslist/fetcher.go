package statuslist

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// fetchResult bundles the raw token bytes (JWT or CWT) returned by the status
// provider with the HTTP-side TTL signal (Cache-Control: max-age).
type fetchResult struct {
	rawToken   []byte
	httpMaxAge time.Duration // 0 if response had no max-age directive
}

// fetchStatusListToken performs an HTTP GET against uri, enforcing
// the spec's Accept/Content-Type contract and the configured body
// size cap. The returned bytes are the unparsed signed token.
//
// Callers are expected to wrap this in singleflight at the URI level
// to dedupe concurrent fetches; the Checker does so.
func fetchStatusListToken(ctx context.Context, vc VerificationContext, uri string) (*fetchResult, error) {
	httpClient := vc.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	timeout := vc.FetchTimeout
	if timeout <= 0 {
		timeout = FetchTimeoutDefault
	}
	maxBody := vc.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = MaxBodyDefault
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrFetch, err)
	}
	// Both Status List Token encodings are supported (see verifyStatusList);
	// let the provider pick whichever it publishes.
	req.Header.Set("Accept", StatusListTokenJWTContentType+", "+StatusListTokenCWTContentType)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w: non-2xx response: %s", ErrFetch, resp.Status)
	}

	ct := resp.Header.Get("Content-Type")
	// Accept either supported media type, with or without parameters like
	// "; charset=...". Reject anything else (RFC §8.2). Which encoding was
	// actually returned is decided later, from the bytes themselves (see
	// looksLikeCWT) — the cache stores only bytes, so a cache-read has no
	// Content-Type to consult either, and this check exists to reject an
	// unexpected response body (an HTML error page, say) early.
	lct := strings.ToLower(ct)
	if !strings.HasPrefix(lct, StatusListTokenJWTContentType) && !strings.HasPrefix(lct, StatusListTokenCWTContentType) {
		return nil, fmt.Errorf(
			"%w: unexpected Content-Type %q: only %s or %s is supported",
			ErrFetch, ct, StatusListTokenJWTContentType, StatusListTokenCWTContentType,
		)
	}

	limited := io.LimitReader(resp.Body, maxBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrFetch, err)
	}
	if int64(len(body)) > maxBody {
		return nil, fmt.Errorf("%w: response body exceeds cap (%d bytes)", ErrFetch, maxBody)
	}

	return &fetchResult{
		rawToken:   body,
		httpMaxAge: parseMaxAge(resp.Header.Get("Cache-Control")),
	}, nil
}

// parseMaxAge picks the max-age=N directive out of a Cache-Control
// header. Returns 0 if the directive is absent or unparseable.
func parseMaxAge(cc string) time.Duration {
	if cc == "" {
		return 0
	}
	for part := range strings.SplitSeq(cc, ",") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(strings.ToLower(part), "max-age=") {
			continue
		}
		v := strings.TrimSpace(part[len("max-age="):])
		secs, err := strconv.ParseInt(v, 10, 64)
		if err != nil || secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	return 0
}
