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

// fetchResult bundles the raw JWT bytes returned by the status
// provider with the HTTP-side TTL signal (Cache-Control: max-age).
type fetchResult struct {
	rawJwt     []byte
	httpMaxAge time.Duration // 0 if response had no max-age directive
}

// fetchStatusListToken performs an HTTP GET against uri, enforcing
// the spec's Accept/Content-Type contract and the configured body
// size cap. The returned bytes are the unparsed signed JWT.
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
	req.Header.Set("Accept", StatusListTokenContentType)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w: non-2xx response: %s", ErrFetch, resp.Status)
	}

	ct := resp.Header.Get("Content-Type")
	// Accept "application/statuslist+jwt" with or without parameters
	// like "; charset=...". Reject anything else (RFC §8.2). Note the
	// CWT encoding (application/statuslist+cwt) is intentionally not
	// supported by v1 — a CWT-only status list is rejected here.
	if !strings.HasPrefix(strings.ToLower(ct), StatusListTokenContentType) {
		return nil, fmt.Errorf(
			"%w: unexpected Content-Type %q: only %s is supported (CWT status lists are not implemented)",
			ErrFetch, ct, StatusListTokenContentType,
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
		rawJwt:     body,
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
