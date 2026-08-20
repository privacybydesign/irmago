package lote

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// maxBody caps a list download. A LoTE is a directory of organizations, not
	// a bulk data feed, so a few megabytes is generous.
	maxBody int64 = 5 << 20

	// fetchTimeout bounds one list download.
	fetchTimeout = 10 * time.Second
)

// Fetch downloads the signed list at url. A nil httpClient falls back to
// http.DefaultClient. Exported so `lote verify --against` downloads a published
// list under the same cap, timeout and status rules the wallet applies.
//
// The response Content-Type is not gated on: ETSI has settled no media type for a
// JAdES-signed TS 119 602 list in JSON. The signature is the gate, and the `typ`
// header inside it is what says this JWS is a trusted list.
func Fetch(ctx context.Context, httpClient *http.Client, url string) ([]byte, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	reqCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("non-2xx response: %s", resp.Status)
	}

	limited := io.LimitReader(resp.Body, maxBody+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %v", err)
	}
	if int64(len(body)) > maxBody {
		return nil, fmt.Errorf("response body exceeds cap (%d bytes)", maxBody)
	}
	return body, nil
}
