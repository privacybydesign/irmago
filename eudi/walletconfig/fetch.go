package walletconfig

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// MaxDocumentBytes caps a config download. A config is a directory of
	// organizations plus a handful of certificates, not a bulk feed, so a few
	// megabytes is generous. Wallets do not make conditional requests, which is
	// why the publisher checks the size on its side too.
	MaxDocumentBytes int64 = 5 << 20

	// FetchTimeout bounds one download.
	FetchTimeout = 10 * time.Second
)

// Fetch downloads the signed config at url. A nil httpClient falls back to
// http.DefaultClient. The response Content-Type is not gated on: the signature
// is the gate, and the `typ` header inside it is what says this is a config.
func Fetch(ctx context.Context, httpClient *http.Client, url string) ([]byte, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %v", err)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode/100 != 2 {
		return nil, fmt.Errorf("non-2xx response: %s", response.Status)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %v", err)
	}
	if int64(len(body)) > MaxDocumentBytes {
		return nil, fmt.Errorf("response body exceeds cap (%d bytes)", MaxDocumentBytes)
	}
	return body, nil
}
