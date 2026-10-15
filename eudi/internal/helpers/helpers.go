package helpers

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DownloadRemoteImage downloads an image from a remote URI.
// It supports both standard HTTP(S) URLs and data URIs (e.g., "data:image/png;base64,...").
// Cancelling ctx aborts the transfer, so a caller shutting down does not have to
// wait out the HTTP client's timeout.
func DownloadRemoteImage(ctx context.Context, httpClient *http.Client, remoteImageUri string) ([]byte, string, error) {
	return DownloadRemoteAsset(ctx, httpClient, remoteImageUri, 0)
}

// DownloadRemoteAsset is DownloadRemoteImage with a size cap: when maxBytes is
// positive, a body (or decoded data URI) larger than maxBytes is an error, and
// at most maxBytes+1 bytes are read from the network.
func DownloadRemoteAsset(ctx context.Context, httpClient *http.Client, remoteImageUri string, maxBytes int64) ([]byte, string, error) {
	data, mimeType, err := downloadRemoteAsset(ctx, httpClient, remoteImageUri, maxBytes)
	if err != nil {
		return nil, "", err
	}
	if maxBytes > 0 && int64(len(data)) > maxBytes {
		return nil, "", fmt.Errorf("asset %s exceeds %d bytes", truncateURI(remoteImageUri), maxBytes)
	}
	return data, mimeType, nil
}

func truncateURI(uri string) string {
	if len(uri) > 80 {
		return uri[:80] + "..."
	}
	return uri
}

func downloadRemoteAsset(ctx context.Context, httpClient *http.Client, remoteImageUri string, maxBytes int64) ([]byte, string, error) {
	// data URIs (e.g. "data:image/png;base64,...") carry the image inline — no HTTP request needed.
	if strings.HasPrefix(remoteImageUri, "data:") {
		// Expected format: data:<mediatype>[;base64],<data>
		rest := remoteImageUri[len("data:"):]
		before, after, ok := strings.Cut(rest, ",")
		if !ok {
			return nil, "", fmt.Errorf("invalid data URI: missing comma in %q", remoteImageUri)
		}
		meta := before
		payload := after
		var imageBytes []byte
		if strings.HasSuffix(meta, ";base64") {
			decoded, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return nil, "", fmt.Errorf("invalid data URI: base64 decode failed: %v", err)
			}
			imageBytes = decoded
		} else {
			imageBytes = []byte(payload)
		}
		mediaType := strings.TrimSuffix(meta, ";base64")
		return imageBytes, mediaType, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteImageUri, nil)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build request for image %s: %v", remoteImageUri, err)
	}

	response, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to download image %s: %v", remoteImageUri, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf(
			"failed to download logo %s: server returned status code %d",
			remoteImageUri,
			response.StatusCode,
		)
	}

	var body io.Reader = response.Body
	if maxBytes > 0 {
		body = io.LimitReader(response.Body, maxBytes+1)
	}
	bytes, err := io.ReadAll(body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read logo %s: %v", remoteImageUri, err)
	}

	return bytes, response.Header.Get("Content-Type"), nil
}
