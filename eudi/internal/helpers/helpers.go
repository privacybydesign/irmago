package helpers

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// DownloadRemoteImage downloads an image from a remote URI.
// It supports both standard HTTP(S) URLs and data URIs (e.g., "data:image/png;base64,...").
func DownloadRemoteImage(httpClient *http.Client, remoteImageUri string) ([]byte, string, error) {
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

	response, err := httpClient.Get(remoteImageUri)
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

	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read logo %s: %v", remoteImageUri, err)
	}

	return bytes, response.Header.Get("Content-Type"), nil
}
