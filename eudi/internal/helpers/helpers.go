package helpers

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// MaxImageSize is the most a downloaded image may be: images are shown on a
// card and travel to the app with the credential.
const MaxImageSize = 2 << 20

// DownloadRemoteImage returns the image at uri, a data URI, an https URL or,
// with allowInsecureHTTP, an http URL, and its MIME type as
// clientmodels.ImageMimeType recognises it. It refuses anything that is no
// recognised image or larger than MaxImageSize.
func DownloadRemoteImage(ctx context.Context, httpClient *http.Client, uri string, allowInsecureHTTP bool) ([]byte, string, error) {
	var data []byte
	if strings.HasPrefix(strings.ToLower(uri), "data:") {
		decoded, err := DecodeDataURI(uri)
		if err != nil {
			return nil, "", err
		}
		data = decoded
	} else {
		downloaded, err := download(ctx, httpClient, uri, allowInsecureHTTP)
		if err != nil {
			return nil, "", err
		}
		data = downloaded
	}

	if len(data) > MaxImageSize {
		return nil, "", fmt.Errorf("image %s is larger than %d bytes", uri, MaxImageSize)
	}
	mimeType := clientmodels.ImageMimeType(data)
	if mimeType == "" {
		return nil, "", fmt.Errorf("%s is no PNG, JPEG, GIF, WebP or SVG image", uri)
	}
	return data, mimeType, nil
}

func download(ctx context.Context, httpClient *http.Client, uri string, allowInsecureHTTP bool) ([]byte, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid image URL %q: %v", uri, err)
	}
	switch {
	case strings.EqualFold(parsed.Scheme, "https"):
	case strings.EqualFold(parsed.Scheme, "http") && allowInsecureHTTP:
	default:
		return nil, fmt.Errorf("image URL %q is not https", uri)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build request for image %s: %v", uri, err)
	}

	response, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download image %s: %v", uri, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download image %s: server returned status code %d", uri, response.StatusCode)
	}
	if response.ContentLength > MaxImageSize {
		return nil, fmt.Errorf("image %s is larger than %d bytes", uri, MaxImageSize)
	}

	// One byte past the limit is enough to tell that the image is too large.
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxImageSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read image %s: %v", uri, err)
	}
	return data, nil
}

// IsImageDataURI reports whether s is a data URI of an image type. The scheme
// and the media type are case-insensitive (RFC 2397).
func IsImageDataURI(s string) bool {
	return len(s) > len("data:image/") && strings.EqualFold(s[:len("data:image/")], "data:image/")
}

// IsImageURI reports whether s is an image data URI or an http(s) URL with a
// host.
func IsImageURI(s string) bool {
	if IsImageDataURI(s) {
		return true
	}
	lower := strings.ToLower(s)
	if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") {
		return false
	}
	parsed, err := url.Parse(s)
	return err == nil && parsed.Host != ""
}

// DecodeDataURI returns the bytes a data URI holds (RFC 2397): base64 when its
// media type ends in ";base64", percent-encoded text otherwise.
func DecodeDataURI(uri string) ([]byte, error) {
	if len(uri) < len("data:") || !strings.EqualFold(uri[:len("data:")], "data:") {
		return nil, fmt.Errorf("not a data URI")
	}
	meta, data, ok := strings.Cut(uri[len("data:"):], ",")
	if !ok {
		return nil, fmt.Errorf("invalid data URI: missing comma")
	}
	if strings.HasSuffix(strings.ToLower(meta), ";base64") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(data))
		if err != nil {
			return nil, fmt.Errorf("invalid data URI: base64 decode failed: %v", err)
		}
		return decoded, nil
	}
	decoded, err := url.PathUnescape(data)
	if err != nil {
		return nil, fmt.Errorf("invalid data URI: %v", err)
	}
	return []byte(decoded), nil
}
