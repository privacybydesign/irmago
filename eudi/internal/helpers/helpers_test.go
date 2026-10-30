package helpers

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/stretchr/testify/require"
)

// A valid 1x1 PNG.
const testPNGBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4z8AAAAMBAQDJ/pLvAAAAAElFTkSuQmCC"

func testPNG(t *testing.T) []byte {
	t.Helper()
	png, err := base64.StdEncoding.DecodeString(testPNGBase64)
	require.NoError(t, err)
	return png
}

func TestDownloadRemoteImage_DataURI(t *testing.T) {
	httpClient := &http.Client{}

	t.Run("base64 encoded image", func(t *testing.T) {
		data, mimeType, err := DownloadRemoteImage(context.Background(), httpClient, "data:image/png;base64,"+testPNGBase64, false)
		require.NoError(t, err)
		require.Equal(t, clientmodels.MimeTypePNG, mimeType)
		require.Equal(t, testPNG(t), data)
	})

	t.Run("percent-encoded SVG", func(t *testing.T) {
		svg := `<svg xmlns="http://www.w3.org/2000/svg"/>`
		data, mimeType, err := DownloadRemoteImage(context.Background(), httpClient, "data:image/svg+xml,"+url.PathEscape(svg), false)
		require.NoError(t, err)
		require.Equal(t, clientmodels.MimeTypeSVG, mimeType)
		require.Equal(t, []byte(svg), data)
	})

	t.Run("the type is the content's, not the media type's", func(t *testing.T) {
		_, mimeType, err := DownloadRemoteImage(context.Background(), httpClient, "data:image/jpeg;base64,"+testPNGBase64, false)
		require.NoError(t, err)
		require.Equal(t, clientmodels.MimeTypePNG, mimeType)
	})

	t.Run("content that is no image", func(t *testing.T) {
		_, _, err := DownloadRemoteImage(context.Background(), httpClient, "data:text/plain,hello", false)
		require.ErrorContains(t, err, "no PNG, JPEG, GIF, WebP or SVG")
	})

	t.Run("invalid data URI without comma", func(t *testing.T) {
		_, _, err := DownloadRemoteImage(context.Background(), httpClient, "data:image/png;base64", false)
		require.ErrorContains(t, err, "missing comma")
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		_, _, err := DownloadRemoteImage(context.Background(), httpClient, "data:image/png;base64,not-valid-base64!!!", false)
		require.ErrorContains(t, err, "base64 decode failed")
	})

	t.Run("an image larger than the limit", func(t *testing.T) {
		large := append(testPNG(t), make([]byte, MaxImageSize)...)
		_, _, err := DownloadRemoteImage(context.Background(), httpClient, "data:image/png;base64,"+base64.StdEncoding.EncodeToString(large), false)
		require.ErrorContains(t, err, "larger than")
	})
}

// imageServer serves body at /image with the given Content-Type, over TLS
// unless plain is set, and counts the bytes it wrote.
func imageServer(t *testing.T, plain bool, contentType string, body []byte) (*httptest.Server, *int) {
	t.Helper()
	written := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		for chunk := range slicesChunk(body, 32*1024) {
			n, err := w.Write(chunk)
			written += n
			if err != nil {
				return
			}
		}
	})
	var server *httptest.Server
	if plain {
		server = httptest.NewServer(handler)
	} else {
		server = httptest.NewTLSServer(handler)
	}
	t.Cleanup(server.Close)
	return server, &written
}

func slicesChunk(b []byte, n int) func(func([]byte) bool) {
	return func(yield func([]byte) bool) {
		for len(b) > 0 {
			end := min(n, len(b))
			if !yield(b[:end]) {
				return
			}
			b = b[end:]
		}
	}
}

func TestDownloadRemoteImage_HTTPS(t *testing.T) {
	server, _ := imageServer(t, false, "application/octet-stream", testPNG(t))

	data, mimeType, err := DownloadRemoteImage(context.Background(), server.Client(), server.URL+"/image", false)
	require.NoError(t, err)
	require.Equal(t, testPNG(t), data)
	require.Equal(t, clientmodels.MimeTypePNG, mimeType, "the type is the content's, not the Content-Type header's")
}

func TestDownloadRemoteImage_PlainHTTPOnlyWhenAllowed(t *testing.T) {
	server, _ := imageServer(t, true, "image/png", testPNG(t))

	_, _, err := DownloadRemoteImage(context.Background(), server.Client(), server.URL+"/image", false)
	require.ErrorContains(t, err, "is not https")

	data, _, err := DownloadRemoteImage(context.Background(), server.Client(), server.URL+"/image", true)
	require.NoError(t, err, "developer mode allows plain http")
	require.Equal(t, testPNG(t), data)
}

func TestDownloadRemoteImage_OtherSchemesRefused(t *testing.T) {
	for _, uri := range []string{"file:///etc/passwd", "ftp://example.com/a.png", "example.com/a.png"} {
		_, _, err := DownloadRemoteImage(context.Background(), http.DefaultClient, uri, true)
		require.ErrorContains(t, err, "is not https", uri)
	}
}

func TestDownloadRemoteImage_ContentThatIsNoImage(t *testing.T) {
	server, _ := imageServer(t, false, "image/png", []byte("<html>not found</html>"))
	_, _, err := DownloadRemoteImage(context.Background(), server.Client(), server.URL+"/image", false)
	require.ErrorContains(t, err, "no PNG, JPEG, GIF, WebP or SVG")
}

func TestDownloadRemoteImage_StatusCode(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	_, _, err := DownloadRemoteImage(context.Background(), server.Client(), server.URL+"/image", false)
	require.ErrorContains(t, err, "status code 404")
}

// countingTransport counts the response body bytes the client reads.
type countingTransport struct {
	inner http.RoundTripper
	read  int
}

func (c *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := c.inner.RoundTrip(r)
	if err == nil {
		response.Body = &countingBody{ReadCloser: response.Body, read: &c.read}
	}
	return response, err
}

type countingBody struct {
	io.ReadCloser
	read *int
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	*b.read += n
	return n, err
}

// A file larger than the limit is refused after reading just past it, also
// when the server does not announce its length.
func TestDownloadRemoteImage_ReadCap(t *testing.T) {
	large := append(testPNG(t), make([]byte, 4*MaxImageSize)...)
	server, _ := imageServer(t, false, "image/png", large)
	transport := &countingTransport{inner: server.Client().Transport}

	_, _, err := DownloadRemoteImage(context.Background(), &http.Client{Transport: transport}, server.URL+"/image", false)
	require.ErrorContains(t, err, "larger than")
	require.Equal(t, MaxImageSize+1, transport.read, "the download stops one byte past the limit")
}

func TestDownloadRemoteImage_AnnouncedLengthTooLarge(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Length", strconv.Itoa(MaxImageSize+1))
		_, _ = w.Write([]byte(strings.Repeat("x", 10)))
	}))
	t.Cleanup(server.Close)

	_, _, err := DownloadRemoteImage(context.Background(), server.Client(), server.URL+"/image", false)
	require.ErrorContains(t, err, "larger than")
	require.Equal(t, 1, requests)
}

func TestDecodeDataURI(t *testing.T) {
	data, err := DecodeDataURI("DATA:image/png;BASE64," + testPNGBase64)
	require.NoError(t, err, "the scheme and the base64 marker are case-insensitive")
	require.Equal(t, testPNG(t), data)

	_, err = DecodeDataURI("https://example.com/a.png")
	require.ErrorContains(t, err, "not a data URI")
}
