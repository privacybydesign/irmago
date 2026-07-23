package helpers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDownloadRemoteImage_DataURI(t *testing.T) {
	httpClient := &http.Client{}

	t.Run("base64 encoded image", func(t *testing.T) {
		// "PNG" as a trivial base64 payload
		payload := "UE5H" // base64("PNG")
		uri := "data:image/png;base64," + payload
		data, mediaType, err := DownloadRemoteImage(httpClient, uri)
		require.NoError(t, err)
		require.Equal(t, "image/png", mediaType)
		require.Equal(t, []byte("PNG"), data)
	})

	t.Run("plain (non-base64) data URI", func(t *testing.T) {
		uri := "data:text/plain,hello"
		data, mediaType, err := DownloadRemoteImage(httpClient, uri)
		require.NoError(t, err)
		require.Equal(t, "text/plain", mediaType)
		require.Equal(t, []byte("hello"), data)
	})

	t.Run("invalid data URI without comma", func(t *testing.T) {
		uri := "data:image/png;base64"
		_, _, err := DownloadRemoteImage(httpClient, uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing comma")
	})

	t.Run("invalid base64 payload", func(t *testing.T) {
		uri := "data:image/png;base64,not-valid-base64!!!"
		_, _, err := DownloadRemoteImage(httpClient, uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "base64 decode failed")
	})

	t.Run("HTTP URI still fetched from server", func(t *testing.T) {
		imageData := []byte{0x89, 0x50, 0x4E, 0x47} // PNG magic bytes
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(imageData)
		}))
		defer server.Close()

		data, mediaType, err := DownloadRemoteImage(httpClient, server.URL+"/logo.png")
		require.NoError(t, err)
		require.Equal(t, "image/png", mediaType)
		require.Equal(t, imageData, data)
	})
}
