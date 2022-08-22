package test

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func NewHTTPClient() *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	httpclient := &http.Client{Jar: jar}
	return httpclient
}

func HTTPPost(t *testing.T, client *http.Client, url, body string, headers http.Header, expectedStatus int, result interface{}) {
	httpDo(t, client, url, "POST", body, headers, expectedStatus, result)
}

func HTTPGet(t *testing.T, client *http.Client, url string, headers http.Header, expectedStatus int, result interface{}) {
	httpDo(t, client, url, "GET", "", headers, expectedStatus, result)
}

func httpDo(t *testing.T, client *http.Client, url, method, body string, headers http.Header, expectedStatus int, result interface{}) {
	var buf io.Reader
	if body != "" {
		buf = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, url, buf)
	require.NoError(t, err)

	if headers != nil {
		req.Header = headers
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}

	if client == nil {
		client = NewHTTPClient()
	}
	res, err := client.Do(req)
	require.NoError(t, err)
	require.Equal(t, expectedStatus, res.StatusCode)

	if result != nil {
		bts, err := ioutil.ReadAll(res.Body)
		require.NoError(t, err)
		if strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
			require.NoError(t, json.Unmarshal(bts, result))
		} else {
			require.IsType(t, &bts, result)
			*result.(*[]byte) = bts
		}
	}

	require.NoError(t, res.Body.Close())
}
