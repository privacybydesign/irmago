package test

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.NoError(t, err)

	if headers != nil {
		req.Header = headers
	}
	if body != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}

	if client == nil {
		client = NewHTTPClient()
	}
	res, err := client.Do(req)
	assert.NoError(t, err)
	assert.Equal(t, expectedStatus, res.StatusCode)

	if result != nil {
		bts, err := ioutil.ReadAll(res.Body)
		assert.NoError(t, err)
		if res.Header.Get("Content-Type") == "application/json" {
			assert.NoError(t, json.Unmarshal(bts, result))
		} else {
			require.IsType(t, &bts, result)
			*result.(*[]byte) = bts
		}
	}

	assert.NoError(t, res.Body.Close())
}
