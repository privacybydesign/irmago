package protocol

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type HTTPTransport struct {
	Server string
	client *http.Client
}

func NewHTTPTransport(serverURL string) *HTTPTransport {
	url := serverURL
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	return &HTTPTransport{
		Server: url,
		client: &http.Client{
			Timeout: time.Second * 5,
		},
	}
}

func (transport *HTTPTransport) request(url string, method string, result interface{}, object interface{}) error {
	if method != http.MethodPost && method != http.MethodGet {
		panic("Unsupported HTTP method " + method)
	}
	if method == http.MethodGet && object != nil {
		panic("Cannot GET and also post an object")
	}

	var reader io.Reader
	if object != nil {
		marshaled, err := json.Marshal(object)
		if err != nil {
			return err
		}
		reader = bytes.NewBuffer(marshaled)
	}

	req, err := http.NewRequest(method, transport.Server+url, reader)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "irmago")
	if object != nil {
		req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}

	res, err := transport.client.Do(req)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(body, result)
	if err != nil {
		return err
	}

	return nil
}

func (transport *HTTPTransport) Post(url string, result interface{}, object interface{}) error {
	return transport.request(url, http.MethodPost, result, object)
}

func (transport *HTTPTransport) Get(url string, result interface{}) error {
	return transport.request(url, http.MethodGet, result, nil)
}

func (transport *HTTPTransport) Delete(url string) {
	// TODO
}
