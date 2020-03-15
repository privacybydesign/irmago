package irma

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/revocation"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/disable_sigpipe"
)

// HTTPTransport sends and receives JSON messages to a HTTP server.
type HTTPTransport struct {
	Server  string
	Binary  bool
	client  *retryablehttp.Client
	headers map[string]string
}

// Logger is used for logging. If not set, init() will initialize it to logrus.StandardLogger().
var Logger *logrus.Logger

var transportlogger *log.Logger

func init() {
	Logger = logrus.New()
	Logger.SetFormatter(&prefixed.TextFormatter{
		DisableColors:   true,
		FullTimestamp:   true,
		TimestampFormat: "15:04:05.000000",
	})
	gabi.Logger = Logger
	revocation.Logger = Logger
}

// NewHTTPTransport returns a new HTTPTransport.
func NewHTTPTransport(serverURL string) *HTTPTransport {
	if Logger.IsLevelEnabled(logrus.TraceLevel) {
		transportlogger = log.New(Logger.WriterLevel(logrus.TraceLevel), "transport: ", 0)
	} else {
		transportlogger = log.New(ioutil.Discard, "", 0)
	}

	url := serverURL
	if serverURL != "" && !strings.HasSuffix(url, "/") { // TODO fix this
		url += "/"
	}

	// Create a transport that dials with a SIGPIPE handler (which is only active on iOS)
	var innerTransport http.Transport

	innerTransport.Dial = func(network, addr string) (c net.Conn, err error) {
		c, err = net.Dial(network, addr)
		if err != nil {
			return c, err
		}
		if err = disable_sigpipe.DisableSigPipe(c); err != nil {
			return c, err
		}
		return c, nil
	}

	client := &retryablehttp.Client{
		Logger:       transportlogger,
		RetryWaitMin: 100 * time.Millisecond,
		RetryWaitMax: 200 * time.Millisecond,
		RetryMax:     2,
		Backoff:      retryablehttp.DefaultBackoff,
		CheckRetry: func(ctx context.Context, resp *http.Response, err error) (bool, error) {
			// Don't retry on 5xx (which retryablehttp does by default)
			return err != nil || resp.StatusCode == 0, err
		},
		HTTPClient: &http.Client{
			Timeout:   time.Second * 3,
			Transport: &innerTransport,
		},
	}

	return &HTTPTransport{
		Server:  url,
		headers: map[string]string{},
		client:  client,
	}
}

func (transport *HTTPTransport) marshal(o interface{}) ([]byte, error) {
	if transport.Binary {
		return MarshalBinary(o)
	}
	return json.Marshal(o)
}

func (transport *HTTPTransport) unmarshal(data []byte, dst interface{}) error {
	if transport.Binary {
		return UnmarshalBinary(data, dst)
	}
	return json.Unmarshal(data, dst)
}

func (transport *HTTPTransport) unmarshalValidate(data []byte, dst interface{}) error {
	if transport.Binary {
		return UnmarshalValidateBinary(data, dst)
	}
	return UnmarshalValidate(data, dst)
}

func (transport *HTTPTransport) log(prefix string, message interface{}, binary bool) {
	if !Logger.IsLevelEnabled(logrus.TraceLevel) {
		return // do nothing if nothing would be printed anyway
	}
	var str string
	switch s := message.(type) {
	case []byte:
		str = string(s)
	case string:
		str = s
	default:
		tmp, _ := json.Marshal(message)
		str = string(tmp)
		binary = false
	}
	if !binary {
		Logger.Tracef("transport: %s: %s", prefix, str)
	} else {
		Logger.Tracef("transport: %s (hex): %s", prefix, hex.EncodeToString([]byte(str)))
	}
}

// SetHeader sets a header to be sent in requests.
func (transport *HTTPTransport) SetHeader(name, val string) {
	transport.headers[name] = val
}

func (transport *HTTPTransport) request(
	url string, method string, reader io.Reader, contenttype string,
) (response *http.Response, err error) {
	var req retryablehttp.Request
	req.Request, err = http.NewRequest(method, transport.Server+url, reader)
	if err != nil {
		return nil, &SessionError{ErrorType: ErrorTransport, Err: err}
	}

	req.Header.Set("User-Agent", "irmago")
	if reader != nil && contenttype != "" {
		req.Header.Set("Content-Type", contenttype)
	}
	for name, val := range transport.headers {
		req.Header.Set(name, val)
	}

	res, err := transport.client.Do(&req)
	if err != nil {
		return nil, &SessionError{ErrorType: ErrorTransport, Err: err}
	}
	Logger.Trace("headers: ", res.Header)
	return res, nil
}

func (transport *HTTPTransport) jsonRequest(url string, method string, result interface{}, object interface{}) error {
	if method != http.MethodPost && method != http.MethodGet && method != http.MethodDelete {
		panic("Unsupported HTTP method " + method)
	}
	if method == http.MethodGet && object != nil {
		panic("Cannot GET and also post an object")
	}

	var reader io.Reader
	var contenttype string
	if object != nil {
		switch o := object.(type) {
		case []byte:
			transport.log("body", o, true)
			contenttype = "application/octet-stream"
			reader = bytes.NewBuffer(o)
		case string:
			transport.log("body", o, false)
			contenttype = "text/plain; charset=UTF-8"
			reader = bytes.NewBuffer([]byte(o))
		default:
			marshaled, err := transport.marshal(object)
			if err != nil {
				return &SessionError{ErrorType: ErrorSerialization, Err: err}
			}
			transport.log("body", string(marshaled), transport.Binary)
			if transport.Binary {
				contenttype = "application/octet-stream"
			} else {
				contenttype = "application/json; charset=UTF-8"
			}
			reader = bytes.NewBuffer(marshaled)
		}
	}

	res, err := transport.request(url, method, reader, contenttype)
	if err != nil {
		return err
	}
	if method == http.MethodDelete {
		return nil
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return &SessionError{ErrorType: ErrorServerResponse, Err: err, RemoteStatus: res.StatusCode}
	}
	if res.StatusCode != 200 {
		apierr := &RemoteError{}
		err = transport.unmarshal(body, apierr)
		if err != nil || apierr.ErrorName == "" { // Not an ApiErrorMessage
			return &SessionError{ErrorType: ErrorServerResponse, Err: err, RemoteStatus: res.StatusCode}
		}
		transport.log("error", apierr, false)
		return &SessionError{ErrorType: ErrorApi, RemoteStatus: res.StatusCode, RemoteError: apierr}
	}

	transport.log("response", body, transport.Binary)
	if result == nil { // caller doesn't care about server response
		return nil
	}
	if _, resultstr := result.(*string); resultstr {
		*result.(*string) = string(body)
	} else {
		err = transport.unmarshalValidate(body, result)
		if err != nil {
			return &SessionError{ErrorType: ErrorServerResponse, Err: err, RemoteStatus: res.StatusCode}
		}
	}

	return nil
}

func (transport *HTTPTransport) GetBytes(url string) ([]byte, error) {
	res, err := transport.request(url, http.MethodGet, nil, "")
	if err != nil {
		return nil, &SessionError{ErrorType: ErrorTransport, Err: err}
	}

	if res.StatusCode != 200 {
		return nil, &SessionError{ErrorType: ErrorServerResponse, RemoteStatus: res.StatusCode}
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, &SessionError{ErrorType: ErrorServerResponse, Err: err, RemoteStatus: res.StatusCode}
	}
	return b, nil
}

func (transport *HTTPTransport) GetSignedFile(url string, dest string, hash ConfigurationFileHash) error {
	b, err := transport.GetBytes(url)
	if err != nil {
		return err
	}
	sha := sha256.Sum256(b)
	if hash != nil && !bytes.Equal(hash, sha[:]) {
		return errors.Errorf("Signature over new file %s is not valid", dest)
	}
	if err = common.EnsureDirectoryExists(filepath.Dir(dest)); err != nil {
		return err
	}
	return common.SaveFile(dest, b)
}

func (transport *HTTPTransport) GetFile(url string, dest string) error {
	return transport.GetSignedFile(url, dest, nil)
}

// Post sends the object to the server and parses its response into result.
func (transport *HTTPTransport) Post(url string, result interface{}, object interface{}) error {
	return transport.jsonRequest(url, http.MethodPost, result, object)
}

// Get performs a GET request and parses the server's response into result.
func (transport *HTTPTransport) Get(url string, result interface{}) error {
	return transport.jsonRequest(url, http.MethodGet, result, nil)
}

// Delete performs a DELETE.
func (transport *HTTPTransport) Delete() {
	_ = transport.jsonRequest("", http.MethodDelete, nil, nil)
}
