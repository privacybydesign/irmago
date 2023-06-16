package irma

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/revocation"
	sseclient "github.com/sietseringers/go-sse"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/disable_sigpipe"
)

const responseDeadline = 10 * time.Minute // TODO: undo

// HTTPTransport sends and receives JSON messages to a HTTP server.
type HTTPTransport struct {
	Server     string
	Binary     bool
	ForceHTTPS bool
	client     *retryablehttp.Client
	headers    http.Header
}

var HTTPHeaders = map[string]http.Header{}

// Logger is used for logging. If not set, init() will initialize it to logrus.StandardLogger().
var Logger *logrus.Logger

var transportlogger *log.Logger

var tlsClientConfig *tls.Config

func init() {
	logger := logrus.New()
	logger.SetFormatter(&prefixed.TextFormatter{
		DisableColors:   true,
		FullTimestamp:   true,
		TimestampFormat: "15:04:05.000000",
	})
	SetLogger(logger)
}

func SetLogger(logger *logrus.Logger) {
	Logger = logger
	gabi.Logger = Logger
	common.Logger = Logger
	revocation.Logger = Logger
	sseclient.Logger = log.New(Logger.WithField("type", "sseclient").WriterLevel(logrus.TraceLevel), "", 0)
}

// SetTLSClientConfig sets the TLS configuration being used for future outbound connections.
// A TLS configuration instance should not be modified after being set.
func SetTLSClientConfig(config *tls.Config) {
	tlsClientConfig = config
}

// NewHTTPTransport returns a new HTTPTransport.
func NewHTTPTransport(serverURL string, forceHTTPS bool) *HTTPTransport {
	if Logger.IsLevelEnabled(logrus.TraceLevel) {
		transportlogger = log.New(Logger.WriterLevel(logrus.TraceLevel), "transport: ", 0)
	} else {
		transportlogger = log.New(io.Discard, "", 0)
	}

	if serverURL != "" && !strings.HasSuffix(serverURL, "/") {
		serverURL += "/"
	}

	// Create a transport that dials with a SIGPIPE handler (which is only active on iOS).
	// The settings are inspired on the defaults of http.DefaultTransport.
	innerTransport := &http.Transport{
		TLSClientConfig:       tlsClientConfig,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   30 * time.Minute, // TODO: remove
				KeepAlive: 30 * time.Minute,
			}
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return conn, err
			}
			return conn, disable_sigpipe.DisableSigPipe(conn)
		},
	}

	client := &retryablehttp.Client{
		Logger:       transportlogger,
		RetryWaitMin: 100 * time.Millisecond,
		RetryWaitMax: 200 * time.Millisecond,
		RetryMax:     2,
		Backoff:      retryablehttp.DefaultBackoff,
		CheckRetry: func(ctx context.Context, resp *http.Response, err error) (bool, error) {
			if cerr := ctx.Err(); cerr != nil {
				return false, cerr
			}
			// Don't retry on 5xx (which retryablehttp does by default)
			return err != nil || resp.StatusCode == 0, err
		},
		HTTPClient: &http.Client{
			Timeout:   time.Hour * 5,
			Transport: innerTransport,
		},
	}

	var host string
	u, err := url.Parse(serverURL)
	if err != nil {
		Logger.Warnf("failed to parse URL %s: %s", serverURL, err.Error())
	} else {
		host = u.Host
	}
	headers := HTTPHeaders[host].Clone()
	if headers == nil {
		headers = http.Header{}
	}
	return &HTTPTransport{
		Server:     serverURL,
		ForceHTTPS: forceHTTPS,
		headers:    headers,
		client:     client,
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
	transport.headers.Set(name, val)
}

func (transport *HTTPTransport) request(
	ctx context.Context,
	url string,
	method string,
	reader io.Reader,
	contenttype string,
) (response *http.Response, err error) {
	var req retryablehttp.Request
	u := transport.Server + url
	if common.ForceHTTPS && transport.ForceHTTPS && !strings.HasPrefix(u, "https") {
		return nil, &SessionError{ErrorType: ErrorHTTPS, Err: errors.New("remote server does not use https")}
	}

	req.Request, err = http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, &SessionError{ErrorType: ErrorTransport, Err: err}
	}
	req.Header = transport.headers.Clone()
	if req.Header.Get("User-agent") == "" {
		req.Header.Set("User-Agent", "irmago")
	}
	if reader != nil && contenttype != "" {
		req.Header.Set("Content-Type", contenttype)
	}
	res, err := transport.client.Do(&req)
	if err != nil {
		return nil, &SessionError{ErrorType: ErrorTransport, Err: err}
	}
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

	ctx, cancel := context.WithTimeout(context.Background(), responseDeadline)
	defer cancel()

	res, err := transport.request(ctx, url, method, reader, contenttype)
	if err != nil {
		return err
	}
	defer common.Close(res.Body)

	// For DELETE requests it's common to receive a '204 No Content' on success.
	if method == http.MethodDelete && (res.StatusCode == http.StatusOK || res.StatusCode == http.StatusNoContent) {
		return nil
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return &SessionError{ErrorType: ErrorServerResponse, Err: err, RemoteStatus: res.StatusCode}
	}

	if res.StatusCode == http.StatusNoContent {
		if result != nil {
			return &SessionError{
				ErrorType:    ErrorServerResponse,
				Err:          errors.New("'204 No Content' received, but result was expected"),
				RemoteStatus: res.StatusCode,
			}
		}
	} else if res.StatusCode != http.StatusOK {
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
	ctx, cancel := context.WithTimeout(context.Background(), responseDeadline)
	defer cancel()

	res, err := transport.request(ctx, url, http.MethodGet, nil, "")
	if err != nil {
		return nil, &SessionError{ErrorType: ErrorTransport, Err: err}
	}
	defer common.Close(res.Body)

	if res.StatusCode != 200 {
		return nil, &SessionError{ErrorType: ErrorServerResponse, RemoteStatus: res.StatusCode}
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, &SessionError{ErrorType: ErrorServerResponse, Err: err, RemoteStatus: res.StatusCode}
	}
	return b, nil
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
func (transport *HTTPTransport) Delete() error {
	return transport.jsonRequest("", http.MethodDelete, nil, nil)
}
