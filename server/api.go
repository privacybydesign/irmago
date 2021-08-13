package server

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi/middleware"
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var Logger *logrus.Logger = logrus.StandardLogger()

type SessionPackage struct {
	SessionPtr      *irma.Qr                     `json:"sessionPtr"`
	Token           irma.RequestorToken          `json:"token"`
	FrontendRequest *irma.FrontendSessionRequest `json:"frontendRequest"`
}

// SessionResult contains session information such as the session status, type, possible errors,
// and disclosed attributes or attribute-based signature if appropriate to the session type.
type SessionResult struct {
	Token       irma.RequestorToken          `json:"token"`
	Status      irma.ServerStatus            `json:"status"`
	Type        irma.Action                  `json:"type"`
	ProofStatus irma.ProofStatus             `json:"proofStatus,omitempty"`
	Disclosed   [][]*irma.DisclosedAttribute `json:"disclosed,omitempty"`
	Signature   *irma.SignedMessage          `json:"signature,omitempty"`
	Err         *irma.RemoteError            `json:"error,omitempty"`
	NextSession irma.RequestorToken          `json:"nextSession,omitempty"`

	LegacySession bool `json:"-"` // true if request was started with legacy (i.e. pre-condiscon) session request
}

// SessionHandler is a function that can handle a session result
// once an IRMA session has completed.
type SessionHandler func(*SessionResult)

type LogOptions struct {
	Response, Headers, From, EncodeBinary bool
}

// Remove this when dropping support for legacy pre-condiscon session requests
type LegacySessionResult struct {
	Token       irma.RequestorToken        `json:"token"`
	Status      irma.ServerStatus          `json:"status"`
	Type        irma.Action                `json:"type"`
	ProofStatus irma.ProofStatus           `json:"proofStatus,omitempty"`
	Disclosed   []*irma.DisclosedAttribute `json:"disclosed,omitempty"`
	Signature   *irma.SignedMessage        `json:"signature,omitempty"`
	Err         *irma.RemoteError          `json:"error,omitempty"`
}

const (
	ComponentRevocation      = "revocation"
	ComponentSession         = "session"
	ComponentFrontendSession = "frontendsession"
	ComponentStatic          = "static"
)

const (
	ReadTimeout  = 5 * time.Second
	WriteTimeout = 2 * ReadTimeout
)

var PostSizeLimit int64 = 10 << 20 // 10 MB

// Remove this when dropping support for legacy pre-condiscon session requests
func (r *SessionResult) Legacy() *LegacySessionResult {
	var disclosed []*irma.DisclosedAttribute
	for _, l := range r.Disclosed {
		disclosed = append(disclosed, l[0])
	}
	return &LegacySessionResult{r.Token, r.Status, r.Type, r.ProofStatus, disclosed, r.Signature, r.Err}
}

// RemoteError converts an error and an explaining message to an *irma.RemoteError.
func RemoteError(err Error, message string) *irma.RemoteError {
	var stack string
	Logger.WithFields(logrus.Fields{
		"status":      err.Status,
		"description": err.Description,
		"error":       err.Type,
		"message":     message,
	}).Warnf("Sending session error")
	if Logger.IsLevelEnabled(logrus.DebugLevel) {
		stack = string(debug.Stack())
		Logger.Warn(stack)
	}
	return &irma.RemoteError{
		Status:      err.Status,
		Description: err.Description,
		ErrorName:   string(err.Type),
		Message:     message,
		Stacktrace:  stack,
	}
}

// JsonResponse JSON-marshals the specified object or error
// and returns it along with a suitable HTTP status code
func JsonResponse(v interface{}, err *irma.RemoteError) (int, []byte) {
	return encodeValOrError(v, err, json.Marshal)
}

func BinaryResponse(v interface{}, err *irma.RemoteError) (int, []byte) {
	return encodeValOrError(v, err, irma.MarshalBinary)
}

func encodeValOrError(v interface{}, err *irma.RemoteError, encoder func(interface{}) ([]byte, error)) (int, []byte) {
	msg := v
	status := http.StatusOK
	if err != nil {
		msg = err
		status = err.Status
	}
	b, e := encoder(msg)
	if e != nil {
		Logger.Error("Failed to serialize response:", e.Error())
		return http.StatusInternalServerError, nil
	}
	return status, b
}

// WriteError writes the specified error and explaining message as JSON to the http.ResponseWriter.
func WriteError(w http.ResponseWriter, err Error, msg string) {
	WriteResponse(w, nil, RemoteError(err, msg))
}

// WriteJson writes the specified object as JSON to the http.ResponseWriter.
func WriteJson(w http.ResponseWriter, object interface{}) {
	WriteResponse(w, object, nil)
}

func WriteBinaryResponse(w http.ResponseWriter, object interface{}, rerr *irma.RemoteError) {
	status, bts := BinaryResponse(object, rerr)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(status)
	_, _ = w.Write(bts)
}

// WriteResponse writes the specified object or error as JSON to the http.ResponseWriter.
func WriteResponse(w http.ResponseWriter, object interface{}, rerr *irma.RemoteError) {
	status, bts := JsonResponse(object, rerr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err := w.Write(bts)
	if err != nil {
		_ = LogWarning(errors.WrapPrefix(err, "failed to write response", 0))
	}
}

// WriteString writes the specified string to the http.ResponseWriter.
func WriteString(w http.ResponseWriter, str string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(str))
	if err != nil {
		_ = LogWarning(errors.WrapPrefix(err, "failed to write response", 0))
	}
}

// ParseSessionRequest attempts to parse the input as an irma.RequestorRequest instance, accepting (skipping "irma.")
//  - RequestorRequest instances directly (ServiceProviderRequest, SignatureRequestorRequest, IdentityProviderRequest)
//  - SessionRequest instances (DisclosureRequest, SignatureRequest, IssuanceRequest)
//  - JSON representations ([]byte or string) of any of the above.
func ParseSessionRequest(request interface{}) (irma.RequestorRequest, error) {
	rr, e := parseInput(request)
	if e != nil {
		return nil, e
	}
	rr.Base().SetDefaultsIfNecessary()

	return rr, e
}

func parseInput(request interface{}) (irma.RequestorRequest, error) {
	switch r := request.(type) {
	case irma.RequestorRequest:
		return r, nil
	case irma.SessionRequest:
		return wrapSessionRequest(r)
	case string:
		return parseInput([]byte(r))
	case []byte:
		var attempts = []irma.Validator{&irma.ServiceProviderRequest{}, &irma.SignatureRequestorRequest{}, &irma.IdentityProviderRequest{}}
		t, err := tryUnmarshalJson(r, attempts)
		if err == nil {
			return t.(irma.RequestorRequest), nil
		}
		attempts = []irma.Validator{&irma.DisclosureRequest{}, &irma.SignatureRequest{}, &irma.IssuanceRequest{}}
		t, err = tryUnmarshalJson(r, attempts)
		if err == nil {
			return wrapSessionRequest(t.(irma.SessionRequest))
		}
		return nil, errors.New("Failed to JSON unmarshal request bytes")
	default:
		return nil, errors.New("Invalid request type")
	}
}

func wrapSessionRequest(request irma.SessionRequest) (irma.RequestorRequest, error) {
	switch r := request.(type) {
	case *irma.DisclosureRequest:
		return &irma.ServiceProviderRequest{Request: r}, nil
	case *irma.SignatureRequest:
		return &irma.SignatureRequestorRequest{Request: r}, nil
	case *irma.IssuanceRequest:
		return &irma.IdentityProviderRequest{Request: r}, nil
	default:
		return nil, errors.New("Invalid session type")
	}
}

func tryUnmarshalJson(bts []byte, attempts []irma.Validator) (irma.Validator, error) {
	for _, a := range attempts {
		if err := irma.UnmarshalValidate(bts, a); err == nil {
			return a, nil
		}
	}
	return nil, errors.New("")
}

// LocalIP returns the IP address of one of the (non-loopback) network interfaces
func LocalIP() (string, error) {
	// Based on https://play.golang.org/p/BDt3qEQ_2H from https://stackoverflow.com/a/23558495
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("No IP found")
}

func Verbosity(level int) logrus.Level {
	switch {
	case level == 1:
		return logrus.DebugLevel
	case level > 1:
		return logrus.TraceLevel
	default:
		return logrus.InfoLevel
	}
}

func TypeString(x interface{}) string {
	return reflect.TypeOf(x).String()
}

func ResultJwt(sessionresult *SessionResult, issuer string, validity int, privatekey *rsa.PrivateKey) (string, error) {
	standardclaims := jwt.StandardClaims{
		Issuer:   issuer,
		IssuedAt: time.Now().Unix(),
		Subject:  string(sessionresult.Type) + "_result",
	}
	standardclaims.ExpiresAt = standardclaims.IssuedAt + int64(validity)

	var claims jwt.Claims
	if sessionresult.LegacySession {
		claims = struct {
			jwt.StandardClaims
			*LegacySessionResult
		}{standardclaims, sessionresult.Legacy()}
	} else {
		claims = struct {
			jwt.StandardClaims
			*SessionResult
		}{standardclaims, sessionresult}
	}

	// Sign the jwt and return it
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privatekey)
}

func DoResultCallback(callbackUrl string, result *SessionResult, issuer string, validity int, privatekey *rsa.PrivateKey) {
	logger := Logger.WithFields(logrus.Fields{"session": result.Token, "callbackUrl": callbackUrl})
	if !strings.HasPrefix(callbackUrl, "https") {
		logger.Warn("POSTing session result to callback URL without TLS: attributes are unencrypted in traffic")
	} else {
		logger.Debug("POSTing session result")
	}

	var res interface{}
	if privatekey != nil {
		var err error
		res, err = ResultJwt(result, issuer, validity, privatekey)
		if err != nil {
			_ = LogError(errors.WrapPrefix(err, "Failed to create JWT for result callback", 0))
			return
		}
	} else {
		res = result
	}

	if err := irma.NewHTTPTransport(callbackUrl, false).Post("", nil, res); err != nil {
		// not our problem, log it and go on
		logger.Warn(errors.WrapPrefix(err, "Failed to POST session result to callback URL", 0))
	}
}

func log(level logrus.Level, err error) error {
	writer := Logger.WithFields(logrus.Fields{"err": TypeString(err)}).WriterLevel(level)
	if e, ok := err.(*errors.Error); ok && Logger.IsLevelEnabled(logrus.DebugLevel) {
		_, _ = writer.Write([]byte(e.ErrorStack()))
	} else {
		_, _ = writer.Write([]byte(fmt.Sprintf("%s", err.Error())))
	}
	return err
}

func LogFatal(err error) error {
	logger := Logger.WithFields(logrus.Fields{"err": TypeString(err)})
	// using log() for this doesn't seem to do anything
	if e, ok := err.(*errors.Error); ok && Logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.Fatal(e.ErrorStack())
	} else {
		logger.Fatalf("%s", err.Error())
	}
	return err
}

func LogError(err error) error {
	return log(logrus.ErrorLevel, err)
}

func LogWarning(err error) error {
	return log(logrus.WarnLevel, err)
}

func LogRequest(typ, proto, method, url, from string, headers http.Header, message []byte) {
	fields := logrus.Fields{
		"type":   typ,
		"proto":  proto,
		"method": method,
		"url":    url,
	}
	if len(headers) > 0 {
		fields["headers"] = headers
	}
	if len(message) > 0 {
		if headers.Get("Content-Type") == "application/octet-stream" {
			fields["message"] = hex.EncodeToString(message)
		} else {
			fields["message"] = string(message)
		}
	}
	if from != "" {
		fields["from"] = from
	}
	Logger.WithFields(fields).Tracef("=> request")
}

func LogResponse(url string, status int, duration time.Duration, binary bool, response []byte) {
	fields := logrus.Fields{
		"status":   status,
		"duration": duration.String(),
	}
	if len(response) > 0 {
		if binary {
			fields["response"] = hex.EncodeToString(response)
		} else {
			fields["response"] = string(response)
		}
	}
	l := Logger.WithFields(fields)
	if status < 400 {
		l.Trace("<= response")
	} else {
		l.WithField("url", url).Warn("<= response")
	}
}

func ToJson(o interface{}) string {
	bts, _ := json.Marshal(o)
	return string(bts)
}

func NewLogger(verbosity int, quiet bool, json bool) *logrus.Logger {
	logger := logrus.New()

	if quiet {
		logger.Out = ioutil.Discard
		return logger
	}

	logger.Level = Verbosity(verbosity)
	if json {
		logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logger.SetFormatter(&prefixed.TextFormatter{
			FullTimestamp: true,
			DisableColors: runtime.GOOS == "windows",
		})
	}

	return logger
}

func SizeLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, PostSizeLimit)
		next.ServeHTTP(w, r)
	})
}

func TimeoutMiddleware(except []string, timeout time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		timeoutNext := http.TimeoutHandler(next, timeout, "")
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, e := range except {
				if strings.HasSuffix(r.URL.Path, e) {
					next.ServeHTTP(w, r)
					return
				}
			}
			timeoutNext.ServeHTTP(w, r)
		})
	}
}

// LogMiddleware is middleware for logging HTTP requests and responses.
func LogMiddleware(typ string, opts LogOptions) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var message []byte
			var err error

			// Read r.Body, and then replace with a fresh ReadCloser for the next handler
			if message, err = ioutil.ReadAll(r.Body); err != nil {
				message = []byte("<failed to read body: " + err.Error() + ">")
			}
			_ = r.Body.Close()
			r.Body = ioutil.NopCloser(bytes.NewBuffer(message))

			var headers http.Header
			var from string
			if opts.Headers {
				headers = r.Header
			}
			if opts.From {
				from = r.RemoteAddr
			}
			LogRequest(typ, r.Proto, r.Method, r.URL.String(), from, headers, message)

			// copy output of HTTP handler to our buffer for later logging
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			var buf *bytes.Buffer
			if opts.Response {
				buf = new(bytes.Buffer)
				ww.Tee(buf)
			}

			// print response afterwards
			var resp []byte
			var start time.Time
			defer func() {
				if ww.Header().Get("Content-Type") == "text/event-stream" {
					return
				}
				if opts.Response && ww.BytesWritten() > 0 {
					resp = buf.Bytes()
				}
				if ww.Status() >= 400 {
					resp = nil // avoid printing stacktraces and SSE in response
				}
				var hexencode bool
				if opts.EncodeBinary && ww.Header().Get("Content-Type") != "application/json" {
					hexencode = true
				}
				LogResponse(r.URL.String(), ww.Status(), time.Since(start), hexencode, resp)
			}()

			// start timer and preform request
			start = time.Now()
			next.ServeHTTP(ww, r)
		})
	}
}

func ParseBody(r *http.Request, input interface{}) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		Logger.WithField("error", err).Info("Malformed request: could not read request body")
		return err
	}

	switch i := input.(type) {
	case *string:
		*i = string(body)
	default:
		if err = json.Unmarshal(body, input); err != nil {
			Logger.WithField("error", err).Info("Malformed request: could not parse request body")
			return err
		}
	}
	return nil
}

func FilterStopError(err error) error {
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
