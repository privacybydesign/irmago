// Package requestorserver is a server allowing IRMA verifiers, issuers or attribute-based signature
// applications (the requestor) to perform IRMA sessions with irmaclient instances (i.e. the IRMA
// app). It exposes a RESTful protocol with which the requestor can start and manage the session as
// well as HTTP endpoints for the irmaclient.
package requestorserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/cors"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

// Server is a requestor server instance.
type Server struct {
	conf     *Configuration
	irmaserv *irmaserver.Server
	stop     chan struct{}
	stopped  chan struct{}
}

// Start the server. If successful then it will not return until Stop() is called.
func (s *Server) Start(config *Configuration) error {
	if s.conf.LogJSON {
		s.conf.Logger.WithField("configuration", s.conf).Debug("Configuration")
	} else {
		bts, _ := json.MarshalIndent(s.conf, "", "   ")
		s.conf.Logger.Debug("Configuration: ", string(bts), "\n")
	}

	// We start either one or two servers, depending on whether a separate client server is enabled, such that:
	// - if any of them returns, the other is also stopped (neither of them is of use without the other)
	// - if any of them returns an unexpected error (ie. other than http.ErrServerClosed), the error is logged and returned
	// - we have a way of stopping all servers from outside (with Stop())
	// - the function returns only after all servers have been stopped
	// - any unexpected error is dealt with here instead of when stopping using Stop().
	// Inspired by https://dave.cheney.net/practical-go/presentations/qcon-china.html#_never_start_a_goroutine_without_when_it_will_stop

	count := 1
	if s.conf.separateClientServer() {
		count = 2
	}
	done := make(chan error, count)
	s.stop = make(chan struct{})
	s.stopped = make(chan struct{}, count)

	if s.conf.separateClientServer() {
		go func() {
			done <- s.startClientServer()
		}()
	}
	go func() {
		done <- s.startRequestorServer()
	}()

	var stopped bool
	var err error
	for i := 0; i < cap(done); i++ {
		if err = <-done; err != nil {
			_ = server.LogError(err)
		}
		if !stopped {
			stopped = true
			close(s.stop)
		}
	}

	return err
}

func (s *Server) startRequestorServer() error {
	tlsConf, _ := s.conf.tlsConfig()
	return s.startServer(s.Handler(), "Server", s.conf.ListenAddress, s.conf.Port, tlsConf)
}

func (s *Server) startClientServer() error {
	tlsConf, _ := s.conf.clientTlsConfig()
	return s.startServer(s.ClientHandler(), "Client server", s.conf.ClientListenAddress, s.conf.ClientPort, tlsConf)
}

func (s *Server) startServer(handler http.Handler, name, addr string, port int, tlsConf *tls.Config) error {
	fulladdr := fmt.Sprintf("%s:%d", addr, port)
	s.conf.Logger.Info(name, " listening at ", fulladdr)

	serv := &http.Server{
		Addr:      fulladdr,
		Handler:   handler,
		TLSConfig: tlsConf,
	}

	go func() {
		<-s.stop
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		if err := serv.Shutdown(ctx); err != nil {
			_ = server.LogError(err)
		}
		s.stopped <- struct{}{}
	}()

	if tlsConf != nil {
		// Disable HTTP/2 (see package documentation of http): it breaks server side events :(
		serv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		s.conf.Logger.Info(name, " TLS enabled")
		return filterStopError(serv.ListenAndServeTLS("", ""))
	} else {
		return filterStopError(serv.ListenAndServe())
	}
}

func filterStopError(err error) error {
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (s *Server) Stop() {
	s.irmaserv.Stop()
	s.stop <- struct{}{}
	<-s.stopped
	if s.conf.separateClientServer() {
		<-s.stopped
	}
}

func New(config *Configuration) (*Server, error) {
	irmaserv, err := irmaserver.New(config.Configuration)
	if err != nil {
		return nil, err
	}
	if err := config.initialize(); err != nil {
		return nil, err
	}
	return &Server{
		conf:     config,
		irmaserv: irmaserv,
	}, nil
}

var corsOptions = cors.Options{
	AllowedOrigins: []string{"*"},
	AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "Cache-Control"},
	AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodDelete},
}

func (s *Server) ClientHandler() http.Handler {
	router := chi.NewRouter()
	router.Use(cors.New(corsOptions).Handler)

	router.Mount("/irma/", s.irmaserv.HandlerFunc())
	if s.conf.StaticPath != "" {
		router.Mount(s.conf.StaticPrefix, s.StaticFilesHandler())
	}

	return router
}

// Handler returns a http.Handler that handles all IRMA requestor messages
// and IRMA client messages.
func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(cors.New(corsOptions).Handler)

	if !s.conf.separateClientServer() {
		// Mount server for irmaclient
		router.Mount("/irma/", s.irmaserv.HandlerFunc())
		if s.conf.StaticPath != "" {
			router.Mount(s.conf.StaticPrefix, s.StaticFilesHandler())
		}
	}

	router.NotFound(s.logHandler("requestor", false, true, true)(router.NotFoundHandler()).ServeHTTP)
	router.MethodNotAllowed(s.logHandler("requestor", false, true, true)(router.MethodNotAllowedHandler()).ServeHTTP)

	// Group main API endpoints, so we can attach our request/response logger to it
	// while not adding it to the endpoints already added above (which do their own logging).
	router.Group(func(r chi.Router) {
		r.Use(cors.New(corsOptions).Handler)
		if s.conf.Verbose >= 2 {
			r.Use(s.logHandler("requestor", true, true, true))
		}

		// Server routes
		r.Post("/session", s.handleCreate)
		r.Delete("/session/{token}", s.handleDelete)
		r.Get("/session/{token}/status", s.handleStatus)
		r.Get("/session/{token}/statusevents", s.handleStatusEvents)
		r.Get("/session/{token}/result", s.handleResult)

		// Routes for getting signed JWTs containing the session result. Only work if configuration has a private key
		r.Get("/session/{token}/result-jwt", s.handleJwtResult)
		r.Get("/session/{token}/getproof", s.handleJwtProofs) // irma_api_server-compatible JWT

		r.Get("/publickey", s.handlePublicKey)
	})

	return router
}

// logHandler is middleware for logging HTTP requests and responses.
func (s *Server) logHandler(typ string, logResponse, logHeaders, logFrom bool) func(next http.Handler) http.Handler {
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
			if logHeaders {
				headers = r.Header
			}
			if logFrom {
				from = r.RemoteAddr
			}
			server.LogRequest(typ, r.Method, r.URL.String(), r.Proto, from, headers, message)

			// copy output of HTTP handler to our buffer for later logging
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			var buf *bytes.Buffer
			if logResponse {
				buf = new(bytes.Buffer)
				ww.Tee(buf)
			}

			// print response afterwards
			var resp []byte
			var start time.Time
			defer func() {
				if logResponse && ww.BytesWritten() > 0 {
					resp = buf.Bytes()
				}
				server.LogResponse(ww.Status(), time.Since(start), resp)
			}()

			// start timer and preform request
			start = time.Now()
			next.ServeHTTP(ww, r)
		})
	}
}

func (s *Server) StaticFilesHandler() http.Handler {
	if len(s.conf.URL) > 6 {
		url := s.conf.URL[:len(s.conf.URL)-6] + s.conf.StaticPrefix
		s.conf.Logger.Infof("Hosting files at %s under %s", s.conf.StaticPath, url)
	} else { // URL not known, don't log it but otherwise continue
		s.conf.Logger.Infof("Hosting files at %s", s.conf.StaticPath)
	}
	return http.StripPrefix(s.conf.StaticPrefix, s.logHandler("static", false, false, false)(
		http.FileServer(http.Dir(s.conf.StaticPath))),
	)
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.Error("Could not read session request HTTP POST body")
		_ = server.LogError(err)
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Authenticate request: check if the requestor is known and allowed to submit requests.
	// We do this by feeding the HTTP POST details to all known authenticators, and see if
	// one of them is applicable and able to authenticate the request.
	var (
		rrequest  irma.RequestorRequest
		request   irma.SessionRequest
		requestor string
		rerr      *irma.RemoteError
		applies   bool
	)
	for _, authenticator := range authenticators { // rrequest abbreviates "requestor request"
		applies, rrequest, requestor, rerr = authenticator.Authenticate(r.Header, body)
		if applies || rerr != nil {
			break
		}
	}
	if rerr != nil {
		_ = server.LogError(rerr)
		server.WriteResponse(w, nil, rerr)
		return
	}
	if !applies {
		s.conf.Logger.Warnf("Session request uses unknown authentication method, HTTP headers: %s, HTTP POST body: %s",
			server.ToJson(r.Header), string(body))
		server.WriteError(w, server.ErrorInvalidRequest, "Request could not be authorized")
		return
	}

	// Authorize request: check if the requestor is allowed to verify or issue
	// the requested attributes or credentials
	request = rrequest.SessionRequest()
	if request.Action() == irma.ActionIssuing {
		allowed, reason := s.conf.CanIssue(requestor, request.(*irma.IssuanceRequest).Credentials)
		if !allowed {
			s.conf.Logger.WithFields(logrus.Fields{"requestor": requestor, "id": reason}).
				Warn("Requestor not authorized to issue credential; full request: ", server.ToJson(request))
			server.WriteError(w, server.ErrorUnauthorized, reason)
			return
		}
	}
	condiscon := request.Disclosure().Disclose
	if len(condiscon) > 0 {
		allowed, reason := s.conf.CanVerifyOrSign(requestor, request.Action(), condiscon)
		if !allowed {
			s.conf.Logger.WithFields(logrus.Fields{"requestor": requestor, "id": reason}).
				Warn("Requestor not authorized to verify attribute; full request: ", server.ToJson(request))
			server.WriteError(w, server.ErrorUnauthorized, reason)
			return
		}
	}
	if rrequest.Base().CallbackUrl != "" && s.conf.jwtPrivateKey == nil {
		s.conf.Logger.WithFields(logrus.Fields{"requestor": requestor}).Warn("Requestor provided callbackUrl but no JWT private key is installed")
		server.WriteError(w, server.ErrorUnsupported, "")
		return
	}

	// Everything is authenticated and parsed, we're good to go!
	qr, token, err := s.irmaserv.StartSession(rrequest, s.doResultCallback)
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	server.WriteJson(w, server.SessionPackage{
		SessionPtr: qr,
		Token:      token,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	res := s.irmaserv.GetSessionResult(chi.URLParam(r, "token"))
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}
	server.WriteJson(w, res.Status)
}

func (s *Server) handleStatusEvents(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	s.conf.Logger.WithFields(logrus.Fields{"session": token}).Debug("new client subscribed to server sent events")
	if err := s.irmaserv.SubscribeServerSentEvents(w, r, token, true); err != nil {
		server.WriteResponse(w, nil, &irma.RemoteError{
			Status:      server.ErrorUnsupported.Status,
			ErrorName:   string(server.ErrorUnsupported.Type),
			Description: server.ErrorUnsupported.Description,
		})
	}
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	err := s.irmaserv.CancelSession(chi.URLParam(r, "token"))
	if err != nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
	}
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	res := s.irmaserv.GetSessionResult(chi.URLParam(r, "token"))
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}
	server.WriteJson(w, res)
}

func (s *Server) handleJwtResult(w http.ResponseWriter, r *http.Request) {
	if s.conf.jwtPrivateKey == nil {
		s.conf.Logger.Warn("Session result JWT requested but no JWT private key is configured")
		server.WriteError(w, server.ErrorUnknown, "JWT signing not supported")
		return
	}

	sessiontoken := chi.URLParam(r, "token")
	res := s.irmaserv.GetSessionResult(sessiontoken)
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}

	j, err := s.resultJwt(res)
	if err != nil {
		s.conf.Logger.Error("Failed to sign session result JWT")
		_ = server.LogError(err)
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, j)
}

func (s *Server) handleJwtProofs(w http.ResponseWriter, r *http.Request) {
	if s.conf.jwtPrivateKey == nil {
		s.conf.Logger.Warn("Session result JWT requested but no JWT private key is configured")
		server.WriteError(w, server.ErrorUnknown, "JWT signing not supported")
		return
	}

	sessiontoken := chi.URLParam(r, "token")
	res := s.irmaserv.GetSessionResult(sessiontoken)
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}

	claims := jwt.MapClaims{}

	// Fill standard claims
	switch res.Type {
	case irma.ActionDisclosing:
		claims["sub"] = "disclosure_result"
	case irma.ActionSigning:
		claims["sub"] = "abs_result"
	default:
		server.WriteError(w, server.ErrorInvalidRequest, "")
		return
	}
	claims["iat"] = time.Now().Unix()
	if s.conf.JwtIssuer != "" {
		claims["iss"] = s.conf.JwtIssuer
	}
	claims["status"] = res.ProofStatus
	validity := s.irmaserv.GetRequest(sessiontoken).Base().ResultJwtValidity
	if validity != 0 {
		claims["exp"] = time.Now().Unix() + int64(validity)
	}

	// Disclosed credentials and possibly signature
	m := make(map[irma.AttributeTypeIdentifier]string, len(res.Disclosed))
	for _, set := range res.Disclosed {
		for _, attr := range set {
			m[attr.Identifier] = attr.Value[""]
		}
	}
	claims["attributes"] = m
	if res.Signature != nil {
		claims["signature"] = res.Signature
	}

	// Sign the jwt and return it
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	resultJwt, err := token.SignedString(s.conf.jwtPrivateKey)
	if err != nil {
		s.conf.Logger.Error("Failed to sign session result JWT")
		_ = server.LogError(err)
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, resultJwt)
}

func (s *Server) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	if s.conf.jwtPrivateKey == nil {
		server.WriteError(w, server.ErrorUnsupported, "")
		return
	}

	bts, err := x509.MarshalPKIXPublicKey(&s.conf.jwtPrivateKey.PublicKey)
	if err != nil {
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bts,
	})
	_, _ = w.Write(pubBytes)
}

func (s *Server) resultJwt(sessionresult *server.SessionResult) (string, error) {
	claims := struct {
		jwt.StandardClaims
		*server.SessionResult
	}{
		StandardClaims: jwt.StandardClaims{
			Issuer:   s.conf.JwtIssuer,
			IssuedAt: time.Now().Unix(),
			Subject:  string(sessionresult.Type) + "_result",
		},
		SessionResult: sessionresult,
	}
	validity := s.irmaserv.GetRequest(sessionresult.Token).Base().ResultJwtValidity
	if validity != 0 {
		claims.ExpiresAt = time.Now().Unix() + int64(validity)
	}

	// Sign the jwt and return it
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.conf.jwtPrivateKey)
}

func (s *Server) doResultCallback(result *server.SessionResult) {
	callbackUrl := s.irmaserv.GetRequest(result.Token).Base().CallbackUrl
	if callbackUrl == "" || s.conf.jwtPrivateKey == nil {
		return
	}
	s.conf.Logger.WithFields(logrus.Fields{"session": result.Token, "callbackUrl": callbackUrl}).Debug("POSTing session result")

	j, err := s.resultJwt(result)
	if err != nil {
		_ = server.LogError(errors.WrapPrefix(err, "Failed to create JWT for result callback", 0))
		return
	}

	var x string // dummy for the server's return value that we don't care about
	if err := irma.NewHTTPTransport(callbackUrl).Post("", &x, j); err != nil {
		// not our problem, log it and go on
		s.conf.Logger.Warn(errors.WrapPrefix(err, "Failed to POST session result to callback URL", 0))
	}
}
