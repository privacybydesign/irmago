// Package requestorserver is a server allowing IRMA verifiers, issuers or attribute-based signature
// applications (the requestor) to perform IRMA sessions with irmaclient instances (i.e. the IRMA
// app). It exposes a RESTful protocol with which the requestor can start and manage the session as
// well as HTTP endpoints for the irmaclient.
package requestorserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
	"github.com/go-chi/cors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
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
	s.conf.Logger.Info(name, " listening at ", fulladdr, s.conf.ApiPrefix)

	serv := &http.Server{
		Addr:      fulladdr,
		Handler:   handler,
		TLSConfig: tlsConf,
		// See https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
		// Write timeouts are handled per request using middleware (to exclude SSE endpoints)
		ReadTimeout: server.ReadTimeout,
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
		s.conf.Logger.Info(name, " TLS enabled")
		return server.FilterStopError(serv.ListenAndServeTLS("", ""))
	} else {
		return server.FilterStopError(serv.ListenAndServe())
	}
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

func (s *Server) prefixRouter(router *chi.Mux) (prefixedRouter *chi.Mux) {
	prefixedRouter = chi.NewRouter()
	prefixedRouter.Mount(s.conf.ApiPrefix, router)
	return
}

func (s *Server) ClientHandler() http.Handler {
	router := chi.NewRouter()
	router.Use(cors.New(corsOptions).Handler)
	s.attachClientEndpoints(router)
	return s.prefixRouter(router)
}

func (s *Server) attachClientEndpoints(router *chi.Mux) {
	router.Mount("/irma/", s.irmaserv.HandlerFunc())
	if s.conf.StaticPath != "" {
		router.Mount(s.conf.StaticPrefix, s.StaticFilesHandler())
	}
}

// Handler returns a http.Handler that handles all IRMA requestor messages
// and IRMA client messages.
func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(cors.New(corsOptions).Handler)

	if !s.conf.separateClientServer() {
		// Mount server for irmaclient
		s.attachClientEndpoints(router)
	}

	log := server.LogOptions{Response: true, Headers: true, From: true}
	router.NotFound(server.LogMiddleware("requestor", log)(router.NotFoundHandler()).ServeHTTP)
	router.MethodNotAllowed(server.LogMiddleware("requestor", log)(router.MethodNotAllowedHandler()).ServeHTTP)

	// Group main API endpoints, so we can attach our request/response logger to it
	// while not adding it to the endpoints already added above (which do their own logging).

	router.Group(func(r chi.Router) {
		r.Use(server.SizeLimitMiddleware)
		r.Use(server.TimeoutMiddleware([]string{"/statusevents"}, server.WriteTimeout))
		r.Use(cors.New(corsOptions).Handler)
		if s.conf.Verbose >= 2 {
			r.Use(server.LogMiddleware("requestor", log))
		}

		// Server routes
		r.Route("/session", func(r chi.Router) {
			r.Post("/", s.handleCreateSession)
			r.Route("/{requestorToken}", func(r chi.Router) {
				r.Delete("/", s.handleDelete)
				r.Get("/status", s.handleStatus)
				r.Get("/statusevents", s.handleStatusEvents)
				r.Get("/result", s.handleResult)
				// Routes for getting signed JWTs containing the session result. Only work if configuration has a private key
				r.Get("/result-jwt", s.handleJwtResult)
				r.Get("/getproof", s.handleJwtProofs) // irma_api_server-compatible JWT
			})
		})

		r.Get("/publickey", s.handlePublicKey)
	})

	router.Group(func(r chi.Router) {
		r.Use(server.SizeLimitMiddleware)
		r.Use(server.TimeoutMiddleware(nil, server.WriteTimeout))
		r.Use(cors.New(corsOptions).Handler)
		if s.conf.Verbose >= 2 {
			r.Use(server.LogMiddleware("revocation", log))
		}
		r.Post("/revocation", s.handleRevocation)
	})

	return s.prefixRouter(router)
}

func (s *Server) StaticFilesHandler() http.Handler {
	if len(s.conf.URL) > 6 {
		url := s.conf.URL[:len(s.conf.URL)-6] + s.conf.StaticPrefix
		s.conf.Logger.Infof("Hosting files at %s under %s", s.conf.StaticPath, url)
	} else { // URL not known, don't log it but otherwise continue
		s.conf.Logger.Infof("Hosting files at %s", s.conf.StaticPath)
	}
	opts := server.LogOptions{Response: false, Headers: false, From: false}
	return http.StripPrefix(s.conf.StaticPrefix, server.LogMiddleware("static", opts)(
		http.FileServer(http.Dir(s.conf.StaticPath))),
	)
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
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
		requestor string
		rerr      *irma.RemoteError
		applies   bool
	)
	for _, authenticator := range authenticators { // rrequest abbreviates "requestor request"
		applies, rrequest, requestor, rerr = authenticator.AuthenticateSession(r.Header, body)
		if applies || rerr != nil {
			break
		}
	}
	if ok := s.checkAuth(w, r, rerr, applies, body); !ok {
		return
	}

	s.createSession(w, requestor, rrequest)
}

func (s *Server) handleRevocation(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.Error("Could not read revocation request HTTP POST body")
		_ = server.LogError(err)
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	var (
		revreq    *irma.RevocationRequest
		requestor string
		rerr      *irma.RemoteError
		applies   bool
	)
	for _, authenticator := range authenticators {
		applies, revreq, requestor, rerr = authenticator.AuthenticateRevocation(r.Header, body)
		if applies || rerr != nil {
			break
		}
	}
	if ok := s.checkAuth(w, r, rerr, applies, body); !ok {
		return
	}

	s.revoke(w, requestor, revreq)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	requestorToken, err := irma.ParseRequestorToken(chi.URLParam(r, "requestorToken"))
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	res, err := s.irmaserv.GetSessionResult(requestorToken)
	if err != nil {
		if _, ok := err.(irmaserver.UnknownSessionError); ok {
			server.WriteError(w, server.ErrorSessionUnknown, "")
		} else {
			server.WriteError(w, server.ErrorInternal, "")
		}
		return
	}

	server.WriteJson(w, res.Status)
}

func (s *Server) handleStatusEvents(w http.ResponseWriter, r *http.Request) {
	requestorToken := chi.URLParam(r, "requestorToken")
	s.conf.Logger.WithFields(logrus.Fields{"session": requestorToken}).Debug("new client subscribed to server sent events")
	r = r.WithContext(context.WithValue(r.Context(), "sse", common.SSECtx{
		Component: server.ComponentSession,
		Arg:       requestorToken,
	}))
	if err := s.irmaserv.SubscribeServerSentEvents(w, r, requestorToken, true); err != nil {
		server.WriteResponse(w, nil, &irma.RemoteError{
			Status:      server.ErrorUnsupported.Status,
			ErrorName:   string(server.ErrorUnsupported.Type),
			Description: server.ErrorUnsupported.Description,
		})
	}
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	requestorToken, err := irma.ParseRequestorToken(chi.URLParam(r, "requestorToken"))
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	err = s.irmaserv.CancelSession(requestorToken)
	if err != nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
	}
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	requestorToken, err := irma.ParseRequestorToken(chi.URLParam(r, "requestorToken"))
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	res, err := s.irmaserv.GetSessionResult(requestorToken)
	if err != nil {
		if _, ok := err.(irmaserver.UnknownSessionError); ok {
			server.WriteError(w, server.ErrorSessionUnknown, "")
		} else {
			server.WriteError(w, server.ErrorInternal, "")
		}
		return
	}

	if res.LegacySession {
		server.WriteJson(w, res.Legacy())
	} else {
		server.WriteJson(w, res)
	}
}

func (s *Server) handleJwtResult(w http.ResponseWriter, r *http.Request) {
	if s.conf.JwtRSAPrivateKey == nil {
		s.conf.Logger.Warn("Session result JWT requested but no JWT private key is configured")
		server.WriteError(w, server.ErrorUnknown, "JWT signing not supported")
		return
	}

	requestorToken, err := irma.ParseRequestorToken(chi.URLParam(r, "requestorToken"))
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	res, err := s.irmaserv.GetSessionResult(requestorToken)
	if err != nil {
		if _, ok := err.(irmaserver.UnknownSessionError); ok {
			server.WriteError(w, server.ErrorSessionUnknown, "")
		} else {
			server.WriteError(w, server.ErrorInternal, "")
		}
		return
	}

	request, err := s.irmaserv.GetRequest(res.Token)
	if err != nil {
		if _, ok := err.(irmaserver.UnknownSessionError); ok {
			server.WriteError(w, server.ErrorSessionUnknown, "")
		} else {
			server.WriteError(w, server.ErrorInternal, "")
		}
		return
	}

	j, err := server.ResultJwt(res,
		s.conf.JwtIssuer,
		request.Base().ResultJwtValidity,
		s.conf.JwtRSAPrivateKey,
	)
	if err != nil {
		s.conf.Logger.Error("Failed to sign session result JWT")
		_ = server.LogError(err)
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, j)
}

func (s *Server) handleJwtProofs(w http.ResponseWriter, r *http.Request) {
	if s.conf.JwtRSAPrivateKey == nil {
		s.conf.Logger.Warn("Session result JWT requested but no JWT private key is configured")
		server.WriteError(w, server.ErrorUnknown, "JWT signing not supported")
		return
	}

	requestorToken, err := irma.ParseRequestorToken(chi.URLParam(r, "requestorToken"))
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	res, err := s.irmaserv.GetSessionResult(requestorToken)
	if err != nil {
		if _, ok := err.(irmaserver.UnknownSessionError); ok {
			server.WriteError(w, server.ErrorSessionUnknown, "")
		} else {
			server.WriteError(w, server.ErrorInternal, "")
		}
		return
	}

	claims := jwt.MapClaims{}

	// Fill standard claims
	switch res.Type {
	case irma.ActionDisclosing:
		claims["sub"] = "disclosure_result"
	case irma.ActionSigning:
		claims["sub"] = "abs_result"
	case irma.ActionIssuing:
		claims["sub"] = "issue_result"
	default:
		server.WriteError(w, server.ErrorInvalidRequest, "")
		return
	}
	claims["iat"] = time.Now().Unix()
	if s.conf.JwtIssuer != "" {
		claims["iss"] = s.conf.JwtIssuer
	}
	claims["status"] = res.ProofStatus

	request, err := s.irmaserv.GetRequest(requestorToken)
	if err != nil {
		server.WriteError(w, server.ErrorInternal, "")
		return
	}
	validity := request.Base().ResultJwtValidity
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
	resultJwt, err := token.SignedString(s.conf.JwtRSAPrivateKey)
	if err != nil {
		s.conf.Logger.Error("Failed to sign session result JWT")
		_ = server.LogError(err)
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, resultJwt)
}

func (s *Server) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	if s.conf.JwtRSAPrivateKey == nil {
		server.WriteError(w, server.ErrorUnsupported, "")
		return
	}

	bts, err := x509.MarshalPKIXPublicKey(&s.conf.JwtRSAPrivateKey.PublicKey)
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

func (s *Server) doResultCallback(result *server.SessionResult) {
	request, err := s.irmaserv.GetRequest(result.Token)
	if err != nil {
		return
	}

	url := request.Base().CallbackURL
	if url == "" {
		return
	}
	server.DoResultCallback(url,
		result,
		s.conf.JwtIssuer,
		request.Base().ResultJwtValidity,
		s.conf.JwtRSAPrivateKey,
	)
}

func (s *Server) createSession(w http.ResponseWriter, requestor string, rrequest irma.RequestorRequest) {
	// Authorize request: check if the requestor is allowed to verify or issue
	// the requested attributes or credentials
	request := rrequest.SessionRequest()
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

	if rrequest.Base().NextSession != nil && rrequest.Base().NextSession.URL == "" {
		s.conf.Logger.WithFields(logrus.Fields{"requestor": requestor}).Warn("nextSession provided with empty URL")
		server.WriteError(w, server.ErrorInvalidRequest, "nextSession provided with empty URL")
	}
	if s.conf.JwtRSAPrivateKey == nil && !s.conf.AllowUnsignedCallbacks {
		var field string
		if rrequest.Base().CallbackURL != "" {
			field = "callbackUrl"
		} else if rrequest.Base().NextSession != nil {
			field = "nextSession"
		}
		if field != "" {
			errormsg := field + " provided but no JWT private key is installed: either install JWT or enable allow_unsigned_callbacks in configuration"
			s.conf.Logger.WithFields(logrus.Fields{"requestor": requestor}).Warn(errormsg)
			server.WriteError(w, server.ErrorUnsupported, errormsg)
			return
		}
	}

	// Everything is authenticated and parsed, we're good to go!
	qr, requestorToken, frontendRequest, err := s.irmaserv.StartSession(rrequest, s.doResultCallback)
	if err != nil {
		if _, ok := err.(irmaserver.RedisError); ok {
			server.WriteError(w, server.ErrorInternal, "")
		} else {
			server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		}
		return
	}

	server.WriteJson(w, server.SessionPackage{
		SessionPtr:      qr,
		Token:           requestorToken,
		FrontendRequest: frontendRequest,
	})
}

func (s *Server) revoke(w http.ResponseWriter, requestor string, request *irma.RevocationRequest) {
	allowed, reason := s.conf.CanRevoke(requestor, request.CredentialType)
	if !allowed {
		s.conf.Logger.WithFields(logrus.Fields{"requestor": requestor, "message": reason}).
			Warn("Requestor not authorized to revoke credential; full request: ", server.ToJson(request))
		server.WriteError(w, server.ErrorUnauthorized, reason)
		return
	}
	var issued time.Time
	if request.Issued != 0 {
		issued = time.Unix(0, request.Issued)
	}
	if err := s.irmaserv.Revoke(request.CredentialType, request.Key, issued); err != nil {
		if err == irma.ErrUnknownRevocationKey {
			server.WriteError(w, server.ErrorUnknownRevocationKey, request.Key)
		} else {
			server.WriteError(w, server.ErrorRevocation, err.Error())
		}
		return
	}
	server.WriteString(w, "OK")
}

func (s *Server) checkAuth(w http.ResponseWriter, r *http.Request, rerr *irma.RemoteError, applies bool, body []byte) bool {
	if rerr != nil {
		_ = server.LogError(rerr)
		server.WriteResponse(w, nil, rerr)
		return false
	}
	if !applies {
		var ctype = r.Header.Get("Content-Type")
		if !regexp.MustCompile("^application/json").MatchString(ctype) && !regexp.MustCompile("^text/plain").MatchString(ctype) {
			s.conf.Logger.Warnf("Session request uses unsupported Content-Type: %s", ctype)
			server.WriteError(w, server.ErrorInvalidRequest, "Unsupported Content-Type: "+ctype)
			return false
		}
		s.conf.Logger.Warnf("Session request uses unknown authentication method, HTTP headers: %s, HTTP POST body: %s", server.ToJson(r.Header), string(body))
		server.WriteError(w, server.ErrorInvalidRequest, "request could not be authenticated")
		return false
	}
	return true
}
