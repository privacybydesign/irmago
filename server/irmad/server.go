// Package irmaserver is a server allowing IRMA verifiers, issuers or attribute-based signature applications (the requestor) to perform IRMA sessions with irmaclient instances (i.e. the IRMA app). It exposes a RESTful protocol with which the requestor can start and manage the session as well as HTTP endpoints for the irmaclient.
package irmad

import (
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
	"github.com/go-chi/cors"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmarequestor"
	"github.com/sirupsen/logrus"
)

type Server struct {
	serv, clientserv *http.Server
	conf             *Configuration
	irmaserv         *irmarequestor.Server
}

// Start the server. If successful then it will not return until Stop() is called.
func (s *Server) Start(config *Configuration) error {
	if s.conf.LogJSON {
		s.conf.Logger.WithField("configuration", s.conf).Debug("Configuration")
	} else {
		bts, _ := json.MarshalIndent(s.conf, "", "   ")
		s.conf.Logger.Debug("Configuration: ", string(bts), "\n")
	}

	// Start server(s)
	if s.conf.separateClientServer() {
		go s.startClientServer()
	}
	s.startRequestorServer()

	return nil
}

func (s *Server) startRequestorServer() {
	s.serv = &http.Server{}
	tlsConf, _ := s.conf.tlsConfig()
	s.startServer(s.serv, s.Handler(), "Server", s.conf.ListenAddress, s.conf.Port, tlsConf)
}

func (s *Server) startClientServer() {
	s.clientserv = &http.Server{}
	tlsConf, _ := s.conf.clientTlsConfig()
	s.startServer(s.clientserv, s.ClientHandler(), "Client server", s.conf.ClientListenAddress, s.conf.ClientPort, tlsConf)
}

func (s *Server) startServer(serv *http.Server, handler http.Handler, name, addr string, port int, tlsConf *tls.Config) {
	fulladdr := fmt.Sprintf("%s:%d", addr, port)
	s.conf.Logger.Info(name, " listening at ", fulladdr)
	serv.Addr = fulladdr
	serv.Handler = handler
	var err error
	if tlsConf != nil {
		serv.TLSConfig = tlsConf
		// Disable HTTP/2 (see package documentation of http): it breaks server side events :(
		serv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		s.conf.Logger.Info(name, " TLS enabled")
		err = serv.ListenAndServeTLS("", "")
	} else {
		err = serv.ListenAndServe()
	}
	if err != http.ErrServerClosed {
		_ = server.LogFatal(err)
	}
}

func (s *Server) Stop() error {
	var err1, err2 error

	// Even if closing serv fails, we want to try closing clientserv
	err1 = s.serv.Close()
	if s.clientserv != nil {
		err2 = s.clientserv.Close()
	}

	// Now check errors
	if err1 != nil && err1 != http.ErrServerClosed {
		return err1
	}
	if err2 != nil && err2 != http.ErrServerClosed {
		return err2
	}
	return nil
}

func New(config *Configuration) (*Server, error) {
	irmaserv, err := irmarequestor.New(config.Configuration)
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

	router.Mount("/irma/", s.irmaserv.HttpHandlerFunc())
	return router
}

// Handler returns a http.Handler that handles all IRMA requestor messages
// and IRMA client messages.
func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(cors.New(corsOptions).Handler)

	if !s.conf.separateClientServer() {
		// Mount server for irmaclient
		router.Mount("/irma/", s.irmaserv.HttpHandlerFunc())
	}

	// Server routes
	router.Post("/session", s.handleCreate)
	router.Delete("/session/{token}", s.handleDelete)
	router.Get("/session/{token}/status", s.handleStatus)
	router.Get("/session/{token}/statusevents", s.handleStatusEvents)
	router.Get("/session/{token}/result", s.handleResult)

	// Routes for getting signed JWTs containing the session result. Only work if configuration has a private key
	router.Get("/session/{token}/result-jwt", s.handleJwtResult)
	router.Get("/session/{token}/getproof", s.handleJwtProofs) // irma_api_server-compatible JWT

	router.Get("/publickey", s.handlePublicKey)

	return router
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
	for _, authenticator := range authenticators {
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
	disjunctions := request.ToDisclose()
	if len(disjunctions) > 0 {
		allowed, reason := s.conf.CanVerifyOrSign(requestor, request.Action(), disjunctions)
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
	qr, _, err := s.irmaserv.StartSession(rrequest, s.doResultCallback)
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	server.WriteJson(w, qr)
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
	if err := s.irmaserv.SubscribeServerSentEvents(w, r, token); err != nil {
		server.WriteError(w, server.ErrorUnexpectedRequest, err.Error())
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
		claims["subject"] = "verification_result"
	case irma.ActionSigning:
		claims["subject"] = "abs_result"
	default:
		if res == nil {
			server.WriteError(w, server.ErrorInvalidRequest, "")
			return
		}
	}
	claims["iat"] = time.Now().Unix()
	if s.conf.JwtIssuer != "" {
		claims["iss"] = s.conf.JwtIssuer
	}
	claims["status"] = res.Status
	validity := s.irmaserv.GetRequest(sessiontoken).Base().ResultJwtValidity
	if validity != 0 {
		claims["exp"] = time.Now().Unix() + int64(validity)
	}

	// Disclosed credentials and possibly signature
	m := make(map[irma.AttributeTypeIdentifier]string, len(res.Disclosed))
	for _, attr := range res.Disclosed {
		m[attr.Identifier] = attr.Value[""]
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
