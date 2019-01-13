// Package irmaserver is a server allowing IRMA verifiers, issuers or attribute-based signature applications (the requestor) to perform IRMA sessions with irmaclient instances (i.e. the IRMA app). It exposes a RESTful protocol with which the requestor can start and manage the session as well as HTTP endpoints for the irmaclient.
package irmaserver

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
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmarequestor"
)

var (
	serv, clientserv *http.Server
	conf             *Configuration
)

// Start the server. If successful then it will not return until Stop() is called.
func Start(config *Configuration) error {
	if err := Initialize(config); err != nil {
		return err
	}

	bts, _ := json.MarshalIndent(conf, "", "   ")
	conf.Logger.Debug("Configuration: ", string(bts), "\n")

	// Start server(s)
	if conf.separateClientServer() {
		go startClientServer()
	}
	startRequestorServer()

	return nil
}

func startRequestorServer() {
	serv = &http.Server{}
	tlsConf, _ := conf.tlsConfig()
	startServer(serv, Handler(), "Server", conf.ListenAddress, conf.Port, tlsConf)
}

func startClientServer() {
	clientserv = &http.Server{}
	tlsConf, _ := conf.clientTlsConfig()
	startServer(clientserv, ClientHandler(), "Client server", conf.ClientListenAddress, conf.ClientPort, tlsConf)
}

func startServer(s *http.Server, handler http.Handler, name, addr string, port int, tlsConf *tls.Config) {
	fulladdr := fmt.Sprintf("%s:%d", addr, port)
	conf.Logger.Info(name, " listening at ", fulladdr)
	s.Addr = fulladdr
	s.Handler = handler
	var err error
	if tlsConf != nil {
		s.TLSConfig = tlsConf
		// Disable HTTP/2 (see package documentation of http): it breaks server side events :(
		s.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		conf.Logger.Info(name, " TLS enabled")
		err = s.ListenAndServeTLS("", "")
	} else {
		err = s.ListenAndServe()
	}
	if err != http.ErrServerClosed {
		_ = server.LogFatal(err)
	}
}

func Stop() error {
	var err1, err2 error

	// Even if closing serv fails, we want to try closing clientserv
	err1 = serv.Close()
	if clientserv != nil {
		err2 = clientserv.Close()
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

func Initialize(config *Configuration) error {
	conf = config
	if err := irmarequestor.Initialize(conf.Configuration); err != nil {
		return err
	}
	if err := conf.initialize(); err != nil {
		return err
	}
	return nil
}

var corsOptions = cors.Options{
	AllowedOrigins: []string{"*"},
	AllowedHeaders: []string{"Accept", "Authorization", "Content-Type", "Cache-Control"},
	AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodDelete},
}

func ClientHandler() http.Handler {
	router := chi.NewRouter()
	router.Use(cors.New(corsOptions).Handler)

	router.Mount("/irma/", irmarequestor.HttpHandlerFunc())
	return router
}

// Handler returns a http.Handler that handles all IRMA requestor messages
// and IRMA client messages.
func Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(cors.New(corsOptions).Handler)

	if !conf.separateClientServer() {
		// Mount server for irmaclient
		router.Mount("/irma/", irmarequestor.HttpHandlerFunc())
	}

	// Server routes
	router.Post("/session", handleCreate)
	router.Delete("/session/{token}", handleDelete)
	router.Get("/session/{token}/status", handleStatus)
	router.Get("/session/{token}/statusevents", handleStatusEvents)
	router.Get("/session/{token}/result", handleResult)

	// Routes for getting signed JWTs containing the session result. Only work if configuration has a private key
	router.Get("/session/{token}/result-jwt", handleJwtResult)
	router.Get("/session/{token}/getproof", handleJwtProofs) // irma_api_server-compatible JWT

	router.Get("/publickey", handlePublicKey)

	return router
}

func handleCreate(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		conf.Logger.Error("Could not read session request HTTP POST body")
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
		conf.Logger.Warnf("Session request uses unknown authentication method, HTTP headers: %s, HTTP POST body: %s",
			server.ToJson(r.Header), string(body))
		server.WriteError(w, server.ErrorInvalidRequest, "Request could not be authorized")
		return
	}

	// Authorize request: check if the requestor is allowed to verify or issue
	// the requested attributes or credentials
	request = rrequest.SessionRequest()
	if request.Action() == irma.ActionIssuing {
		allowed, reason := conf.CanIssue(requestor, request.(*irma.IssuanceRequest).Credentials)
		if !allowed {
			conf.Logger.Warn("Requestor %s tried to issue credential %s but it is not authorized to; full request: %s",
				requestor, reason, server.ToJson(request))
			server.WriteError(w, server.ErrorUnauthorized, reason)
			return
		}
	}
	disjunctions := request.ToDisclose()
	if len(disjunctions) > 0 {
		allowed, reason := conf.CanVerifyOrSign(requestor, request.Action(), disjunctions)
		if !allowed {
			conf.Logger.Warn("Requestor %s tried to verify attribute %s but it is not authorized to; full request: %s",
				requestor, reason, server.ToJson(request))
			server.WriteError(w, server.ErrorUnauthorized, reason)
			return
		}
	}

	// Everything is authenticated and parsed, we're good to go!
	qr, _, err := irmarequestor.StartSession(rrequest, nil)
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	server.WriteJson(w, qr)
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	res := irmarequestor.GetSessionResult(chi.URLParam(r, "token"))
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}
	server.WriteJson(w, res.Status)
}

func handleStatusEvents(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	conf.Logger.Debug("new client subscribed to server sent events of session " + token)
	if err := irmarequestor.SubscribeServerSentEvents(w, r, token); err != nil {
		server.WriteError(w, server.ErrorUnexpectedRequest, err.Error())
	}
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	err := irmarequestor.CancelSession(chi.URLParam(r, "token"))
	if err != nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
	}
}

func handleResult(w http.ResponseWriter, r *http.Request) {
	res := irmarequestor.GetSessionResult(chi.URLParam(r, "token"))
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}
	server.WriteJson(w, res)
}

func handleJwtResult(w http.ResponseWriter, r *http.Request) {
	if conf.jwtPrivateKey == nil {
		conf.Logger.Warn("Session result JWT requested but no JWT private key is configured")
		server.WriteError(w, server.ErrorUnknown, "JWT signing not supported")
		return
	}

	sessiontoken := chi.URLParam(r, "token")
	res := irmarequestor.GetSessionResult(sessiontoken)
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}

	claims := struct {
		jwt.StandardClaims
		*server.SessionResult
	}{
		SessionResult: res,
	}
	claims.Issuer = conf.JwtIssuer
	claims.IssuedAt = time.Now().Unix()
	claims.Subject = string(res.Type) + "_result"
	validity := irmarequestor.GetRequest(sessiontoken).Base().ResultJwtValidity
	if validity != 0 {
		claims.ExpiresAt = time.Now().Unix() + int64(validity)
	}

	// Sign the jwt and return it
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	resultJwt, err := token.SignedString(conf.jwtPrivateKey)
	if err != nil {
		conf.Logger.Error("Failed to sign session result JWT")
		_ = server.LogError(err)
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, resultJwt)
}

func handleJwtProofs(w http.ResponseWriter, r *http.Request) {
	if conf.jwtPrivateKey == nil {
		conf.Logger.Warn("Session result JWT requested but no JWT private key is configured")
		server.WriteError(w, server.ErrorUnknown, "JWT signing not supported")
		return
	}

	sessiontoken := chi.URLParam(r, "token")
	res := irmarequestor.GetSessionResult(sessiontoken)
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
	if conf.JwtIssuer != "" {
		claims["iss"] = conf.JwtIssuer
	}
	claims["status"] = res.Status
	validity := irmarequestor.GetRequest(sessiontoken).Base().ResultJwtValidity
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
	resultJwt, err := token.SignedString(conf.jwtPrivateKey)
	if err != nil {
		conf.Logger.Error("Failed to sign session result JWT")
		_ = server.LogError(err)
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, resultJwt)
}

func handlePublicKey(w http.ResponseWriter, r *http.Request) {
	if conf.jwtPrivateKey == nil {
		server.WriteError(w, server.ErrorUnsupported, "")
		return
	}

	bts, err := x509.MarshalPKIXPublicKey(&conf.jwtPrivateKey.PublicKey)
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
