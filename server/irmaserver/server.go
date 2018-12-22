// Package irmaserver is a server allowing IRMA verifiers, issuers or attribute-based signature applications (the requestor) to perform IRMA sessions with irmaclient instances (i.e. the IRMA app). It exposes a RESTful protocol with which the requestor can start and manage the session as well as HTTP endpoints for the irmaclient.
package irmaserver

import (
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
	s    *http.Server
	conf *Configuration
)

// Start the server. If successful then it will not return until Stop() is called.
func Start(config *Configuration) error {
	handler, err := Handler(config)
	if err != nil {
		return err
	}

	// Start server
	addr := config.listenAddress()
	config.Logger.Info("Listening at ", addr)
	s = &http.Server{Addr: addr, Handler: handler}
	err = s.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil // Server was closed normally
	}

	return err
}

func Stop() {
	s.Close()
}

// Handler returns a http.Handler that handles all IRMA requestor messages
// and IRMA client messages.
func Handler(config *Configuration) (http.Handler, error) {
	conf = config
	if err := conf.initialize(); err != nil {
		return nil, err
	}
	if err := irmarequestor.Initialize(conf.Configuration); err != nil {
		return nil, err
	}

	router := chi.NewRouter()

	router.Use(cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedHeaders: []string{"Accept", "Authorization", "Content-Type"},
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodDelete},
	}).Handler)

	// Mount server for irmaclient
	router.Mount("/irma/", irmarequestor.HttpHandlerFunc())

	// Server routes
	router.Post("/session", handleCreate)
	router.Delete("/session/{token}", handleDelete)
	router.Get("/session/{token}/status", handleStatus)
	router.Get("/session/{token}/result", handleResult)

	// Routes for getting signed JWTs containing the session result. Only work if configuration has a private key
	router.Get("/session/{token}/result-jwt", handleJwtResult)
	router.Get("/session/{token}/getproof", handleJwtProofs) // irma_api_server-compatible JWT

	return router, nil
}

func handleCreate(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Authenticate request: check if the requestor is known and allowed to submit requests.
	// We do this by feeding the HTTP POST details to all known authenticators, and see if
	// one of them is applicable and able to authenticate the request.
	var (
		request   irma.SessionRequest
		requestor string
		rerr      *irma.RemoteError
		applies   bool
	)
	for _, authenticator := range authenticators {
		applies, request, requestor, rerr = authenticator.Authenticate(r.Header, body)
		if applies || rerr != nil {
			break
		}
	}
	if rerr != nil {
		server.WriteResponse(w, nil, rerr)
		return
	}
	if !applies {
		server.WriteError(w, server.ErrorInvalidRequest, "Request could not be authorized")
		return
	}

	// Authorize request: check if the requestor is allowed to verify or issue
	// the requested attributes or credentials
	if request.Action() == irma.ActionIssuing {
		allowed, reason := conf.CanIssue(requestor, request.(*irma.IssuanceRequest).Credentials)
		if !allowed {
			server.WriteError(w, server.ErrorUnauthorized, reason)
			return
		}
	}
	disjunctions := request.ToDisclose()
	if len(disjunctions) > 0 {
		allowed, reason := conf.CanVerifyOrSign(requestor, request.Action(), disjunctions)
		if !allowed {
			server.WriteError(w, server.ErrorUnauthorized, reason)
			return
		}
	}

	// Everything is authenticated and parsed, we're good to go!
	qr, _, err := irmarequestor.StartSession(request, nil)
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
		server.WriteError(w, server.ErrorUnknown, "JWT signing not supported")
		return
	}

	res := irmarequestor.GetSessionResult(chi.URLParam(r, "token"))
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

	// Sign the jwt and return it
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	resultJwt, err := token.SignedString(conf.jwtPrivateKey)
	if err != nil {
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, resultJwt)
}

func handleJwtProofs(w http.ResponseWriter, r *http.Request) {
	if conf.jwtPrivateKey == nil {
		server.WriteError(w, server.ErrorUnknown, "JWT signing not supported")
		return
	}

	res := irmarequestor.GetSessionResult(chi.URLParam(r, "token"))
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
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, resultJwt)
}
