package irmaserver

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-chi/chi"
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
	s = &http.Server{Addr: fmt.Sprintf(":%d", config.Port), Handler: handler}
	err = s.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil // Server was closed normally
	}

	return err
}

func Stop() {
	s.Close()
}

func Handler(config *Configuration) (http.Handler, error) {
	conf = config
	if err := irmarequestor.Initialize(conf.Configuration); err != nil {
		return nil, err
	}
	if err := conf.initialize(); err != nil {
		return nil, err
	}

	router := chi.NewRouter()

	// Mount server for irmaclient
	router.Mount("/irma/", irmarequestor.HttpHandlerFunc("/irma/"))

	// Server routes
	router.Post("/create", handleCreate)
	router.Get("/status/{token}", handleStatus)
	router.Get("/result/{token}", handleResult)
	router.Get("/result-jwt/{token}", handleJwtResult)
	router.Get("/getproof/{token}", handleJwtProofs)

	return router, nil
}

func handleCreate(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Authenticate request: check if the requestor is known and allowed to submit requests
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
	disjunctions := request.ToDisclose()
	if request.Action() == irma.ActionIssuing {
		allowed, reason := conf.CanIssue(requestor, request.(*irma.IssuanceRequest).Credentials)
		if !allowed {
			server.WriteError(w, server.ErrorUnauthorized, reason)
			return
		}
	}
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

func handleResult(w http.ResponseWriter, r *http.Request) {
	res := irmarequestor.GetSessionResult(chi.URLParam(r, "token"))
	if res == nil {
		server.WriteError(w, server.ErrorSessionUnknown, "")
		return
	}
	server.WriteJson(w, res)
}

func handleJwtResult(w http.ResponseWriter, r *http.Request) {
	if conf.privateKey == nil {
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
	resultJwt, err := token.SignedString(conf.privateKey)
	if err != nil {
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, resultJwt)
}

func handleJwtProofs(w http.ResponseWriter, r *http.Request) {
	if conf.privateKey == nil {
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
	resultJwt, err := token.SignedString(conf.privateKey)
	if err != nil {
		server.WriteError(w, server.ErrorUnknown, err.Error())
		return
	}
	server.WriteString(w, resultJwt)
}
