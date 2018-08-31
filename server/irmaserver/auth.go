package irmaserver

import (
	"crypto/rsa"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
)

// Authenticator instances authenticate incoming session requests. Given details of the HTTP
// post done by the requestor, it is checked whether or not the requestor is known and
// allowed to submit session requests.
type Authenticator interface {
	// Initialize is called once on server startup for each requestor that uses this authentication method.
	// Used to parse keys or populate caches for later use.
	Initialize(name string, requestor Requestor) error

	// Authenticate checks, given the HTTP header and POST body, if the authenticator is known
	// and allowed to submit session requests. It returns whether or not the current authenticator
	// is applicable to this sesion requests; the request itself; the name of the requestor;
	// or an error (which is only non-nil if applies is true; i.e. this authenticator applies but
	// it was not able to successfully authenticate the request).
	Authenticate(
		headers http.Header, body []byte,
	) (applies bool, request irma.SessionRequest, requestor string, err *irma.RemoteError)
}

type AuthenticationMethod string

// Currently supported requestor authentication methods
const (
	AuthenticationMethodPublicKey = "publickey"
	AuthenticationMethodPSK       = "psk"
	AuthenticationMethodNone      = "none"
)

type PublicKeyAuthenticator struct {
	publickeys map[string]*rsa.PublicKey
}
type PresharedKeyAuthenticator struct {
	presharedkeys map[string]string
}
type NilAuthenticator struct{}

var authenticators map[AuthenticationMethod]Authenticator

func (NilAuthenticator) Authenticate(
	headers http.Header, body []byte,
) (bool, irma.SessionRequest, string, *irma.RemoteError) {
	if headers.Get("Authentication") != "" || !strings.HasPrefix(headers.Get("Content-Type"), "application/json") {
		return false, nil, "", nil
	}
	request, err := parseRequest(body)
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	return true, request, "", nil
}

func (NilAuthenticator) Initialize(name string, requestor Requestor) error {
	return nil
}

func (pkauth *PublicKeyAuthenticator) Authenticate(
	headers http.Header, body []byte,
) (bool, irma.SessionRequest, string, *irma.RemoteError) {
	if headers.Get("Authorization") != "" || !strings.HasPrefix(headers.Get("Content-Type"), "text/plain") {
		return false, nil, "", nil
	}

	requestorJwt := string(body)
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(requestorJwt, claims, jwtPublicKeyExtractor(pkauth.publickeys))
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	if !claims.VerifyIssuedAt(time.Now().Unix(), true) {
		return true, nil, "", server.RemoteError(server.ErrorUnauthorized, "jwt not yet valid")
	}
	if time.Unix(claims.IssuedAt, 0).Add(10 * time.Minute).Before(time.Now()) { // TODO make configurable
		return true, nil, "", server.RemoteError(server.ErrorUnauthorized, "jwt too old")
	}

	// Read JWT contents
	parsedJwt, err := irma.ParseRequestorJwt(claims.Subject, requestorJwt)
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}

	requestor := token.Header["kid"].(string) // presence in Header and type is already checked by jwtPublicKeyExtractor
	return true, parsedJwt.SessionRequest(), requestor, nil
}

func (pkauth *PublicKeyAuthenticator) Initialize(name string, requestor Requestor) error {
	var bts []byte
	var err error
	if strings.HasPrefix(requestor.AuthenticationKey, "-----BEGIN") {
		bts = []byte(requestor.AuthenticationKey)
	}
	if _, err := os.Stat(requestor.AuthenticationKey); err == nil {
		bts, err = ioutil.ReadFile(requestor.AuthenticationKey)
		if err != nil {
			return err
		}
	}
	if len(bts) == 0 {
		return errors.Errorf("Requestor %s has invalid public key", name)
	}
	pk, err := jwt.ParseRSAPublicKeyFromPEM(bts)
	if err != nil {
		return err
	}
	pkauth.publickeys[name] = pk

	return nil
}

func (pskauth *PresharedKeyAuthenticator) Authenticate(
	headers http.Header, body []byte,
) (bool, irma.SessionRequest, string, *irma.RemoteError) {
	auth := headers.Get("Authentication")
	if auth == "" || !strings.HasPrefix(headers.Get("Content-Type"), "application/json") {
		return false, nil, "", nil
	}
	requestor, ok := pskauth.presharedkeys[auth]
	if !ok {
		return true, nil, "", server.RemoteError(server.ErrorUnauthorized, "")
	}
	request, err := parseRequest(body)
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	return true, request, requestor, nil
}

func (pskauth *PresharedKeyAuthenticator) Initialize(name string, requestor Requestor) error {
	if requestor.AuthenticationKey == "" {
		return errors.Errorf("Requestor %s had no authentication key")
	}
	pskauth.presharedkeys[requestor.AuthenticationKey] = name
	return nil
}

// Helper functions

// Given an (unauthenticated) jwt, return the public key against which it should be verified using the "kid" header
func jwtPublicKeyExtractor(publickeys map[string]*rsa.PublicKey) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		var ok bool
		kid, ok := token.Header["kid"]
		if !ok {
			return nil, errors.New("No kid jwt header found")
		}
		requestor, ok := kid.(string)
		if !ok {
			return nil, errors.New("kid jwt header was not a string")
		}
		if pk, ok := publickeys[requestor]; ok {
			return pk, nil
		}
		return nil, errors.Errorf("Unknown requestor: %s", requestor)
	}
}

func parseRequest(bts []byte) (request irma.SessionRequest, err error) {
	request = &irma.DisclosureRequest{}
	if err = irma.UnmarshalValidate(bts, request); err == nil {
		return request, nil
	}
	request = &irma.SignatureRequest{}
	if err = irma.UnmarshalValidate(bts, request); err == nil {
		return request, nil
	}
	request = &irma.IssuanceRequest{}
	if err = irma.UnmarshalValidate(bts, request); err == nil {
		return request, nil
	}
	return nil, errors.New("Invalid or disabled session type")
}
