package irmaserver

import (
	"encoding/base64"
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
	AuthenticationMethodHmac      = "hmac"
	AuthenticationMethodPublicKey = "publickey"
	AuthenticationMethodToken     = "token"
	AuthenticationMethodNone      = "none"
)

type HmacAuthenticator struct {
	hmackeys map[string]interface{}
}
type PublicKeyAuthenticator struct {
	publickeys map[string]interface{}
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
	request, err := server.ParseSessionRequest(body)
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	return true, request, "", nil
}

func (NilAuthenticator) Initialize(name string, requestor Requestor) error {
	return nil
}

func (hauth *HmacAuthenticator) Authenticate(
	headers http.Header, body []byte,
) (applies bool, request irma.SessionRequest, requestor string, err *irma.RemoteError) {
	return jwtAuthenticate(headers, body, jwt.SigningMethodHS256.Name, hauth.hmackeys)
}

func (hauth *HmacAuthenticator) Initialize(name string, requestor Requestor) error {
	if requestor.AuthenticationKey == "" {
		return errors.Errorf("Requestor %s has no authentication key", name)
	}

	var err error
	var bts []byte
	// We accept any of the base64 encodings
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, encoding := range encodings {
		err = nil
		if bts, err = encoding.DecodeString(requestor.AuthenticationKey); err == nil {
			break
		}
	}
	if err != nil {
		return errors.WrapPrefix(err, "Failed to base64 decode hmac key of requestor "+name, 0)
	}

	hauth.hmackeys[name] = bts
	return nil

}

func (pkauth *PublicKeyAuthenticator) Authenticate(
	headers http.Header, body []byte,
) (bool, irma.SessionRequest, string, *irma.RemoteError) {
	return jwtAuthenticate(headers, body, jwt.SigningMethodRS256.Name, pkauth.publickeys)
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
	request, err := server.ParseSessionRequest(body)
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	return true, request, requestor, nil
}

func (pskauth *PresharedKeyAuthenticator) Initialize(name string, requestor Requestor) error {
	if requestor.AuthenticationKey == "" {
		return errors.Errorf("Requestor %s has no authentication key", name)
	}
	pskauth.presharedkeys[requestor.AuthenticationKey] = name
	return nil
}

// Helper functions

// Given an (unauthenticated) jwt, return the key against which it should be verified using the "kid" header
func jwtKeyExtractor(publickeys map[string]interface{}) func(token *jwt.Token) (interface{}, error) {
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

// jwtAuthenticate is a helper function for JWT-based authenticators that verifies and parses JWTs.
func jwtAuthenticate(
	headers http.Header, body []byte, signatureAlg string, keys map[string]interface{},
) (bool, irma.SessionRequest, string, *irma.RemoteError) {
	// Read JWT and check its type
	if headers.Get("Authorization") != "" || !strings.HasPrefix(headers.Get("Content-Type"), "text/plain") {
		return false, nil, "", nil
	}
	requestorJwt := string(body)

	// We need to establish the signature method with which the JWT was signed. We do this by just
	// inspecting the JWT header here, before the signature is verified (which is done below). I suppose
	// it would be more idiomatic to have the KeyFunc which is fed to jwt.ParseWithClaims() perform this
	// task, but then the KeyFunc would need access to all public keys here instead of the ones belonging
	// to the signature algorithm we are expecting (specified by signatureAlg). Security-wise it makes no
	// difference: either way the alg header is examined before the signature is verified.
	alg, err := jwtSignatureAlg(requestorJwt)
	if err != nil || alg != signatureAlg {
		// If err != nil, ie. we failed to determine the JWT signature algorithm, we assume that the
		// request is not meant for this authenticator. So we don't return err
		return false, nil, "", nil
	}

	// Verify JWT signature. We do not yet store the JWT contents here, because we need to know the session type first
	// before we can construct a struct instance of the appropriate type into which to unmarshal the JWT contents.
	claims := &jwt.StandardClaims{}
	token, err := jwt.ParseWithClaims(requestorJwt, claims, jwtKeyExtractor(keys))
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

	requestor := token.Header["kid"].(string) // presence in Header and type is already checked by jwtKeyExtractor
	return true, parsedJwt.SessionRequest(), requestor, nil
}

func jwtSignatureAlg(j string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(j, &jwt.StandardClaims{})
	if err != nil {
		return "", err
	}
	return token.Method.Alg(), nil
}
