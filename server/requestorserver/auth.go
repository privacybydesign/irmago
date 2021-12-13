package requestorserver

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
)

// Authenticator instances authenticate incoming session requests. Given details of the HTTP
// post done by the requestor, it is checked whether or not the requestor is known and
// allowed to submit session requests.
type Authenticator interface {
	// Initialize is called once on server startup for each requestor that uses this authentication method.
	// Used to parse keys or populate caches for later use.
	Initialize(name string, requestor Requestor) error

	// AuthenticateSession checks, given the HTTP header and POST body, if the authenticator is known
	// and allowed to submit session requests. It returns whether or not the current authenticator
	// is applicable to this sesion requests; the request itself; the name of the requestor;
	// or an error (which is only non-nil if applies is true; i.e. this authenticator applies but
	// it was not able to successfully authenticate the request).
	AuthenticateSession(
		headers http.Header, body []byte,
	) (applies bool, request irma.RequestorRequest, requestor string, err *irma.RemoteError)

	AuthenticateRevocation(
		headers http.Header, body []byte,
	) (applies bool, request *irma.RevocationRequest, requestor string, err *irma.RemoteError)
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
	hmackeys      map[string]interface{}
	maxRequestAge int
}
type PublicKeyAuthenticator struct {
	publickeys    map[string]interface{}
	maxRequestAge int
}
type PresharedKeyAuthenticator struct {
	presharedkeys map[string]string
}
type NilAuthenticator struct{}

var authenticators map[AuthenticationMethod]Authenticator

func (NilAuthenticator) AuthenticateSession(
	headers http.Header, body []byte,
) (bool, irma.RequestorRequest, string, *irma.RemoteError) {
	if headers.Get("Authorization") != "" || !strings.HasPrefix(headers.Get("Content-Type"), "application/json") {
		return false, nil, "", nil
	}
	request, err := server.ParseSessionRequest(body)
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	return true, request, "", nil
}

func (NilAuthenticator) AuthenticateRevocation(headers http.Header, body []byte) (bool, *irma.RevocationRequest, string, *irma.RemoteError) {
	if headers.Get("Authorization") != "" || !strings.HasPrefix(headers.Get("Content-Type"), "application/json") {
		return false, nil, "", nil
	}
	r := &irma.RevocationRequest{}
	if err := irma.UnmarshalValidate(body, r); err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	return true, r, "", nil
}

func (NilAuthenticator) Initialize(name string, requestor Requestor) error {
	return nil
}

func (hauth *HmacAuthenticator) AuthenticateSession(
	headers http.Header, body []byte,
) (applies bool, request irma.RequestorRequest, requestor string, err *irma.RemoteError) {
	return jwtAuthenticate(headers, body, jwt.SigningMethodHS256.Name, hauth.hmackeys, hauth.maxRequestAge)
}

func (hauth *HmacAuthenticator) AuthenticateRevocation(headers http.Header, body []byte) (bool, *irma.RevocationRequest, string, *irma.RemoteError) {
	return jwtAutheticateRevocation(headers, body, jwt.SigningMethodHS256.Name, hauth.hmackeys, hauth.maxRequestAge)
}

func (hauth *HmacAuthenticator) Initialize(name string, requestor Requestor) error {
	bts, err := common.ReadKey(requestor.AuthenticationKey, requestor.AuthenticationKeyFile)
	if err != nil {
		return errors.WrapPrefix(err, "Failed to read key of requestor "+name, 0)
	}

	// We accept any of the base64 encodings
	bts, err = common.Base64Decode(bts)
	if err != nil {
		return errors.WrapPrefix(err, "Failed to base64 decode hmac key of requestor "+name, 0)
	}

	hauth.hmackeys[name] = bts
	return nil

}

func (pkauth *PublicKeyAuthenticator) AuthenticateSession(
	headers http.Header, body []byte,
) (bool, irma.RequestorRequest, string, *irma.RemoteError) {
	return jwtAuthenticate(headers, body, jwt.SigningMethodRS256.Name, pkauth.publickeys, pkauth.maxRequestAge)
}

func (pkauth *PublicKeyAuthenticator) AuthenticateRevocation(headers http.Header, body []byte) (bool, *irma.RevocationRequest, string, *irma.RemoteError) {
	return jwtAutheticateRevocation(headers, body, jwt.SigningMethodRS256.Name, pkauth.publickeys, pkauth.maxRequestAge)
}

func (pkauth *PublicKeyAuthenticator) Initialize(name string, requestor Requestor) error {
	bts, err := common.ReadKey(requestor.AuthenticationKey, requestor.AuthenticationKeyFile)
	if err != nil {
		return errors.WrapPrefix(err, "Failed to read key of requestor "+name, 0)
	}

	pk, err := jwt.ParseRSAPublicKeyFromPEM(bts)
	if err != nil {
		return err
	}
	pkauth.publickeys[name] = pk

	return nil
}

func (pskauth *PresharedKeyAuthenticator) AuthenticateSession(
	headers http.Header, body []byte,
) (bool, irma.RequestorRequest, string, *irma.RemoteError) {
	auth := headers.Get("Authorization")
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

func (pskauth *PresharedKeyAuthenticator) AuthenticateRevocation(headers http.Header, body []byte) (bool, *irma.RevocationRequest, string, *irma.RemoteError) {
	auth := headers.Get("Authorization")
	if auth == "" || !strings.HasPrefix(headers.Get("Content-Type"), "application/json") {
		return false, nil, "", nil
	}
	requestor, ok := pskauth.presharedkeys[auth]
	if !ok {
		return true, nil, "", server.RemoteError(server.ErrorUnauthorized, "")
	}
	r := &irma.RevocationRequest{}
	if err := irma.UnmarshalValidate(body, r); err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	return true, r, requestor, nil
}

func (pskauth *PresharedKeyAuthenticator) Initialize(name string, requestor Requestor) error {
	bts, err := common.ReadKey(requestor.AuthenticationKey, requestor.AuthenticationKeyFile)
	if err != nil {
		return errors.WrapPrefix(err, "Failed to read key of requestor "+name, 0)
	}
	pskauth.presharedkeys[string(bts)] = name
	return nil
}

// Helper functions

// Given an (unauthenticated) jwt, return the key against which it should be verified using the "kid" header
func jwtKeyExtractor(publickeys map[string]interface{}) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		var ok bool
		kid, ok := token.Header["kid"]
		if !ok {
			kid = token.Claims.(*jwt.StandardClaims).Issuer
		}
		requestor, ok := kid.(string)
		if !ok {
			return nil, errors.New("requestor name was not a string")
		}
		token.Claims.(*jwt.StandardClaims).Issuer = requestor
		if pk, ok := publickeys[requestor]; ok {
			return pk, nil
		}
		return nil, errors.Errorf("Unknown requestor: %s", requestor)
	}
}

// jwtAuthenticate is a helper function for JWT-based authenticators that verifies and parses JWTs.
func jwtAuthenticate(
	headers http.Header, body []byte, signatureAlg string, keys map[string]interface{}, maxRequestAge int,
) (bool, irma.RequestorRequest, string, *irma.RemoteError) {
	if !jwtApplies(headers, body, signatureAlg) {
		return false, nil, "", nil
	}

	// Verify JWT signature. We do not yet store the JWT contents here, because we need to know the session type first
	// before we can construct a struct instance of the appropriate type into which to unmarshal the JWT contents.
	claims := &jwt.StandardClaims{}
	requestorJwt := string(body)
	_, err := jwt.ParseWithClaims(requestorJwt, claims, jwtKeyExtractor(keys))
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	if time.Unix(claims.IssuedAt, 0).Add(time.Duration(maxRequestAge) * time.Second).Before(time.Now()) {
		return true, nil, "", server.RemoteError(server.ErrorUnauthorized, "jwt too old")
	}
	if !claims.VerifyIssuedAt(time.Now().Unix(), true) {
		return true, nil, "", server.RemoteError(server.ErrorUnauthorized, "jwt not yet valid")
	}

	// Read JWT contents
	parsedJwt, err := irma.ParseRequestorJwt(claims.Subject, requestorJwt)
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}

	requestor := claims.Issuer // presence is ensured by jwtKeyExtractor
	return true, parsedJwt.RequestorRequest(), requestor, nil
}

func jwtAutheticateRevocation(
	headers http.Header, body []byte, signatureAlg string, keys map[string]interface{}, maxRequestAge int,
) (bool, *irma.RevocationRequest, string, *irma.RemoteError) {
	if !jwtApplies(headers, body, signatureAlg) {
		return false, nil, "", nil
	}
	s := &irma.RevocationJwt{}
	if _, err := jwt.ParseWithClaims(string(body), s, jwtKeyExtractor(keys)); err != nil {
		return false, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	if time.Unix(time.Time(s.IssuedAt).Unix(), 0).Add(time.Duration(maxRequestAge) * time.Second).Before(time.Now()) {
		return true, nil, "", server.RemoteError(server.ErrorUnauthorized, "jwt too old")
	}
	return true, s.Request, s.ServerName, nil
}

func jwtApplies(headers http.Header, body []byte, signatureAlg string) bool {
	// Read JWT and check its type
	if headers.Get("Authorization") != "" || !strings.HasPrefix(headers.Get("Content-Type"), "text/plain") {
		return false
	}

	// We need to establish the signature method with which the JWT was signed. We do this by just
	// inspecting the JWT header here, before the signature is verified (which is done below). I suppose
	// it would be more idiomatic to have the KeyFunc which is fed to jwt.ParseWithClaims() perform this
	// task, but then the KeyFunc would need access to all public keys here instead of the ones belonging
	// to the signature algorithm we are expecting (specified by signatureAlg). Security-wise it makes no
	// difference: either way the alg header is examined before the signature is verified.
	alg, err := jwtSignatureAlg(string(body))
	if err != nil || alg != signatureAlg {
		// If err != nil, ie. we failed to determine the JWT signature algorithm, we assume that the
		// request is not meant for this authenticator. So we don't return err
		return false
	}

	return true
}

func jwtSignatureAlg(j string) (string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(j, &jwt.StandardClaims{})
	if err != nil {
		return "", err
	}
	return token.Method.Alg(), nil
}
