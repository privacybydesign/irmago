package requestorserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/jose"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server"
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
	hmackeys      map[string]any
	maxRequestAge int
}
type PublicKeyAuthenticator struct {
	publickeys    map[string]any
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
	return jwtAuthenticate(headers, body, jwa.HS256(), hauth.hmackeys, hauth.maxRequestAge)
}

func (hauth *HmacAuthenticator) AuthenticateRevocation(headers http.Header, body []byte) (bool, *irma.RevocationRequest, string, *irma.RemoteError) {
	return jwtAutheticateRevocation(headers, body, jwa.HS256(), hauth.hmackeys, hauth.maxRequestAge)
}

func (hauth *HmacAuthenticator) Initialize(name string, requestor Requestor) error {
	bts, err := common.ReadKey(requestor.AuthenticationKey, requestor.AuthenticationKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read key of requestor %s: %w", name, err)
	}

	// We accept any of the base64 encodings
	bts, err = common.Base64Decode(bts)
	if err != nil {
		return fmt.Errorf("failed to base64 decode hmac key of requestor %s: %w", name, err)
	}

	hauth.hmackeys[name] = bts
	return nil

}

func (pkauth *PublicKeyAuthenticator) AuthenticateSession(
	headers http.Header, body []byte,
) (bool, irma.RequestorRequest, string, *irma.RemoteError) {
	return jwtAuthenticate(headers, body, jwa.RS256(), pkauth.publickeys, pkauth.maxRequestAge)
}

func (pkauth *PublicKeyAuthenticator) AuthenticateRevocation(headers http.Header, body []byte) (bool, *irma.RevocationRequest, string, *irma.RemoteError) {
	return jwtAutheticateRevocation(headers, body, jwa.RS256(), pkauth.publickeys, pkauth.maxRequestAge)
}

func (pkauth *PublicKeyAuthenticator) Initialize(name string, requestor Requestor) error {
	bts, err := common.ReadKey(requestor.AuthenticationKey, requestor.AuthenticationKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read key of requestor %s: %w", name, err)
	}

	pk, err := jose.ParseRSAPublicKeyFromPEM(bts)
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
		return fmt.Errorf("failed to read key of requestor %s: %w", name, err)
	}
	pskauth.presharedkeys[string(bts)] = name
	return nil
}

// Helper functions

// Given an (unauthenticated) jwt, return the key against which it should be verified using the
// "kid" header, falling back to the "iss" claim. The name the key was found under is reported
// through requestor, because that is what identifies the requestor further on, and it is not
// always the "iss" the verified token ends up carrying.
func jwtKeyExtractor(alg jwa.SignatureAlgorithm, requestor *string, publickeys map[string]any) jose.KeyFunc {
	return func(headers jws.Headers, payload []byte) (jwa.SignatureAlgorithm, any, error) {
		name, ok := headers.KeyID()
		if !ok {
			var unverified irma.RegisteredClaims
			if err := json.Unmarshal(payload, &unverified); err != nil {
				return jwa.EmptySignatureAlgorithm(), nil, err
			}
			name = unverified.Issuer
		}
		*requestor = name
		if pk, ok := publickeys[name]; ok {
			return alg, pk, nil
		}
		return jwa.EmptySignatureAlgorithm(), nil, errors.Errorf("Unknown requestor: %s", name)
	}
}

// jwtAuthenticate is a helper function for JWT-based authenticators that verifies and parses JWTs.
func jwtAuthenticate(
	headers http.Header, body []byte, signatureAlg jwa.SignatureAlgorithm, keys map[string]any, maxRequestAge int,
) (bool, irma.RequestorRequest, string, *irma.RemoteError) {
	if !jwtApplies(headers, body, signatureAlg) {
		return false, nil, "", nil
	}

	validatedJwt, claims, validationErr := jwtValidateClaims(body, signatureAlg, keys, maxRequestAge)
	if validationErr != nil {
		return true, nil, "", validationErr
	}

	// Read JWT contents
	parsedJwt, err := irma.ParseRequestorJwt(claims.Subject, validatedJwt)
	if err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}

	requestor := claims.Issuer // presence is ensured by jwtKeyExtractor
	return true, parsedJwt.RequestorRequest(), requestor, nil
}

func jwtAutheticateRevocation(
	headers http.Header, body []byte, signatureAlg jwa.SignatureAlgorithm, keys map[string]any, maxRequestAge int,
) (bool, *irma.RevocationRequest, string, *irma.RemoteError) {
	if !jwtApplies(headers, body, signatureAlg) {
		return false, nil, "", nil
	}

	validatedJwt, _, validationErr := jwtValidateClaims(body, signatureAlg, keys, maxRequestAge)
	if validationErr != nil {
		return true, nil, "", validationErr
	}

	// Read JWT contents
	revocationJwt := &irma.RevocationJwt{}
	if _, err := jose.ParseUnverified(validatedJwt, revocationJwt); err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	if err := revocationJwt.Request.Validate(); err != nil {
		return true, nil, "", server.RemoteError(server.ErrorInvalidRequest, "Invalid JWT body")
	}
	return true, revocationJwt.Request, revocationJwt.ServerName, nil
}

func jwtValidateClaims(
	body []byte, signatureAlg jwa.SignatureAlgorithm, keys map[string]any, maxRequestAge int,
) (string, *irma.RegisteredClaims, *irma.RemoteError) {
	// Verify JWT signature. We do not yet store the JWT contents here, because we need to know the session type first
	// before we can construct a struct instance of the appropriate type into which to unmarshal the JWT contents.
	claims := &irma.RegisteredClaims{}
	requestorJwt := string(body)
	var requestor string
	if err := jose.Verify(requestorJwt, claims, jwtKeyExtractor(signatureAlg, &requestor, keys)); err != nil {
		return "", nil, server.RemoteError(server.ErrorInvalidRequest, err.Error())
	}
	claims.Issuer = requestor

	// A JWT without an iat is treated as one issued at the epoch, so it is refused as too old.
	var issuedAt time.Time
	if claims.IssuedAt != nil {
		issuedAt = claims.IssuedAt.Time
	}
	if issuedAt.Add(time.Duration(maxRequestAge) * time.Second).Before(time.Now()) {
		return "", nil, server.RemoteError(server.ErrorUnauthorized, "jwt too old")
	}
	if issuedAt.After(time.Now()) {
		return "", nil, server.RemoteError(server.ErrorUnauthorized, "jwt not yet valid")
	}

	return requestorJwt, claims, nil
}

func jwtApplies(headers http.Header, body []byte, signatureAlg jwa.SignatureAlgorithm) bool {
	// Read JWT and check its type
	if headers.Get("Authorization") != "" || !strings.HasPrefix(headers.Get("Content-Type"), "text/plain") {
		return false
	}

	// We need to establish the signature method with which the JWT was signed. We do this by just
	// inspecting the JWT header here, before the signature is verified (which is done below). I suppose
	// it would be more idiomatic to have the KeyFunc which is fed to jose.Verify() perform this
	// task, but then the KeyFunc would need access to all public keys here instead of the ones belonging
	// to the signature algorithm we are expecting (specified by signatureAlg). Security-wise it makes no
	// difference: either way the alg header is examined before the signature is verified.
	alg, err := jose.SignatureAlgorithm(string(body))
	if err != nil || alg != signatureAlg {
		// If err != nil, ie. we failed to determine the JWT signature algorithm, we assume that the
		// request is not meant for this authenticator. So we don't return err
		return false
	}

	return true
}
