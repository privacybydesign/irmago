// Why this package exists, rather than the callers using the jwx jwt package directly.
//
// The jwx jwt package models a token as a set of dynamically typed claims. The JWTs of the IRMA
// protocol instead have a fixed shape that a Go type already describes, such as ServiceProviderJwt
// or irma.KeyshareEnrollmentClaims, and those types are public API that predates jwx. This package
// bridges the two: jwt.Parse does the verifying and the checking of the registered time claims, and
// then the token is re-encoded into the caller's struct.
//
// That re-encode is a marshal and an unmarshal that the earlier jws-only implementation did not do.
// Measured against a 2048-bit RSA verify it costs nothing on the keyshare access token, the JWT
// verified most often here, and about 3µs on the largest one, the ProofP token, whose payload is
// three big.Ints. The signature check dominates either way.
//
// The EUDI packages whose tokens are dynamically shaped, such as sdjwtvc, statuslist, openid4vci
// and proofs, hold a jwt.Token from end to end and do not need the bridge. The ones that decode
// into a struct, openid4vp and sdjwt, come through here like the rest.
//
// KeyFunc makes each caller name the signature algorithm it expects, rather than trusting the "alg"
// of the token being verified. jwx already refuses an algorithm the key cannot support, so this is
// not what stops algorithm substitution; it is what keeps a call site from silently accepting a
// second algorithm its key happens to allow.

// Package jose signs and verifies JWTs whose claims are ordinary Go structs, on top of
// github.com/lestrrat-go/jwx/v4.
package jose

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"maps"
	"reflect"

	"github.com/go-errors/errors"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/lestrrat-go/jwx/v4/jwt"
)

// TypeHeader is the value of the "typ" header of the JWTs produced by Sign.
const TypeHeader = "JWT"

// KeyFunc returns the algorithm and the key with which a token's signature must be verified.
//
// It receives the token's protected header and its payload, both still unverified, so that a token
// can say which key it is signed with. A keyshare enrolment request carries the public key in its
// body, the way a CSR does, and requestor JWTs name their key in the "kid" header. Neither input
// may be used as an answer in its own right, only to pick a key.
type KeyFunc func(headers jws.Headers, payload []byte) (jwa.SignatureAlgorithm, any, error)

// StaticKey returns a KeyFunc that always verifies with alg and key.
func StaticKey(alg jwa.SignatureAlgorithm, key any) KeyFunc {
	return func(jws.Headers, []byte) (jwa.SignatureAlgorithm, any, error) {
		return alg, key, nil
	}
}

// keyProvider adapts a KeyFunc to the interface jwt.Parse expects.
type keyProvider struct {
	keyfunc KeyFunc
}

func (p keyProvider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	alg, key, err := p.keyfunc(sig.ProtectedHeaders(), msg.Payload())
	if err != nil {
		return err
	}
	sink.Key(alg, key)
	return nil
}

// Sign marshals claims to JSON and signs the result into a compact JWS. Entries of
// extraHeaders are added to the protected header, next to the "alg" and "typ" that Sign
// always sets itself.
func Sign(claims any, alg jwa.SignatureAlgorithm, key any, extraHeaders map[string]any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", errors.WrapPrefix(err, "failed to marshal JWT claims", 0)
	}
	return SignPayload(payload, alg, key, extraHeaders)
}

// SignPayload is Sign for a payload that is already serialised, for callers that have one and
// want its bytes signed as they are.
func SignPayload(payload []byte, alg jwa.SignatureAlgorithm, key any, extraHeaders map[string]any) (string, error) {
	fields := map[string]any{"typ": TypeHeader}
	maps.Copy(fields, extraHeaders)
	headers, err := Headers(fields)
	if err != nil {
		return "", err
	}

	signed, err := jws.Sign(payload, jws.WithKey(alg, key, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", errors.WrapPrefix(err, "failed to sign JWT", 0)
	}
	return string(signed), nil
}

// Headers builds a JWS protected header out of a map of field names to values. It goes through
// JSON so that a field that jwx models with a type of its own, such as the certificate chain in
// "x5c", is decoded into that type instead of being refused. A field whose value is nil is left
// out, so that callers can fill the map in unconditionally.
func Headers(fields map[string]any) (jws.Headers, error) {
	// Why the JSON round trip, and why a map at all: jws.Headers.Set refuses a field that jwx
	// models with a type of its own unless it is handed that type, and "x5c" wants a *cert.Chain
	// where every caller here holds a []string. Marshalling the map and unmarshalling it into the
	// header lets jwx do that decoding. This is the one conversion in the signing path beyond
	// marshalling the payload itself, and it costs nothing at the 22 of 25 signing call sites that
	// pass no header at all. Taking a jws.Headers here instead would remove it, at the price of
	// reaching into eudi/utils.ConvertPemCertificateChainToX5cFormat and the sdjwt.JwtCreator
	// interface, which both speak []string.
	headers := jws.NewHeaders()
	present := make(map[string]any, len(fields))
	for name, value := range fields {
		if isNil(value) {
			continue
		}
		present[name] = value
	}
	if len(present) == 0 {
		return headers, nil
	}
	encoded, err := json.Marshal(present)
	if err != nil {
		return nil, errors.WrapPrefix(err, "failed to marshal JWT header", 0)
	}
	if err := json.Unmarshal(encoded, &headers); err != nil {
		return nil, errors.WrapPrefix(err, "failed to build JWT header", 0)
	}
	return headers, nil
}

// isNil reports whether value is nil. A nil slice, map or pointer held in an interface does not
// compare equal to nil, so those are checked for separately.
func isNil(value any) bool {
	if value == nil {
		return true
	}
	switch v := reflect.ValueOf(value); v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// ParseUnverified decodes the payload of a compact JWS into claims and returns its protected
// header, without verifying the signature. The caller is responsible for not trusting the
// result: use it to decide how to verify the token, not as an answer.
func ParseUnverified(token string, claims any) (jws.Headers, error) {
	// This stays on jws rather than jwt.ParseInsecure. There is no signature to check and no
	// claim to validate here, so jwx's jwt layer would only add the re-encode that Verify pays
	// for, and it hands back no protected header, which two of the callers need.
	headers, payload, err := parse(token)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, errors.WrapPrefix(err, "failed to unmarshal JWT claims", 0)
	}
	return headers, nil
}

// SignatureAlgorithm returns the "alg" of a compact JWS without verifying its signature.
func SignatureAlgorithm(token string) (jwa.SignatureAlgorithm, error) {
	headers, _, err := parse(token)
	if err != nil {
		return jwa.EmptySignatureAlgorithm(), err
	}
	alg, ok := headers.Algorithm()
	if !ok {
		return jwa.EmptySignatureAlgorithm(), errors.New("JWT header contains no alg")
	}
	return alg, nil
}

// Verify verifies the signature of a compact JWS with the key that keyfunc selects, checks the
// registered time claims "exp", "nbf" and "iat", and decodes the payload into claims.
//
// The options are the jwx ones, so a caller that wants different checks asks jwx for them:
// jwt.WithValidate(false) to skip them, jwt.WithAcceptableSkew for clock drift,
// jwt.WithRequiredClaim to insist a claim is present.
//
// An expired token comes back as a jwt.TokenExpiredError, which errors.Is recognises through the
// wrapping this function adds.
func Verify(token string, claims any, keyfunc KeyFunc, options ...jwt.ParseOption) error {
	options = append([]jwt.ParseOption{jwt.WithKeyProvider(keyProvider{keyfunc: keyfunc})}, options...)
	parsed, err := jwt.Parse([]byte(token), options...)
	if err != nil {
		return errors.WrapPrefix(err, "failed to verify JWT", 0)
	}
	return decodeToken(parsed, claims)
}

// decodeToken re-encodes a verified token into the caller's claims struct.
func decodeToken(token jwt.Token, claims any) error {
	// jwx holds "aud" as a list, while the claims structs here declare it as a single string,
	// which is how it went out on the wire. Flattening writes a one-element audience back as
	// that string. A multi-valued "aud" still fails to decode, as it did before jwt.Parse.
	token.Options().Enable(jwt.FlattenAudience)
	encoded, err := json.Marshal(token)
	if err != nil {
		return errors.WrapPrefix(err, "failed to re-encode JWT claims", 0)
	}
	if err := json.Unmarshal(encoded, claims); err != nil {
		return errors.WrapPrefix(err, "failed to unmarshal JWT claims", 0)
	}
	return nil
}

// parse splits a compact JWS into its protected header and its payload.
func parse(token string) (jws.Headers, []byte, error) {
	msg, err := jws.Parse([]byte(token), jws.WithCompact())
	if err != nil {
		return nil, nil, errors.WrapPrefix(err, "failed to parse JWT", 0)
	}
	signatures := msg.Signatures()
	if len(signatures) != 1 {
		return nil, nil, errors.Errorf("expected 1 JWT signature, got %d", len(signatures))
	}
	return signatures[0].ProtectedHeaders(), msg.Payload(), nil
}

// ParseRSAPrivateKeyFromPEM parses a PEM encoded RSA private key.
func ParseRSAPrivateKeyFromPEM(bts []byte) (*rsa.PrivateKey, error) {
	return parseRSAKeyFromPEM[*rsa.PrivateKey](bts)
}

// ParseRSAPublicKeyFromPEM parses a PEM encoded RSA public key or certificate.
func ParseRSAPublicKeyFromPEM(bts []byte) (*rsa.PublicKey, error) {
	return parseRSAKeyFromPEM[*rsa.PublicKey](bts)
}

func parseRSAKeyFromPEM[T *rsa.PrivateKey | *rsa.PublicKey](bts []byte) (T, error) {
	var zero T
	key, err := jwk.ParseKey(bts, jwk.WithX509(true))
	if err != nil {
		return zero, errors.WrapPrefix(err, "failed to parse PEM encoded RSA key", 0)
	}
	raw, err := jwk.Export[T](key)
	if err != nil {
		return zero, errors.WrapPrefix(err, "PEM encoded key is not an RSA key of the expected kind", 0)
	}
	return raw, nil
}
