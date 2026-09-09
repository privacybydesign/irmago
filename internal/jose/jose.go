// Why this package exists, rather than the jwx jwt package.
//
// The jwx jwt package models a token as a set of dynamically typed claims. The JWTs of the IRMA
// protocol instead have a fixed shape that a Go type already describes, such as ServiceProviderJwt
// or irma.KeyshareEnrollmentClaims. Routing those through jwt.Token would mean converting between
// the struct and a dynamic token on every hop, and would give up the compiler's checking of claim
// names and types on the way. So this package marshals the struct to JSON, hands that to jws as the
// payload, and unmarshals it back on the way in.
//
// The EUDI packages do not use this package. Their tokens are dynamically shaped, so they build and
// read a jwx jwt.Token directly, which is the right tool there. Both halves sit on the same jws
// primitives, so a token produced by one verifies under the other.
//
// KeyFunc makes each caller name the signature algorithm it expects, rather than trusting the "alg"
// of the token being verified. jwx already refuses an algorithm the key cannot support, so this is
// not what stops algorithm substitution; it is what keeps a call site from silently accepting a
// second algorithm its key happens to allow.

// Package jose signs and verifies JWTs whose claims are ordinary Go structs, on top of
// github.com/lestrrat-go/jwx/v4. It treats the JWS payload as JSON to marshal a claims struct into
// and unmarshal it out of, and leaves the JOSE part to jws.
package jose

import (
	"crypto/rsa"
	"encoding/json"
	"maps"
	"reflect"
	"time"

	"github.com/go-errors/errors"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// TypeHeader is the value of the "typ" header of the JWTs produced by Sign.
const TypeHeader = "JWT"

// Validator is implemented by claims types that need to be checked after decoding, for
// example by rejecting a token that has expired. Verify runs it; VerifyWithoutClaimsValidation
// does not.
type Validator interface {
	ValidateClaims(now time.Time) error
}

// KeyFunc returns the algorithm and the key with which a token's signature must be verified.
//
// It receives the protected header of the token. By the time Verify calls it, the claims struct
// Verify was given is already filled in, so a KeyFunc that needs a value from the body, such as
// the public key an enrolment request is signed with, can read it there. Neither the header nor
// those claims are verified yet, so they may only be used to select a key, never as an answer in
// their own right.
type KeyFunc func(headers jws.Headers) (jwa.SignatureAlgorithm, any, error)

// StaticKey returns a KeyFunc that always verifies with alg and key.
func StaticKey(alg jwa.SignatureAlgorithm, key any) KeyFunc {
	return func(jws.Headers) (jwa.SignatureAlgorithm, any, error) {
		return alg, key, nil
	}
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

// Verify verifies the signature of a compact JWS with the key that keyfunc selects, decodes
// its payload into claims, and validates those claims if they implement Validator.
func Verify(token string, claims any, keyfunc KeyFunc) error {
	if err := VerifyWithoutClaimsValidation(token, claims, keyfunc); err != nil {
		return err
	}
	if validator, ok := claims.(Validator); ok {
		return validator.ValidateClaims(time.Now())
	}
	return nil
}

// VerifyWithoutClaimsValidation is Verify without the Validator step, for callers that check
// the time claims themselves, for example to allow for clock drift.
func VerifyWithoutClaimsValidation(token string, claims any, keyfunc KeyFunc) error {
	headers, payload, err := parse(token)
	if err != nil {
		return err
	}
	// Decoding before verifying is what lets keyfunc pick a key by a "kid" header or by a
	// public key carried in the body. The bytes handed to jws.Verify below are the same ones
	// decoded here, so after it returns, claims holds verified content.
	if err := json.Unmarshal(payload, claims); err != nil {
		return errors.WrapPrefix(err, "failed to unmarshal JWT claims", 0)
	}

	alg, key, err := keyfunc(headers)
	if err != nil {
		return err
	}
	if _, err := jws.Verify([]byte(token), jws.WithKey(alg, key)); err != nil {
		return errors.WrapPrefix(err, "failed to verify JWT signature", 0)
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
