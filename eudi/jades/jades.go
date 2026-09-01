// Package jades produces and checks compact JAdES Baseline B signatures
// (ETSI TS 119 182-1).
//
// A JAdES signature is a JWS carrying ETSI-defined header parameters, so it
// verifies with ordinary JWS machinery. Baseline B is the lowest of four levels and
// carries no time-stamp: the signer's own claim about when it signed is all there
// is, so a document relying on it needs its own freshness mechanism. The level is
// in the function names, so B-T and B-LTA are absent rather than representable.
//
// Two things JAdES does not own, and so are the caller's:
//
//   - `typ`. Clause 6.3 leaves any header parameter JAdES does not profile
//     unconstrained, so the payload's media type belongs to the format being
//     carried.
//   - Trust anchors. This package reports which certificate signed; whether that
//     certificate is anchored is decided elsewhere.
package jades

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

const (
	// IatHeader carries the claimed signing time (clause 5.1.11): an integer
	// NumericDate, no fractions. jwx has no constant for it, because `iat` is a JWT
	// claim everywhere except JAdES, which puts it in the protected header.
	IatHeader = "iat"

	// SigTHeader is the pre-2025-07-15 spelling (clause 5.2.1), a string
	// date-time. Accepted on verification, never emitted.
	SigTHeader = "sigT"
)

// SignatureAlgorithmFor picks the JWS algorithm for a signing key. Every case
// satisfies clause 5.1.2 and clause 6.2.1, and an unsupported key is an error
// rather than a fallback, so there is no path to a weak signature.
//
// It decides on the public key, so an opaque crypto.Signer — a key in an HSM, a
// PKCS#11 token or a cloud KMS, which never hands out its private half — signs
// the same as an in-memory one. That is what makes moving the list signer to
// hardware a constructor swap rather than a rewrite.
func SignatureAlgorithmFor(key crypto.Signer) (jwa.SignatureAlgorithm, error) {
	if key == nil {
		return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported key type: no key")
	}
	switch public := key.Public().(type) {
	case *ecdsa.PublicKey:
		switch public.Curve {
		case elliptic.P256():
			return jwa.ES256(), nil
		case elliptic.P384():
			return jwa.ES384(), nil
		case elliptic.P521():
			return jwa.ES512(), nil
		}
		return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported EC curve %s", public.Curve.Params().Name)
	case *rsa.PublicKey:
		return jwa.RS256(), nil
	}
	return jwa.SignatureAlgorithm{}, fmt.Errorf("unsupported key type %T", key.Public())
}
