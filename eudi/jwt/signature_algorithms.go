package eudi_jwt

import (
	"slices"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// supportedSignatureAlgorithms is the single allow-list of JWS signature algorithms this
// module accepts. It is read both when verifying a JWT signature and when deciding whether
// an issuer's advertised signing algorithms are usable, so that a configuration accepted up
// front is one whose signatures can actually be verified afterwards.
//
// Deliberately excluded, and why:
//   - HS256, HS384, HS512: symmetric, so verifying would mean sharing the signing secret with
//     every verifier. Nothing in this module has such a shared secret with an issuer.
//   - none: unsigned.
//   - Ed448: not registered by jwx, and the Go standard library has no Ed448 implementation.
//
// EdDSA is accepted alongside Ed25519. RFC 9864 deprecates the EdDSA name in favour of the
// curve-specific Ed25519 and Ed448 ones, but it remains what issuers publish and sign with in
// practice, and jwx verifies an Ed25519 signature under either name, so refusing it would reject
// tokens this module can verify. The curve is determined by the key, not by the name.
//
// ES256K is accepted only in builds that carry the `jwx_es256k` build tag, because that tag is
// what compiles jwx's secp256k1 support. See secp256k1SignatureAlgorithms.
var supportedSignatureAlgorithms = append([]jwa.SignatureAlgorithm{
	jwa.ES256(),
	jwa.ES384(),
	jwa.ES512(),
	jwa.EdDSA(),
	jwa.EdDSAEd25519(),
	jwa.PS256(),
	jwa.PS384(),
	jwa.PS512(),
	jwa.RS256(),
	jwa.RS384(),
	jwa.RS512(),
}, secp256k1SignatureAlgorithms...)

// SupportedSignatureAlgorithms returns the JWS signature algorithms this module accepts.
func SupportedSignatureAlgorithms() []jwa.SignatureAlgorithm {
	return slices.Clone(supportedSignatureAlgorithms)
}

// IsSupportedSignatureAlgorithm reports whether alg is one this module accepts. Key providers
// call it before handing a key to the verification sink, so that an unsupported or substituted
// algorithm in the protected header cannot be used to verify a signature.
func IsSupportedSignatureAlgorithm(alg jwa.SignatureAlgorithm) bool {
	return slices.Contains(supportedSignatureAlgorithms, alg)
}

// LookupSupportedSignatureAlgorithm resolves a JOSE 'alg' name to an algorithm this module
// accepts. It differs from jwa.LookupSignatureAlgorithm in that a name jwx knows but this
// module does not accept is reported as not found.
func LookupSupportedSignatureAlgorithm(name string) (jwa.SignatureAlgorithm, bool) {
	alg, found := jwa.LookupSignatureAlgorithm(name)
	if !found || !IsSupportedSignatureAlgorithm(alg) {
		return jwa.SignatureAlgorithm{}, false
	}
	return alg, true
}
