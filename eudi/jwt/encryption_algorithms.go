package eudi_jwt

import (
	"slices"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

// supportedKeyEncryptionAlgorithms is the allow-list of JWE key management algorithms the wallet
// encrypts with: OpenID4VP authorization responses (direct_post.jwt, dc_api.jwt) and OpenID4VCI
// credential requests. In both cases the other party publishes the public key and its `alg`, so
// without this list a verifier or issuer could steer the wallet to any algorithm jwx implements.
//
// Deliberately excluded, and why:
//   - RSA1_5: RSAES-PKCS1-v1_5 is open to padding-oracle attacks (Bleichenbacher), and RFC 8725
//     §3.2 says not to use it.
//   - RSA-OAEP: OAEP with SHA-1. RSA-OAEP-256 and up do the same with SHA-2.
//   - dir, A*KW, A*GCMKW, PBES2-*: symmetric. They need a secret shared with the recipient, and
//     a verifier or issuer publishes a public key, not a shared secret.
//   - HPKE-*: registered by jwx from v4.4.0 on, but JOSE HPKE is still an IETF draft and no
//     OpenID4VC or EUDI profile specifies it, so accepting it is a policy choice not made yet.
//
// ECDH-ES (with P-256) is what HAIP requires; the key-wrapping variants and RSA-OAEP with SHA-2
// are accepted for verifiers and issuers outside that profile.
var supportedKeyEncryptionAlgorithms = []jwa.KeyEncryptionAlgorithm{
	jwa.ECDH_ES(),
	jwa.ECDH_ES_A128KW(),
	jwa.ECDH_ES_A192KW(),
	jwa.ECDH_ES_A256KW(),
	jwa.RSA_OAEP_256(),
	jwa.RSA_OAEP_384(),
	jwa.RSA_OAEP_512(),
}

// supportedContentEncryptionAlgorithms is the allow-list of JWE content encryption algorithms the
// wallet encrypts with. It holds every content encryption algorithm RFC 7518 defines, all of them
// authenticated; the list exists so that one added to jwx later is not accepted without a decision.
var supportedContentEncryptionAlgorithms = []jwa.ContentEncryptionAlgorithm{
	jwa.A128GCM(),
	jwa.A192GCM(),
	jwa.A256GCM(),
	jwa.A128CBC_HS256(),
	jwa.A192CBC_HS384(),
	jwa.A256CBC_HS512(),
}

// SupportedKeyEncryptionAlgorithms returns the JWE key management algorithms the wallet encrypts with.
func SupportedKeyEncryptionAlgorithms() []jwa.KeyEncryptionAlgorithm {
	return slices.Clone(supportedKeyEncryptionAlgorithms)
}

// SupportedContentEncryptionAlgorithms returns the JWE content encryption algorithms the wallet
// encrypts with.
func SupportedContentEncryptionAlgorithms() []jwa.ContentEncryptionAlgorithm {
	return slices.Clone(supportedContentEncryptionAlgorithms)
}

// SupportedKeyEncryptionAlgorithm reports whether alg is a JWE key management algorithm the wallet
// encrypts with, and returns it as one. A key's `alg` is a jwa.KeyAlgorithm, which may also be a
// signature algorithm; those are reported as not supported.
func SupportedKeyEncryptionAlgorithm(alg jwa.KeyAlgorithm) (jwa.KeyEncryptionAlgorithm, bool) {
	keyAlg, ok := alg.(jwa.KeyEncryptionAlgorithm)
	if !ok || !slices.Contains(supportedKeyEncryptionAlgorithms, keyAlg) {
		return jwa.KeyEncryptionAlgorithm{}, false
	}
	return keyAlg, true
}

// LookupSupportedContentEncryptionAlgorithm resolves a JOSE `enc` name to a content encryption
// algorithm the wallet encrypts with. It differs from jwa.LookupContentEncryptionAlgorithm in that
// a name jwx knows but the wallet does not accept is reported as not found.
func LookupSupportedContentEncryptionAlgorithm(name string) (jwa.ContentEncryptionAlgorithm, bool) {
	alg, found := jwa.LookupContentEncryptionAlgorithm(name)
	if !found || !slices.Contains(supportedContentEncryptionAlgorithms, alg) {
		return jwa.ContentEncryptionAlgorithm{}, false
	}
	return alg, true
}
