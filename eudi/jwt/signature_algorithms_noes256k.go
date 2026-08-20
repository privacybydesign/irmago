//go:build !jwx_es256k

package eudi_jwt

import "github.com/lestrrat-go/jwx/v3/jwa"

// es256kEnabled reports whether this build can sign and verify with ES256K.
const es256kEnabled = false

// secp256k1SignatureAlgorithms is empty without the `jwx_es256k` build tag: jwx compiles no
// secp256k1 support in this build, so a signature using ES256K could never be verified.
// jwa.LookupSignatureAlgorithm resolves the name regardless of the tag, so accepting it here
// would let a credential configuration through validation only for verification to fail later
// as an opaque signature error rather than an algorithm error.
var secp256k1SignatureAlgorithms []jwa.SignatureAlgorithm
