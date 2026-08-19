//go:build !jwx_es256k

package eudi_jwt

import "github.com/lestrrat-go/jwx/v4/jwa"

// es256kEnabled reports whether this build can sign and verify with ES256K.
const es256kEnabled = false

// secp256k1SignatureAlgorithms is empty without the `jwx_es256k` build tag: the
// github.com/jwx-go/es256k/v4 companion package that registers ES256K support is never
// imported in this build, so the algorithm is not even known to jwx here, let alone verifiable.
var secp256k1SignatureAlgorithms []jwa.SignatureAlgorithm
