//go:build jwx_es256k

package eudi_jwt

import "github.com/lestrrat-go/jwx/v3/jwa"

// es256kEnabled reports whether this build can sign and verify with ES256K.
const es256kEnabled = true

// secp256k1SignatureAlgorithms adds ES256K to the accepted set. jwx compiles its secp256k1
// support only under the `jwx_es256k` build tag, so a consumer that wants ES256K must build
// irmago with that tag; see the "Cryptographic agility" section of the README.
var secp256k1SignatureAlgorithms = []jwa.SignatureAlgorithm{jwa.ES256K()}
