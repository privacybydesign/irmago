//go:build jwx_es256k

package eudi_jwt

import (
	"github.com/jwx-go/es256k/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

// es256kEnabled reports whether this build can sign and verify with ES256K.
const es256kEnabled = true

// secp256k1SignatureAlgorithms adds ES256K to the accepted set. jwx v4 moved secp256k1 support
// out of the main module into this companion package, which registers it (and the ES256K
// algorithm identifier) as an import side effect; a consumer that wants ES256K must still build
// irmago with the `jwx_es256k` tag, so that support is pulled in — see the "Cryptographic
// agility" section of the README.
var secp256k1SignatureAlgorithms = []jwa.SignatureAlgorithm{es256k.ES256K()}
