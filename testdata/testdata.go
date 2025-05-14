package testdata

import _ "embed"

//go:embed eudi/holder_ec_priv.pem
var HolderPrivKeyBytes []byte

//go:embed eudi/issuer_ec_priv.pem
var IssuerPrivKeyBytes []byte

//go:embed eudi/holder_ec_pub.jwk
var HolderPubJwkBytes []byte
