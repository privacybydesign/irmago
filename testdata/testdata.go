package testdata

import (
	_ "embed"
	"encoding/json"
)

//go:embed eudi/holder_ec_priv.pem
var HolderPrivKeyBytes []byte

//go:embed eudi/issuer_ec_priv.pem
var IssuerPrivKeyBytes []byte

//go:embed eudi/holder_ec_pub.jwk
var HolderPubJwkBytes []byte

func ParseHolderPubJwk() (result map[string]any) {
	json.Unmarshal(HolderPubJwkBytes, &result)
	return result
}
