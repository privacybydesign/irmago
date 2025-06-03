package testdata

import (
	_ "embed"
	"log"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

//go:embed eudi/holder_ec_priv.pem
var HolderPrivKeyBytes []byte

//go:embed eudi/holder_ec_pub.jwk
var HolderPubJwkBytes []byte

//go:embed eudi/issuer_ec_priv.pem
var IssuerPrivKeyBytes []byte

//go:embed eudi/issuer_ec_pub.jwk
var IssuerPubJwkBytes []byte

//go:embed eudi/issuer_cert_openid4vc_staging_yivi_app.pem
var IssuerCert_openid4vc_staging_yivi_app_Bytes []byte

//go:embed eudi/issuer_cert_irma_app.pem
var IssuerCert_irma_app_Bytes []byte

func ParseHolderPubJwk() jwk.Key {
	key, err := jwk.ParseKey(HolderPubJwkBytes)
	if err != nil {
		log.Fatalf("failed to parse holder pub key jwk: %v", err)
	}
	return key
}

func ParseIssuerPubJwk() jwk.Key {
	key, err := jwk.ParseKey(IssuerPubJwkBytes)
	if err != nil {
		log.Fatalf("failed to parse issuer pub key jwk: %v", err)
	}
	return key
}
