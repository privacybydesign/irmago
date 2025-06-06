package sdjwtvc

import "github.com/lestrrat-go/jwx/v3/jwk"

type IssuerMetadata struct {
	// The issuer identifier, MUST be identical to the `iss` field in the issuer signed jwt
	Issuer string `json:"issuer"`

	// Jwks pub keys of the issuer
	Jwks jwk.Set `json:"jwks"`
}
