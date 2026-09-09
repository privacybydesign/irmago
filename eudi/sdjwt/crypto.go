package sdjwt

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/privacybydesign/irmago/internal/jose"
)

type JwtCreator interface {
	CreateSignedJwt(customHeaderFields map[string]any, payload string) (string, error)
}

type DefaultEcdsaJwtCreator struct {
	privateKey *ecdsa.PrivateKey
}

func NewJwtCreator(privateKey *ecdsa.PrivateKey) JwtCreator {
	return &DefaultEcdsaJwtCreator{
		privateKey: privateKey,
	}
}

func (c *DefaultEcdsaJwtCreator) CreateSignedJwt(customHeaderFields map[string]any, payload string) (string, error) {
	// The payload is signed as given, so that the disclosure digests in it keep matching the
	// JSON they were computed over.
	if !json.Valid([]byte(payload)) {
		return "", fmt.Errorf("sd-jwt payload is not valid JSON")
	}
	return jose.SignPayload([]byte(payload), jwa.ES256(), c.privateKey, customHeaderFields)
}

type JwtVerifier interface {
	Verify(jwt string, key any, sigAlg jwa.SignatureAlgorithm) (payload []byte, err error)
}

type JwxJwtVerifier struct{}

func NewJwxJwtVerifier() *JwxJwtVerifier {
	return &JwxJwtVerifier{}
}

func (v *JwxJwtVerifier) Verify(jwtString string, keyAny any, sigAlg jwa.SignatureAlgorithm) (payload []byte, err error) {
	return jws.Verify([]byte(jwtString), jws.WithKey(sigAlg, keyAny))
}
