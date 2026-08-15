package sdjwt

import (
	"crypto/ecdsa"
	"encoding/json"
	"maps"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
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
	var claims jwt.MapClaims
	err := json.Unmarshal([]byte(payload), &claims)

	if err != nil {
		return "", err
	}

	sdjwt := jwt.NewWithClaims(jwt.SigningMethodES256, &claims)
	maps.Copy(sdjwt.Header, customHeaderFields)

	jwt, err := sdjwt.SignedString(c.privateKey)
	if err != nil {
		return "", err
	}

	return jwt, nil
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
