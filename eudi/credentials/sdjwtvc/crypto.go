package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type JwtCreator interface {
	CreateSignedJwt(customHeaderFields map[string]string, payload string) (string, error)
}

type DefaultEcdsaJwtCreator struct {
	PrivateKey *ecdsa.PrivateKey
}

func (c *DefaultEcdsaJwtCreator) CreateSignedJwt(customHeaderFields map[string]string, payload string) (string, error) {
	var claims jwt.MapClaims
	err := json.Unmarshal([]byte(payload), &claims)

	if err != nil {
		return "", err
	}

	sdjwt := jwt.NewWithClaims(jwt.SigningMethodES256, &claims)

	for key, value := range customHeaderFields {
		sdjwt.Header[key] = value
	}

	jwt, err := sdjwt.SignedString(c.PrivateKey)
	if err != nil {
		return "", err
	}

	return jwt, nil
}

func ReadEcdsaPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, err
	}

	return x509.ParseECPrivateKey(block.Bytes)
}
