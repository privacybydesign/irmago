package sdjwtvc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/privacybydesign/irmago/testdata"
)

type JwtCreator interface {
	CreateSignedJwt(customHeaderFields map[string]string, payload string) (string, error)
}

type DefaultEcdsaJwtCreator struct {
	key *ecdsa.PrivateKey
}

func NewDefaultEcdsaJwtCreatorWithHolderPrivateKey() (JwtCreator, error) {
	key, err := DecodeEcdsaPrivateKey(testdata.HolderPrivKeyBytes)
	return &DefaultEcdsaJwtCreator{
		key: key,
	}, err
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

	jwt, err := sdjwt.SignedString(c.key)
	if err != nil {
		return "", err
	}

	return jwt, nil
}

func DecodeEcdsaPrivateKey(bytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, errors.New("failed to decode ecsda private key")
	}

	return x509.ParseECPrivateKey(block.Bytes)

}

func ReadEcdsaPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return DecodeEcdsaPrivateKey(keyBytes)
}
