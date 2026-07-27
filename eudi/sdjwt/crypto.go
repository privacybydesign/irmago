package sdjwt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	iana "github.com/privacybydesign/irmago/internal/crypto/hashing"
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

func CreateUrlEncodedHash(algorithm iana.HashingAlgorithm, content string) (string, error) {
	hash, err := iana.Sum(algorithm, content)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(hash), nil
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
