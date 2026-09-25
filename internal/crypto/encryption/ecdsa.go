package encryption

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

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
