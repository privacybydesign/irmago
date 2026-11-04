// Package sdjwttest holds SD-JWT test fixtures that need the irmago/testdata
// module (fixed test keys). Kept out of eudi/sdjwt itself so that production
// code never depends on test fixtures.
package sdjwttest

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/privacybydesign/irmago/eudi/sdjwt"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"github.com/privacybydesign/irmago/testdata"
)

// NewEcdsaJwtCreatorWithIssuerTestKey creates a JwtCreator backed by the fixed
// issuer test key.
func NewEcdsaJwtCreatorWithIssuerTestKey() sdjwt.JwtCreator {
	key, err := readTestIssuerPrivateKey()
	if err != nil {
		return nil
	}
	return sdjwt.NewJwtCreator(key)
}

func readTestIssuerPrivateKey() (*ecdsa.PrivateKey, error) {
	key, err := encryption.DecodeEcdsaPrivateKey(testdata.IssuerPrivKeyBytes)
	if err != nil || key == nil {
		return nil, fmt.Errorf("failed to read ecdsa private key: %v", err)
	}
	return key, nil
}
