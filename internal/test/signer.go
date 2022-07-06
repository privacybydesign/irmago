package test

import (
	"crypto/ecdsa"
	"testing"

	"github.com/privacybydesign/gabi/signed"
	"github.com/stretchr/testify/require"
)

type Signer struct {
	privateKey *ecdsa.PrivateKey
}

func NewSigner(t *testing.T) *Signer {
	privateKey, err := signed.GenerateKey()
	require.NoError(t, err)
	return &Signer{privateKey: privateKey}
}

func LoadSigner(t *testing.T, privateKey *ecdsa.PrivateKey) *Signer {
	return &Signer{privateKey: privateKey}
}

func (s *Signer) PublicKey(_ string) ([]byte, error) {
	return signed.MarshalPublicKey(&s.privateKey.PublicKey)
}

func (s *Signer) ECDSAPublicKey() *ecdsa.PublicKey {
	return &s.privateKey.PublicKey
}

func (s *Signer) Sign(_ string, msg []byte) ([]byte, error) {
	return signed.Sign(s.privateKey, msg)
}
