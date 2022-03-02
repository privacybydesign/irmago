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

func (s *Signer) PublicKey() ([]byte, error) {
	return signed.MarshalPublicKey(&s.privateKey.PublicKey)

}

func (s *Signer) Sign(msg []byte) ([]byte, error) {
	return signed.Sign(s.privateKey, msg)
}
