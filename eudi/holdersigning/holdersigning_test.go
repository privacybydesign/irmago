package holdersigning

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignSoftwareSignsWithTheCurvesHash(t *testing.T) {
	input := []byte("header.payload")
	for _, tc := range []struct {
		curve  elliptic.Curve
		digest []byte
	}{
		{elliptic.P256(), func() []byte { d := sha256.Sum256(input); return d[:] }()},
		{elliptic.P384(), func() []byte { d := sha512.Sum384(input); return d[:] }()},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		require.NoError(t, err)

		sig, err := SignSoftware(Software(key), input)
		require.NoError(t, err)
		size := (tc.curve.Params().BitSize + 7) / 8
		require.Len(t, sig, 2*size)
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		require.True(t, ecdsa.Verify(&key.PublicKey, tc.digest, r, s), tc.curve.Params().Name)
	}
}

func TestSignSoftwareRefusesExternalKeys(t *testing.T) {
	_, err := SignSoftware(External("ref"), []byte("x"))
	require.ErrorIs(t, err, ErrExternalKey)
}
