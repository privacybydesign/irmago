package mdoc

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// TestECDSAPublicKeyFromCOSERejectsOverWideCoordinate pins that a COSE key
// whose coordinates are wider than P-256 is rejected with an error. The
// coordinates are copied into a fixed 32-byte buffer with big.Int.FillBytes,
// which panics rather than erroring when the value does not fit, so without a
// width check an MSO carrying a 33-byte X took the whole process down instead
// of failing the one credential.
func TestECDSAPublicKeyFromCOSERejectsOverWideCoordinate(t *testing.T) {
	valid := validCOSEKey(t)

	tests := []struct {
		name string
		key  COSEKey
	}{
		{
			name: "X wider than P-256",
			key:  COSEKey{Kty: valid.Kty, Crv: valid.Crv, X: append([]byte{0x01}, valid.X...), Y: valid.Y},
		},
		{
			name: "Y wider than P-256",
			key:  COSEKey{Kty: valid.Kty, Crv: valid.Crv, X: valid.X, Y: append([]byte{0x01}, valid.Y...)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := ecdsaPublicKeyFromCOSE(tc.key)
			require.Error(t, err, "ecdsaPublicKeyFromCOSE accepted an over-wide coordinate, got key %v", pub)
			require.Nil(t, pub, "expected a nil key alongside the error, got %v", pub)
		})
	}
}

// TestECDSAPublicKeyFromCOSEAcceptsValidKey guards the width check against
// rejecting the keys it has to keep accepting: a real generated P-256 key,
// whose coordinates coseKeyFromECDSA encodes at the fixed SEC1 width of 32
// bytes each, round-trips unchanged. A coordinate encoded shorter than 32
// bytes is not exercised here — nothing in this package produces one — and
// would be accepted regardless, since the guard only rejects values wider
// than the curve.
func TestECDSAPublicKeyFromCOSEAcceptsValidKey(t *testing.T) {
	valid := validCOSEKey(t)

	pub, err := ecdsaPublicKeyFromCOSE(valid)
	require.NoError(t, err, "ecdsaPublicKeyFromCOSE rejected a valid key: %v", err)
	require.NotNil(t, pub, "expected a key, got nil")

	gotX := pub.X.FillBytes(make([]byte, 32))
	require.Equal(t, leftPad(valid.X, 32), gotX, "X round-tripped as %x, want %x", gotX, leftPad(valid.X, 32))

	gotY := pub.Y.FillBytes(make([]byte, 32))
	require.Equal(t, leftPad(valid.Y, 32), gotY, "Y round-tripped as %x, want %x", gotY, leftPad(valid.Y, 32))
}

// validCOSEKey returns the COSE encoding of a real generated P-256 key, so the
// over-wide cases below differ from a valid key only in coordinate width.
func validCOSEKey(t *testing.T) COSEKey {
	t.Helper()

	holder, err := NewHolder()
	require.NoError(t, err, "NewHolder: %v", err)
	key, err := coseKeyFromECDSA(holder.PublicKey())
	require.NoError(t, err, "coseKeyFromECDSA: %v", err)
	return key
}

func leftPad(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
