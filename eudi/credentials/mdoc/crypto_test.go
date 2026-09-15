package mdoc

import (
	"testing"

	"github.com/stretchr/testify/require"
	cose "github.com/veraison/go-cose"
)

// TestECDSAPublicKeyFromCOSERejectsOverWideCoordinate pins that a COSE key
// whose coordinates are wider than P-256 is rejected with an error. The
// coordinates are copied into a fixed 32-byte buffer with big.Int.FillBytes,
// which panics rather than erroring when the value does not fit, so without a
// width check an MSO carrying a 33-byte X took the whole process down instead
// of failing the one credential.
func TestECDSAPublicKeyFromCOSERejectsOverWideCoordinate(t *testing.T) {
	valid := validCOSEKey(t)
	crv, x, y, _ := valid.EC2()

	tests := []struct {
		name string
		key  *cose.Key
	}{
		{
			name: "X wider than P-256",
			key:  ec2Key(valid.Type, crv, append([]byte{0x01}, x...), y),
		},
		{
			name: "Y wider than P-256",
			key:  ec2Key(valid.Type, crv, x, append([]byte{0x01}, y...)),
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

	_, wantX, wantY, _ := valid.EC2()

	gotX := pub.X.FillBytes(make([]byte, 32))
	require.Equal(t, leftPad(wantX, 32), gotX, "X round-tripped as %x, want %x", gotX, leftPad(wantX, 32))

	gotY := pub.Y.FillBytes(make([]byte, 32))
	require.Equal(t, leftPad(wantY, 32), gotY, "Y round-tripped as %x, want %x", gotY, leftPad(wantY, 32))
}

// validCOSEKey returns the COSE encoding of a real generated P-256 key, so the
// over-wide cases below differ from a valid key only in coordinate width.
func validCOSEKey(t *testing.T) *cose.Key {
	t.Helper()

	holder, err := NewHolder()
	require.NoError(t, err, "NewHolder: %v", err)
	key, err := coseKeyFromECDSA(holder.PublicKey())
	require.NoError(t, err, "coseKeyFromECDSA: %v", err)
	return key
}

// ec2Key builds a COSE_Key from raw labels, for the malformed shapes no real
// generated key can produce. A nil coordinate is left out of the map entirely,
// which is how a key missing that label arrives off the wire.
func ec2Key(kty cose.KeyType, crv cose.Curve, x, y []byte) *cose.Key {
	params := map[any]any{cose.KeyLabelEC2Curve: crv}
	if x != nil {
		params[cose.KeyLabelEC2X] = x
	}
	if y != nil {
		params[cose.KeyLabelEC2Y] = y
	}
	return &cose.Key{Type: kty, Params: params}
}

func leftPad(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
