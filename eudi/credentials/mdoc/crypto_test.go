package mdoc

import (
	"bytes"
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
			if err == nil {
				t.Fatalf("ecdsaPublicKeyFromCOSE accepted an over-wide coordinate, got key %v", pub)
			}
			if pub != nil {
				t.Errorf("expected a nil key alongside the error, got %v", pub)
			}
		})
	}
}

// TestECDSAPublicKeyFromCOSEAcceptsValidKey guards the width check against
// rejecting the keys it has to keep accepting, including a coordinate with
// leading zero bytes (which encodes shorter than 32 bytes).
func TestECDSAPublicKeyFromCOSEAcceptsValidKey(t *testing.T) {
	valid := validCOSEKey(t)

	pub, err := ecdsaPublicKeyFromCOSE(valid)
	if err != nil {
		t.Fatalf("ecdsaPublicKeyFromCOSE rejected a valid key: %v", err)
	}
	if pub == nil {
		t.Fatal("expected a key, got nil")
	}
	if got := pub.X.FillBytes(make([]byte, 32)); !bytes.Equal(got, leftPad(valid.X, 32)) {
		t.Errorf("X round-tripped as %x, want %x", got, leftPad(valid.X, 32))
	}
	if got := pub.Y.FillBytes(make([]byte, 32)); !bytes.Equal(got, leftPad(valid.Y, 32)) {
		t.Errorf("Y round-tripped as %x, want %x", got, leftPad(valid.Y, 32))
	}
}

// validCOSEKey returns the COSE encoding of a real generated P-256 key, so the
// over-wide cases below differ from a valid key only in coordinate width.
func validCOSEKey(t *testing.T) COSEKey {
	t.Helper()

	holder, err := NewHolder()
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	key, err := coseKeyFromECDSA(holder.PublicKey())
	if err != nil {
		t.Fatalf("coseKeyFromECDSA: %v", err)
	}
	return key
}

func leftPad(b []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
