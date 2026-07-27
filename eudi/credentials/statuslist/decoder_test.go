package statuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// encodeLst compresses raw with zlib and base64url-encodes it,
// matching the on-wire shape the spec requires for `lst`.
func encodeLst(t *testing.T, raw []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, err := w.Write(raw)
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func Test_DecodeBits_RoundTrip(t *testing.T) {
	raw := []byte{0x55, 0xAA, 0xF0, 0x0F}
	lst := encodeLst(t, raw)
	out, err := decodeBits(lst, 0)
	require.NoError(t, err)
	require.Equal(t, raw, out)
}

func Test_DecodeBits_InvalidBase64_ReturnsErrDecode(t *testing.T) {
	_, err := decodeBits("not_base64!!!", 0)
	require.ErrorIs(t, err, ErrDecode)
}

func Test_DecodeBits_InvalidZlib_ReturnsErrDecode(t *testing.T) {
	bogus := base64.RawURLEncoding.EncodeToString([]byte("not-zlib"))
	_, err := decodeBits(bogus, 0)
	require.ErrorIs(t, err, ErrDecode)
}

func Test_DecodeBits_PostDecompressionCap_ReturnsErrDecode(t *testing.T) {
	// Highly compressible payload that decompresses to ~10 KB,
	// against a cap of 100 bytes.
	raw := bytes.Repeat([]byte{0x00}, 10000)
	lst := encodeLst(t, raw)
	_, err := decodeBits(lst, 100)
	require.ErrorIs(t, err, ErrDecode)
	require.True(t, strings.Contains(err.Error(), "exceeds cap"))
}

// --- statusAtIndex: bit packing ----------------------------------------------

func Test_StatusAtIndex_1Bit_Valid_Invalid(t *testing.T) {
	// One byte holds 8 entries at 1 bit each.
	// Byte 0b10100011 → entries (lsb first): 1,1,0,0,0,1,0,1.
	bits := []byte{0b10100011}
	want := []Status{
		StatusInvalid, StatusInvalid, StatusValid, StatusValid,
		StatusValid, StatusInvalid, StatusValid, StatusInvalid,
	}
	for i, w := range want {
		s, err := statusAtIndex(bits, 1, uint64(i))
		require.NoError(t, err)
		require.Equalf(t, w, s, "idx %d", i)
	}
}

func Test_StatusAtIndex_2Bit_AllFourValues(t *testing.T) {
	// One byte holds 4 entries at 2 bits each.
	// Byte 0b11100100 → entries (lsb first): 0,1,2,3 → Valid,
	// Invalid, Suspended, ApplicationSpecific.
	bits := []byte{0b11100100}
	want := []Status{StatusValid, StatusInvalid, StatusSuspended, StatusApplicationSpecific}
	for i, w := range want {
		s, err := statusAtIndex(bits, 2, uint64(i))
		require.NoError(t, err)
		require.Equalf(t, w, s, "idx %d", i)
	}
}

func Test_StatusAtIndex_4Bit_Nibbles(t *testing.T) {
	// One byte holds 2 entries at 4 bits each.
	// Byte 0xA5 → entries (lsb first): 0x5 (5 → AppSpecific), 0xA (10 → AppSpecific).
	bits := []byte{0xA5}
	s0, err := statusAtIndex(bits, 4, 0)
	require.NoError(t, err)
	require.Equal(t, StatusApplicationSpecific, s0)
	s1, err := statusAtIndex(bits, 4, 1)
	require.NoError(t, err)
	require.Equal(t, StatusApplicationSpecific, s1)
}

func Test_StatusAtIndex_4Bit_ValidThenInvalid(t *testing.T) {
	// 0x10 → entry 0 = 0 (Valid), entry 1 = 1 (Invalid).
	bits := []byte{0x10}
	s0, err := statusAtIndex(bits, 4, 0)
	require.NoError(t, err)
	require.Equal(t, StatusValid, s0)
	s1, err := statusAtIndex(bits, 4, 1)
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, s1)
}

func Test_StatusAtIndex_8Bit_FullByte(t *testing.T) {
	// One byte = one entry at 8 bits.
	bits := []byte{0, 1, 2, 7, 255}
	want := []Status{
		StatusValid, StatusInvalid, StatusSuspended,
		StatusApplicationSpecific, StatusApplicationSpecific,
	}
	for i, w := range want {
		s, err := statusAtIndex(bits, 8, uint64(i))
		require.NoError(t, err)
		require.Equalf(t, w, s, "idx %d", i)
	}
}

func Test_StatusAtIndex_LastIndexExactlyAtEnd_OK(t *testing.T) {
	bits := []byte{0xFF}                // 8 entries at 1 bit each
	s, err := statusAtIndex(bits, 1, 7) // index 7 → bit 7
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, s)
}

func Test_StatusAtIndex_PastEnd_ReturnsErrIndexBounds(t *testing.T) {
	bits := []byte{0xFF} // 8 entries at 1 bit each
	_, err := statusAtIndex(bits, 1, 8)
	require.ErrorIs(t, err, ErrIndexBounds)
}

func Test_StatusAtIndex_InvalidBitSize_ReturnsErrUnauthorized(t *testing.T) {
	_, err := statusAtIndex([]byte{0xFF}, 3, 0)
	require.True(t, errors.Is(err, ErrUnauthorized))
}

func Test_StatusAtIndex_CrossesByteBoundary_2Bit(t *testing.T) {
	// 2-bit packing never crosses byte boundaries (8 % 2 == 0). With
	// bits=2, idx=4 lives at byte 1, position 0. Use two bytes to
	// confirm we land on the second.
	bits := []byte{0x00, 0b11100100}
	want := []Status{StatusValid, StatusInvalid, StatusSuspended, StatusApplicationSpecific}
	for i, w := range want {
		s, err := statusAtIndex(bits, 2, uint64(4+i))
		require.NoError(t, err)
		require.Equalf(t, w, s, "idx %d", 4+i)
	}
}
