package bitstringstatus

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encodeBitstring encodes raw bytes the way a BitstringStatusListCredential's
// credentialSubject.encodedList is produced: GZIP, then Multibase base64url-no-pad.
func encodeBitstring(t *testing.T, raw []byte) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write(raw)
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return "u" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func TestExpandBitstring_RoundTrip(t *testing.T) {
	raw := []byte{0x80, 0x00, 0x5A, 0xFF}
	got, err := ExpandBitstring(encodeBitstring(t, raw))
	require.NoError(t, err)
	assert.Equal(t, raw, got)
}

func TestExpandBitstring_Rejects(t *testing.T) {
	valid := encodeBitstring(t, []byte{0x00})

	t.Run("empty", func(t *testing.T) {
		_, err := ExpandBitstring("")
		require.ErrorIs(t, err, ErrDecode)
	})
	t.Run("missing multibase prefix", func(t *testing.T) {
		_, err := ExpandBitstring(valid[1:]) // drop the leading 'u'
		require.ErrorIs(t, err, ErrDecode)
	})
	t.Run("wrong multibase prefix", func(t *testing.T) {
		_, err := ExpandBitstring("z" + valid[1:]) // 'z' = base58btc, not accepted
		require.ErrorIs(t, err, ErrDecode)
	})
	t.Run("not base64url", func(t *testing.T) {
		_, err := ExpandBitstring("u!!!not-base64!!!")
		require.ErrorIs(t, err, ErrDecode)
	})
	t.Run("not gzip", func(t *testing.T) {
		_, err := ExpandBitstring("u" + base64.RawURLEncoding.EncodeToString([]byte("not gzip data")))
		require.ErrorIs(t, err, ErrDecode)
	})
}

func TestStatusValueAt_MSBFirstSingleBit(t *testing.T) {
	// 0x80 = 0b10000000: only index 0 is set. 0x5A = 0b01011010: indices 1,3,4,6.
	bits := []byte{0x80, 0x5A}

	set := map[uint64]bool{0: true, 9: true, 11: true, 12: true, 14: true}
	for idx := uint64(0); idx < 16; idx++ {
		v, err := StatusValueAt(bits, 1, idx)
		require.NoError(t, err)
		want := uint(0)
		if set[idx] {
			want = 1
		}
		assert.Equalf(t, want, v, "bit index %d", idx)
	}
}

func TestStatusValueAt_MultiBitWithinByte(t *testing.T) {
	// 0x90 = 0b10010000; statusSize 2 → entries [10][01][00][00] = 2,1,0,0.
	bits := []byte{0x90}
	for idx, want := range []uint{2, 1, 0, 0} {
		v, err := StatusValueAt(bits, 2, uint64(idx))
		require.NoError(t, err)
		assert.Equalf(t, want, v, "entry %d", idx)
	}
}

func TestStatusValueAt_MultiBitCrossesByteBoundary(t *testing.T) {
	// statusSize 3, entry index 2 starts at bit 6 and spans bytes 0 and 1.
	// byte0 0b00000011, byte1 0b10000000 → bits 6,7,8 = 1,1,1 → value 7.
	bits := []byte{0x03, 0x80}
	v, err := StatusValueAt(bits, 3, 2)
	require.NoError(t, err)
	assert.Equal(t, uint(7), v)
}

func TestStatusValueAt_IndexOutOfBounds(t *testing.T) {
	bits := []byte{0xFF} // 8 single-bit entries: valid indices 0..7
	_, err := StatusValueAt(bits, 1, 8)
	require.ErrorIs(t, err, ErrIndexBounds)

	// A multi-bit entry that would read past the end.
	_, err = StatusValueAt(bits, 2, 4)
	require.ErrorIs(t, err, ErrIndexBounds)
}

func TestStatusValueAt_InvalidStatusSize(t *testing.T) {
	bits := []byte{0xFF}
	for _, size := range []int{0, -1, 9} {
		_, err := StatusValueAt(bits, size, 0)
		require.ErrorIsf(t, err, ErrDecode, "statusSize %d", size)
	}
}
