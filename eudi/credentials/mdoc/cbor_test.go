package mdoc

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalEncodingIsDeterministic(t *testing.T) {
	// A map whose keys differ in length exercises the length-first ("canonical")
	// ordering: the single-character keys must sort before the longer one,
	// regardless of insertion order.
	in := map[string]int{
		"org.iso.18013.5.1.US": 3,
		"a":                    1,
		"bb":                   2,
	}

	first, err := MarshalCBOR(in)
	require.NoError(t, err)

	// Re-encoding must produce byte-identical output.
	for i := 0; i < 16; i++ {
		again, err := MarshalCBOR(in)
		require.NoError(t, err)
		require.True(t, bytes.Equal(first, again), "canonical encoding must be stable")
	}

	// Canonical order is length-first then bytewise: "a", "bb", "org...".
	expected, err := hex.DecodeString("a3" +
		"6161" + "01" + // "a": 1
		"626262" + "02" + // "bb": 2
		"74" + "6f72672e69736f2e31383031332e352e312e5553" + "03") // "org.iso.18013.5.1.US": 3
	require.NoError(t, err)
	assert.Equal(t, expected, first)
}

func TestEncodedCBORRoundTrip(t *testing.T) {
	type inner struct {
		Name string `cbor:"name"`
		N    int    `cbor:"n"`
	}
	original := inner{Name: "alice", N: 42}

	wrapped, err := NewEncodedCBOR(original)
	require.NoError(t, err)

	encoded, err := MarshalCBOR(wrapped)
	require.NoError(t, err)

	// The outer item must be a tag 24 (0xd818) wrapping a byte string.
	require.GreaterOrEqual(t, len(encoded), 2)
	assert.Equal(t, byte(0xd8), encoded[0])
	assert.Equal(t, byte(0x18), encoded[1])

	var decoded EncodedCBOR
	require.NoError(t, UnmarshalCBOR(encoded, &decoded))
	assert.Equal(t, wrapped.Data, decoded.Data)

	var got inner
	require.NoError(t, decoded.DecodeInto(&got))
	assert.Equal(t, original, got)
}

func TestEncodedCBORByteExact(t *testing.T) {
	// #6.24(bstr) of an empty CBOR map {} (0xa0): d818 41 a0.
	wrapped, err := NewEncodedCBOR(map[string]any{})
	require.NoError(t, err)

	encoded, err := MarshalCBOR(wrapped)
	require.NoError(t, err)

	expected, err := hex.DecodeString("d81841a0")
	require.NoError(t, err)
	assert.Equal(t, expected, encoded)
}

func TestEncodedCBORRejectsWrongTag(t *testing.T) {
	// A plain byte string (not tagged with 24) must be rejected.
	plain, err := MarshalCBOR([]byte{0x01, 0x02})
	require.NoError(t, err)

	var decoded EncodedCBOR
	assert.Error(t, UnmarshalCBOR(plain, &decoded))
}

func TestFullDateRoundTrip(t *testing.T) {
	d := NewFullDate(time.Date(2019, time.October, 20, 13, 30, 0, 0, time.UTC))

	encoded, err := MarshalCBOR(d)
	require.NoError(t, err)

	// tag 1004 (0xd903ec) + text string "2019-10-20".
	expected, err := hex.DecodeString("d903ec" + "6a" + hex.EncodeToString([]byte("2019-10-20")))
	require.NoError(t, err)
	assert.Equal(t, expected, encoded)

	var got FullDate
	require.NoError(t, UnmarshalCBOR(encoded, &got))
	assert.Equal(t, "2019-10-20", got.String())
}

func TestDateTimeRoundTrip(t *testing.T) {
	// Fractional seconds and a non-UTC zone must be normalised away.
	loc := time.FixedZone("CET", 3600)
	dt := NewDateTime(time.Date(2020, time.October, 1, 14, 30, 2, 500_000_000, loc))

	encoded, err := MarshalCBOR(dt)
	require.NoError(t, err)

	// tag 0 (0xc0) + text string "2020-10-01T13:30:02Z" (UTC, no fractional secs).
	expected, err := hex.DecodeString("c0" + "74" + hex.EncodeToString([]byte("2020-10-01T13:30:02Z")))
	require.NoError(t, err)
	assert.Equal(t, expected, encoded)

	var got DateTime
	require.NoError(t, UnmarshalCBOR(encoded, &got))
	assert.True(t, got.Time().Equal(time.Date(2020, time.October, 1, 13, 30, 2, 0, time.UTC)))
}

func TestDateTimeMatchesAnnexDValidityInfo(t *testing.T) {
	// The validityInfo "signed" value from the Annex D MSO is tag 0 with
	// "2020-10-01T13:30:02Z"; confirm we produce the identical encoding.
	signed := NewDateTime(time.Date(2020, time.October, 1, 13, 30, 2, 0, time.UTC))
	encoded, err := MarshalCBOR(signed)
	require.NoError(t, err)

	expected, err := hex.DecodeString("c074323032302d31302d30315431333a33303a30325a")
	require.NoError(t, err)
	assert.Equal(t, expected, encoded)
}

func TestWrongTagTypeRejected(t *testing.T) {
	var fd FullDate
	dt, err := MarshalCBOR(NewDateTime(time.Now()))
	require.NoError(t, err)
	// A tag-0 date-time must not decode as a tag-1004 full-date.
	assert.Error(t, UnmarshalCBOR(dt, &fd))
}

func TestIndefiniteLengthRejected(t *testing.T) {
	// 0x9f ... 0xff is an indefinite-length array, forbidden by the mdoc profile.
	indef, err := hex.DecodeString("9f01ff")
	require.NoError(t, err)
	var v []int
	assert.Error(t, UnmarshalCBOR(indef, &v))

	// Sanity check: the definite-length form decodes fine.
	def, err := hex.DecodeString("8101")
	require.NoError(t, err)
	require.NoError(t, UnmarshalCBOR(def, &v))
	assert.Equal(t, []int{1}, v)
}

// TestCanonicalModeMatchesFxamacker guards against accidental drift from the
// documented canonical option set.
func TestCanonicalModeMatchesFxamacker(t *testing.T) {
	want, err := cbor.CanonicalEncOptions().EncMode()
	require.NoError(t, err)
	a, err := want.Marshal(map[string]int{"a": 1, "bb": 2})
	require.NoError(t, err)
	b, err := MarshalCBOR(map[string]int{"a": 1, "bb": 2})
	require.NoError(t, err)
	assert.Equal(t, a, b)
}
