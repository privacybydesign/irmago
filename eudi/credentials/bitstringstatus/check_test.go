package bitstringstatus

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseListCredentialSubject(t *testing.T) {
	t.Run("single purpose", func(t *testing.T) {
		s, err := ParseListCredentialSubject(map[string]any{
			"type":          "BitstringStatusList",
			"statusPurpose": "revocation",
			"encodedList":   "uH4sIAAAAAAAAA",
		})
		require.NoError(t, err)
		assert.Equal(t, []StatusPurpose{PurposeRevocation}, s.StatusPurposes)
		assert.Equal(t, "uH4sIAAAAAAAAA", s.EncodedList)
	})

	t.Run("multiple purposes", func(t *testing.T) {
		s, err := ParseListCredentialSubject(map[string]any{
			"type":          []any{"BitstringStatusList"},
			"statusPurpose": []any{"revocation", "suspension"},
			"encodedList":   "uABC",
		})
		require.NoError(t, err)
		assert.Equal(t, []StatusPurpose{PurposeRevocation, PurposeSuspension}, s.StatusPurposes)
	})

	t.Run("wrong type", func(t *testing.T) {
		_, err := ParseListCredentialSubject(map[string]any{"type": "SomethingElse", "encodedList": "uABC", "statusPurpose": "revocation"})
		require.ErrorIs(t, err, ErrUnauthorized)
	})
	t.Run("missing encodedList", func(t *testing.T) {
		_, err := ParseListCredentialSubject(map[string]any{"type": "BitstringStatusList", "statusPurpose": "revocation"})
		require.ErrorIs(t, err, ErrDecode)
	})
	t.Run("missing statusPurpose", func(t *testing.T) {
		_, err := ParseListCredentialSubject(map[string]any{"type": "BitstringStatusList", "encodedList": "uABC"})
		require.ErrorIs(t, err, ErrUnauthorized)
	})
}

func TestCheck_EndToEnd(t *testing.T) {
	// A revocation list where only entry index 5 is set. Index 5 (MSB-first)
	// is bit position 5 of byte 0 → 0b00000100.
	subject := ListCredentialSubject{
		StatusPurposes: []StatusPurpose{PurposeRevocation},
		EncodedList:    encodeBitstring(t, []byte{0x04}),
	}
	entry := func(idx uint64) Entry {
		return Entry{StatusPurpose: PurposeRevocation, StatusListIndex: idx, StatusSize: 1, StatusListCredential: "https://x"}
	}

	revoked, err := Check(entry(5), subject)
	require.NoError(t, err)
	assert.Equal(t, uint(1), revoked, "index 5 is set → revoked")

	notRevoked, err := Check(entry(6), subject)
	require.NoError(t, err)
	assert.Equal(t, uint(0), notRevoked, "index 6 is clear → not revoked")
}

func TestCheck_PurposeMismatch(t *testing.T) {
	subject := ListCredentialSubject{
		StatusPurposes: []StatusPurpose{PurposeRevocation},
		EncodedList:    encodeBitstring(t, []byte{0xFF}),
	}
	_, err := Check(Entry{StatusPurpose: PurposeSuspension, StatusListIndex: 0, StatusSize: 1}, subject)
	require.ErrorIs(t, err, ErrUnauthorized, "a suspension entry must not read a revocation-only list")
}

func TestCheck_IndexPastEnd(t *testing.T) {
	subject := ListCredentialSubject{
		StatusPurposes: []StatusPurpose{PurposeRevocation},
		EncodedList:    encodeBitstring(t, []byte{0x00}), // 8 entries, indices 0..7
	}
	_, err := Check(Entry{StatusPurpose: PurposeRevocation, StatusListIndex: 8, StatusSize: 1}, subject)
	require.ErrorIs(t, err, ErrIndexBounds)
}
