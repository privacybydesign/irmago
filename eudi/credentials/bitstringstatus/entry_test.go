package bitstringstatus

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fromJSON unmarshals a credentialStatus fragment the way it arrives inside a
// decoded VCDM document (numbers become float64, objects map[string]any).
func fromJSON(t *testing.T, raw string) any {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal([]byte(raw), &v))
	return v
}

func TestParseEntries_SingleObject(t *testing.T) {
	cs := fromJSON(t, `{
		"id": "https://example.com/status/1#94567",
		"type": "BitstringStatusListEntry",
		"statusPurpose": "revocation",
		"statusListIndex": "94567",
		"statusListCredential": "https://example.com/status/1"
	}`)

	entries, err := ParseEntries(cs)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "https://example.com/status/1#94567", e.ID)
	assert.Equal(t, PurposeRevocation, e.StatusPurpose)
	assert.Equal(t, uint64(94567), e.StatusListIndex)
	assert.Equal(t, "https://example.com/status/1", e.StatusListCredential)
	assert.Equal(t, DefaultStatusSize, e.StatusSize)
}

func TestParseEntries_ArrayOfPurposes(t *testing.T) {
	cs := fromJSON(t, `[
		{"type": "BitstringStatusListEntry", "statusPurpose": "revocation", "statusListIndex": "17", "statusListCredential": "https://example.com/revocation"},
		{"type": "BitstringStatusListEntry", "statusPurpose": "suspension", "statusListIndex": "18", "statusListCredential": "https://example.com/suspension"}
	]`)

	entries, err := ParseEntries(cs)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, PurposeRevocation, entries[0].StatusPurpose)
	assert.Equal(t, PurposeSuspension, entries[1].StatusPurpose)
	assert.Equal(t, "https://example.com/suspension", entries[1].StatusListCredential)
}

func TestParseEntries_SkipsOtherMechanisms(t *testing.T) {
	cs := fromJSON(t, `[
		{"type": "SomeOtherStatusMethod", "id": "x"},
		{"type": ["BitstringStatusListEntry"], "statusPurpose": "revocation", "statusListIndex": "3", "statusListCredential": "https://example.com/s"}
	]`)

	entries, err := ParseEntries(cs)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the BitstringStatusListEntry is returned; type may be an array")
	assert.Equal(t, uint64(3), entries[0].StatusListIndex)
}

func TestParseEntries_StatusSizeParsed(t *testing.T) {
	cs := fromJSON(t, `{
		"type": "BitstringStatusListEntry", "statusPurpose": "message",
		"statusListIndex": "1", "statusListCredential": "https://example.com/s", "statusSize": 2
	}`)

	entries, err := ParseEntries(cs)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, 2, entries[0].StatusSize)
}

// W3C §2.1 has the issuer include a statusMessage with a statusSize above 1,
// but the wallet reads only the status value, so it accepts an entry without
// one, or with one that is malformed.
func TestParseEntries_StatusMessageNotRequired(t *testing.T) {
	for name, statusMessage := range map[string]string{
		"absent":    ``,
		"malformed": `, "statusMessage": [{"status": "zero"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			entries, err := ParseEntries(fromJSON(t, `{
				"type": "BitstringStatusListEntry", "statusPurpose": "message",
				"statusListIndex": "1", "statusListCredential": "https://example.com/s", "statusSize": 2`+statusMessage+`
			}`))
			require.NoError(t, err)
			require.Len(t, entries, 1)
			assert.Equal(t, 2, entries[0].StatusSize)
		})
	}
}

func TestParseEntries_NilIsEmpty(t *testing.T) {
	entries, err := ParseEntries(nil)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestParseEntries_Errors(t *testing.T) {
	cases := map[string]string{
		"missing statusPurpose":        `{"type":"BitstringStatusListEntry","statusListIndex":"1","statusListCredential":"https://x"}`,
		"missing statusListIndex":      `{"type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListCredential":"https://x"}`,
		"non-numeric statusListIndex":  `{"type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":"abc","statusListCredential":"https://x"}`,
		"index not a string":           `{"type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":1,"statusListCredential":"https://x"}`,
		"missing statusListCredential": `{"type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":"1"}`,
		"zero statusSize":              `{"type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":"1","statusListCredential":"https://x","statusSize":0}`,
		"fractional statusSize":        `{"type":"BitstringStatusListEntry","statusPurpose":"revocation","statusListIndex":"1","statusListCredential":"https://x","statusSize":1.5}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseEntries(fromJSON(t, raw))
			require.ErrorIs(t, err, ErrEntry)
		})
	}
}

func TestParseEntries_RejectsNonObjectShapes(t *testing.T) {
	_, err := ParseEntries(fromJSON(t, `"a string"`))
	require.ErrorIs(t, err, ErrEntry)

	_, err = ParseEntries(fromJSON(t, `[42]`))
	require.ErrorIs(t, err, ErrEntry)
}
