package statuslist

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_StatusClaim_JSON_Roundtrip(t *testing.T) {
	in := StatusClaim{StatusList: &Reference{Index: 42, URI: "https://example.com/sl/1"}}
	b, err := json.Marshal(in)
	require.NoError(t, err)
	require.JSONEq(t, `{"status_list":{"idx":42,"uri":"https://example.com/sl/1"}}`, string(b))

	var out StatusClaim
	require.NoError(t, json.Unmarshal(b, &out))
	require.Equal(t, in, out)
}

func Test_StatusClaim_JSON_OmitsStatusListWhenNil(t *testing.T) {
	b, err := json.Marshal(StatusClaim{})
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(b))
}

func Test_Status_String(t *testing.T) {
	cases := map[Status]string{
		StatusUnknown:             "unknown",
		StatusValid:               "valid",
		StatusInvalid:             "invalid",
		StatusSuspended:           "suspended",
		StatusApplicationSpecific: "application_specific",
	}
	for s, want := range cases {
		require.Equal(t, want, s.String())
	}
}

func Test_StatusFromRaw_Mapping(t *testing.T) {
	require.Equal(t, StatusValid, statusFromRaw(0))
	require.Equal(t, StatusInvalid, statusFromRaw(1))
	require.Equal(t, StatusSuspended, statusFromRaw(2))
	require.Equal(t, StatusApplicationSpecific, statusFromRaw(3))
	require.Equal(t, StatusApplicationSpecific, statusFromRaw(255))
}

func Test_Errors_AreDistinctSentinels(t *testing.T) {
	require.False(t, errors.Is(ErrFetch, ErrUnauthorized))
	require.False(t, errors.Is(ErrFetch, ErrDecode))
	require.False(t, errors.Is(ErrFetch, ErrIndexBounds))
	require.True(t, errors.Is(ErrFetch, ErrFetch))
}

func TestParseStatusClaim(t *testing.T) {
	decode := func(js string) any {
		var v any
		require.NoError(t, json.Unmarshal([]byte(js), &v))
		return v
	}

	ref, err := ParseStatusClaim(decode(`{"status_list": {"idx": 42, "uri": "https://issuer.example/list/1"}}`))
	require.NoError(t, err)
	require.Equal(t, &Reference{Index: 42, URI: "https://issuer.example/list/1"}, ref)

	ref, err = ParseStatusClaim(decode(`{"other_mechanism": {}}`))
	require.NoError(t, err)
	require.Nil(t, ref, "a status claim without status_list names no list")

	for _, bad := range []string{
		`"not an object"`,
		`{"status_list": []}`,
		`{"status_list": {"idx": 1}}`,
		`{"status_list": {"uri": "https://issuer.example/list/1"}}`,
		`{"status_list": {"idx": -1, "uri": "https://issuer.example/list/1"}}`,
		`{"status_list": {"idx": 1.5, "uri": "https://issuer.example/list/1"}}`,
	} {
		_, err := ParseStatusClaim(decode(bad))
		require.Error(t, err, bad)
	}
}
