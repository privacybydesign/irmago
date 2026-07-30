package sdjwt

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// ========================== ProcessedPayload.MarshalJSON Tests ==========================
// MarshalJSON produces a fully deterministic JSON encoding: map keys are sorted at every
// nesting level by encoding/json, while array element order is preserved as-is, since it
// is meaningful in SD-JWT claims.

func Test_ProcessedPayload_MarshalJSON_EmptyPayload(t *testing.T) {
	p := ProcessedPayload{}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{}`, string(out))
}

func Test_ProcessedPayload_MarshalJSON_ScalarValues_KeysSorted(t *testing.T) {
	p := ProcessedPayload{
		"z": "last",
		"a": "first",
		"m": "middle",
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	// encoding/json sorts map keys alphabetically.
	require.Equal(t, `{"a":"first","m":"middle","z":"last"}`, string(out))
}

func Test_ProcessedPayload_MarshalJSON_StringSlice_ArrayOrderPreserved(t *testing.T) {
	p := ProcessedPayload{
		"tags": []string{"cherry", "apple", "banana"},
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{"tags":["cherry","apple","banana"]}`, string(out))
}

func Test_ProcessedPayload_MarshalJSON_IntSlice_ArrayOrderPreserved(t *testing.T) {
	p := ProcessedPayload{
		"nums": []int{30, 10, 20},
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{"nums":[30,10,20]}`, string(out))
}

func Test_ProcessedPayload_MarshalJSON_NestedMap_KeysSorted(t *testing.T) {
	p := ProcessedPayload{
		"z_key": "last",
		"a_key": ProcessedPayload{
			"z_inner": "last",
			"a_inner": "first",
		},
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{"a_key":{"a_inner":"first","z_inner":"last"},"z_key":"last"}`, string(out))
}

func Test_ProcessedPayload_MarshalJSON_NestedMapWithSlice_KeysSortedArrayOrderPreserved(t *testing.T) {
	p := ProcessedPayload{
		"z": "scalar",
		"a": ProcessedPayload{
			"tags":   []string{"z", "a", "m"},
			"name":   "nested",
			"counts": []int{30, 10, 20},
			"scores": []float64{3.3, 1.1, 2.2},
		},
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{"a":{"counts":[30,10,20],"name":"nested","scores":[3.3,1.1,2.2],"tags":["z","a","m"]},"z":"scalar"}`, string(out))
}

func Test_ProcessedPayload_MarshalJSON_Deterministic_SameBytesTwice(t *testing.T) {
	p := ProcessedPayload{
		"z": "last",
		"a": ProcessedPayload{
			"items": []string{"c", "a", "b"},
		},
		"m": 42,
	}

	first, err := json.Marshal(&p)
	require.NoError(t, err)

	second, err := json.Marshal(&p)
	require.NoError(t, err)

	require.Equal(t, first, second)
}
