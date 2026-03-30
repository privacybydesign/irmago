package sdjwtvc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// ========================== ProcessedSdJwtPayload.Sort Tests ==========================
// Current behaviour summary:
//   - Nested ProcessedSdJwtPayload values are recursively sorted.
//   - Scalar values (string, int, bool, float) are left unchanged.
//   - Slice values are sorted in ascending order.
//   - Map values that are not ProcessedSdJwtPayload cause a panic.
//   - Nil values in the map cause a panic (reflect.TypeOf(nil).Kind() panics).

func Test_ProcessedSdJwtPayload_Sort_EmptyPayload_NoPanic(t *testing.T) {
	p := ProcessedSdJwtPayload{}
	require.NotPanics(t, func() { p.Sort() })
}

func Test_ProcessedSdJwtPayload_Sort_ScalarValues_Unchanged(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"str":   "hello",
		"int":   42,
		"float": 3.14,
		"bool":  true,
	}

	p.Sort()

	require.Equal(t, "hello", p["str"])
	require.Equal(t, 42, p["int"])
	require.Equal(t, 3.14, p["float"])
	require.Equal(t, true, p["bool"])
}

func Test_ProcessedSdJwtPayload_Sort_NestedPayload_RecurseWithoutPanic(t *testing.T) {
	inner := ProcessedSdJwtPayload{
		"b": "second",
		"a": "first",
	}
	p := ProcessedSdJwtPayload{
		"nested": inner,
		"top":    "value",
	}

	require.NotPanics(t, func() { p.Sort() })
	// Values must still be present and unchanged after sort.
	require.Equal(t, "value", p["top"])
	innerResult, ok := p["nested"].(ProcessedSdJwtPayload)
	require.True(t, ok)
	require.Equal(t, "first", innerResult["a"])
	require.Equal(t, "second", innerResult["b"])
}

func Test_ProcessedSdJwtPayload_Sort_DeeplyNestedPayload_RecurseWithoutPanic(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"level1": ProcessedSdJwtPayload{
			"level2": ProcessedSdJwtPayload{
				"level3": ProcessedSdJwtPayload{
					"leaf": "value",
				},
			},
		},
	}

	require.NotPanics(t, func() { p.Sort() })

	l1 := p["level1"].(ProcessedSdJwtPayload)
	l2 := l1["level2"].(ProcessedSdJwtPayload)
	l3 := l2["level3"].(ProcessedSdJwtPayload)
	require.Equal(t, "value", l3["leaf"])
}

func Test_ProcessedSdJwtPayload_Sort_SliceValue_Sorted(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"items": []string{"c", "a", "b"},
	}

	p.Sort()

	result, ok := p["items"].([]string)
	require.True(t, ok)
	require.Equal(t, []string{"a", "b", "c"}, result)
}

func Test_ProcessedSdJwtPayload_Sort_SliceOfInts_Sorted(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"nums": []int{3, 1, 2},
	}

	p.Sort()

	result, ok := p["nums"].([]int)
	require.True(t, ok)
	require.Equal(t, []int{1, 2, 3}, result)
}

func Test_ProcessedSdJwtPayload_Sort_UnknownMapType_Panics(t *testing.T) {
	// A map[string]string value is not castable to ProcessedSdJwtPayload (map[string]any),
	// so Sort must panic when it encounters it.
	p := ProcessedSdJwtPayload{
		"bad": map[string]string{"key": "val"},
	}

	require.Panics(t, func() { p.Sort() })
}

func Test_ProcessedSdJwtPayload_Sort_MultipleNestedPayloads_AllRecursed(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"first": ProcessedSdJwtPayload{
			"x": "1",
		},
		"second": ProcessedSdJwtPayload{
			"y": "2",
		},
		"scalar": "flat",
	}

	require.NotPanics(t, func() { p.Sort() })

	require.Equal(t, "flat", p["scalar"])
	require.Equal(t, "1", p["first"].(ProcessedSdJwtPayload)["x"])
	require.Equal(t, "2", p["second"].(ProcessedSdJwtPayload)["y"])
}

func Test_ProcessedSdJwtPayload_Sort_NestedPayloadContainingSlice_SliceUnsorted(t *testing.T) {
	inner := ProcessedSdJwtPayload{
		"tags": []string{"z", "a", "m"},
	}
	p := ProcessedSdJwtPayload{
		"nested": inner,
	}

	p.Sort()

	result := p["nested"].(ProcessedSdJwtPayload)["tags"].([]string)
	require.Equal(t, []string{"a", "m", "z"}, result)
}

// ========================== ProcessedSdJwtPayload.MarshalJSON Tests ==========================
// MarshalJSON calls Sort() before marshalling, producing a fully deterministic JSON encoding:
// map keys are sorted by encoding/json, and slice elements are sorted by Sort().

func Test_ProcessedSdJwtPayload_MarshalJSON_EmptyPayload(t *testing.T) {
	p := ProcessedSdJwtPayload{}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{}`, string(out))
}

func Test_ProcessedSdJwtPayload_MarshalJSON_ScalarValues_KeysSorted(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"z": "last",
		"a": "first",
		"m": "middle",
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	// encoding/json sorts map keys alphabetically.
	require.Equal(t, `{"a":"first","m":"middle","z":"last"}`, string(out))
}

func Test_ProcessedSdJwtPayload_MarshalJSON_StringSlice_ArraySorted(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"tags": []string{"cherry", "apple", "banana"},
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{"tags":["apple","banana","cherry"]}`, string(out))
}

func Test_ProcessedSdJwtPayload_MarshalJSON_IntSlice_ArraySorted(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"nums": []int{30, 10, 20},
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{"nums":[10,20,30]}`, string(out))
}

func Test_ProcessedSdJwtPayload_MarshalJSON_NestedMap_KeysAndContentSorted(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"z_key": "last",
		"a_key": ProcessedSdJwtPayload{
			"z_inner": "last",
			"a_inner": "first",
		},
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{"a_key":{"a_inner":"first","z_inner":"last"},"z_key":"last"}`, string(out))
}

func Test_ProcessedSdJwtPayload_MarshalJSON_NestedMapWithSlice_FullyDeterministic(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"z": "scalar",
		"a": ProcessedSdJwtPayload{
			"tags":   []string{"z", "a", "m"},
			"name":   "nested",
			"counts": []int{30, 10, 20},
			"scores": []float64{3.3, 1.1, 2.2},
		},
	}

	out, err := json.Marshal(&p)

	require.NoError(t, err)
	require.Equal(t, `{"a":{"counts":[10,20,30],"name":"nested","scores":[1.1,2.2,3.3],"tags":["a","m","z"]},"z":"scalar"}`, string(out))
}

func Test_ProcessedSdJwtPayload_MarshalJSON_Deterministic_SameBytesTwice(t *testing.T) {
	p := ProcessedSdJwtPayload{
		"z": "last",
		"a": ProcessedSdJwtPayload{
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
