package sdjwt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// ========================== ProcessedPayload.GetClaimValue Tests ==========================
// Current behaviour summary:
//   - An empty path returns the payload itself.
//   - A nil receiver with a non-empty path returns an error.
//   - A string component selects a key from the current object.
//   - An int component selects an element by index from the current array.
//   - A nil component asserts that the current value is an array and keeps it as the selection.
//   - Any other component type returns an error.
//   - If a string key is absent, an error is returned.
//   - If an int index is out of range, an error is returned.
//   - If the current value's type does not match the component type, an error is returned.

func Test_ProcessedPayload_GetClaimValue_EmptyPath_ReturnsPayload(t *testing.T) {
	p := ProcessedPayload{"key": "value"}

	result, err := p.GetClaimValue([]any{})

	require.NoError(t, err)
	require.Equal(t, &p, result)
}

func Test_ProcessedPayload_GetClaimValue_NilPayload_EmptyPath_NoError(t *testing.T) {
	var p *ProcessedPayload

	result, err := p.GetClaimValue([]any{})

	require.NoError(t, err)
	require.Nil(t, result)
}

func Test_ProcessedPayload_GetClaimValue_NilPayload_NonEmptyPath_ReturnsError(t *testing.T) {
	var p *ProcessedPayload

	_, err := p.GetClaimValue([]any{"key"})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_TopLevelScalarString_ReturnsValue(t *testing.T) {
	p := ProcessedPayload{"name": "Alice"}

	result, err := p.GetClaimValue([]any{"name"})

	require.NoError(t, err)
	require.Equal(t, "Alice", result)
}

func Test_ProcessedPayload_GetClaimValue_TopLevelInt_ReturnsValue(t *testing.T) {
	p := ProcessedPayload{"age": 30}

	result, err := p.GetClaimValue([]any{"age"})

	require.NoError(t, err)
	require.Equal(t, 30, result)
}

func Test_ProcessedPayload_GetClaimValue_TopLevelBool_ReturnsValue(t *testing.T) {
	p := ProcessedPayload{"active": true}

	result, err := p.GetClaimValue([]any{"active"})

	require.NoError(t, err)
	require.Equal(t, true, result)
}

func Test_ProcessedPayload_GetClaimValue_NestedKey_ReturnsValue(t *testing.T) {
	p := ProcessedPayload{
		"address": ProcessedPayload{
			"city": "Amsterdam",
		},
	}

	result, err := p.GetClaimValue([]any{"address", "city"})

	require.NoError(t, err)
	require.Equal(t, "Amsterdam", result)
}

func Test_ProcessedPayload_GetClaimValue_DeeplyNestedKey_ReturnsValue(t *testing.T) {
	p := ProcessedPayload{
		"a": ProcessedPayload{
			"b": ProcessedPayload{
				"c": "deep",
			},
		},
	}

	result, err := p.GetClaimValue([]any{"a", "b", "c"})

	require.NoError(t, err)
	require.Equal(t, "deep", result)
}

func Test_ProcessedPayload_GetClaimValue_PathToNestedObject_ReturnsObject(t *testing.T) {
	inner := ProcessedPayload{"city": "Amsterdam"}
	p := ProcessedPayload{"address": inner}

	result, err := p.GetClaimValue([]any{"address"})

	require.NoError(t, err)
	require.Equal(t, inner, result)
}

func Test_ProcessedPayload_GetClaimValue_PathToSlice_ReturnsSlice(t *testing.T) {
	tags := []string{"a", "b", "c"}
	p := ProcessedPayload{"tags": tags}

	result, err := p.GetClaimValue([]any{"tags"})

	require.NoError(t, err)
	require.Equal(t, tags, result)
}

func Test_ProcessedPayload_GetClaimValue_IntIndexIntoStringSlice_ReturnsElement(t *testing.T) {
	p := ProcessedPayload{"tags": []string{"a", "b", "c"}}

	result, err := p.GetClaimValue([]any{"tags", 1})

	require.NoError(t, err)
	require.Equal(t, "b", result)
}

func Test_ProcessedPayload_GetClaimValue_IntIndexIntoAnySlice_ReturnsElement(t *testing.T) {
	p := ProcessedPayload{"items": []any{"x", 42, true}}

	result, err := p.GetClaimValue([]any{"items", 2})

	require.NoError(t, err)
	require.Equal(t, true, result)
}

func Test_ProcessedPayload_GetClaimValue_IntIndexFirstElement_ReturnsElement(t *testing.T) {
	p := ProcessedPayload{"nums": []int{10, 20, 30}}

	result, err := p.GetClaimValue([]any{"nums", 0})

	require.NoError(t, err)
	require.Equal(t, 10, result)
}

func Test_ProcessedPayload_GetClaimValue_IntIndexLastElement_ReturnsElement(t *testing.T) {
	p := ProcessedPayload{"nums": []int{10, 20, 30}}

	result, err := p.GetClaimValue([]any{"nums", 2})

	require.NoError(t, err)
	require.Equal(t, 30, result)
}

func Test_ProcessedPayload_GetClaimValue_StringKeyThenIntIndex_ReturnsElement(t *testing.T) {
	p := ProcessedPayload{
		"address": ProcessedPayload{
			"postcodes": []string{"1011AB", "1012CD"},
		},
	}

	result, err := p.GetClaimValue([]any{"address", "postcodes", 0})

	require.NoError(t, err)
	require.Equal(t, "1011AB", result)
}

func Test_ProcessedPayload_GetClaimValue_MissingTopLevelKey_ReturnsError(t *testing.T) {
	p := ProcessedPayload{"name": "Alice"}

	_, err := p.GetClaimValue([]any{"missing"})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_MissingNestedKey_ReturnsError(t *testing.T) {
	p := ProcessedPayload{
		"address": ProcessedPayload{
			"city": "Amsterdam",
		},
	}

	_, err := p.GetClaimValue([]any{"address", "country"})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_IntIndexOutOfRange_ReturnsError(t *testing.T) {
	p := ProcessedPayload{"tags": []string{"a", "b"}}

	_, err := p.GetClaimValue([]any{"tags", 5})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_NegativeIntIndex_ReturnsError(t *testing.T) {
	p := ProcessedPayload{"tags": []string{"a", "b"}}

	_, err := p.GetClaimValue([]any{"tags", -1})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_IntIndexOnObject_ReturnsError(t *testing.T) {
	p := ProcessedPayload{"address": ProcessedPayload{"city": "Amsterdam"}}

	_, err := p.GetClaimValue([]any{"address", 0})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_StringKeyOnScalar_ReturnsError(t *testing.T) {
	p := ProcessedPayload{"name": "Alice"}

	_, err := p.GetClaimValue([]any{"name", "first"})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_StringKeyOnSlice_ReturnsError(t *testing.T) {
	p := ProcessedPayload{"tags": []string{"a", "b"}}

	_, err := p.GetClaimValue([]any{"tags", "0"})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_NilComponentOnStringSlice_ReturnsSlice(t *testing.T) {
	tags := []string{"a", "b", "c"}
	p := ProcessedPayload{"tags": tags}

	result, err := p.GetClaimValue([]any{"tags", nil})

	require.NoError(t, err)
	require.Equal(t, tags, result)
}

func Test_ProcessedPayload_GetClaimValue_NilComponentOnAnySlice_ReturnsSlice(t *testing.T) {
	items := []any{"x", 42, true}
	p := ProcessedPayload{"items": items}

	result, err := p.GetClaimValue([]any{"items", nil})

	require.NoError(t, err)
	require.Equal(t, items, result)
}

func Test_ProcessedPayload_GetClaimValue_NilComponentOnObject_ReturnsError(t *testing.T) {
	p := ProcessedPayload{"address": ProcessedPayload{"city": "Amsterdam"}}

	_, err := p.GetClaimValue([]any{"address", nil})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_NilComponentOnScalar_ReturnsError(t *testing.T) {
	p := ProcessedPayload{"name": "Alice"}

	_, err := p.GetClaimValue([]any{"name", nil})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_NilComponentErrorMessage_ContainsNull(t *testing.T) {
	p := ProcessedPayload{"name": "Alice"}

	_, err := p.GetClaimValue([]any{"name", nil})

	require.ErrorContains(t, err, "null")
}

func Test_ProcessedPayload_GetClaimValue_UnsupportedComponentType_ReturnsError(t *testing.T) {
	p := ProcessedPayload{"key": "value"}

	_, err := p.GetClaimValue([]any{3.14})

	require.Error(t, err)
}

func Test_ProcessedPayload_GetClaimValue_ErrorMessage_ContainsMissingKeyAndIndex(t *testing.T) {
	p := ProcessedPayload{
		"address": ProcessedPayload{},
	}

	_, err := p.GetClaimValue([]any{"address", "missing"})

	require.ErrorContains(t, err, "1")
	require.ErrorContains(t, err, "missing")
}

func Test_ProcessedPayload_GetClaimValue_ErrorMessage_ContainsOutOfRangeIndex(t *testing.T) {
	p := ProcessedPayload{"tags": []string{"a"}}

	_, err := p.GetClaimValue([]any{"tags", 99})

	require.ErrorContains(t, err, "99")
}
