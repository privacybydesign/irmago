package utils

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSet(t *testing.T) {
	s := NewSet[string]()
	require.NotNil(t, s)
}

func TestAdd_SingleCall_StoresValue(t *testing.T) {
	s := NewSet[string]()
	s.Add("test")
	require.True(t, s.m["test"])
}

func TestAdd_MultipleCallsSameValue_StoresValue(t *testing.T) {
	s := NewSet[string]()
	s.Add("test")
	s.Add("test")
	require.True(t, s.m["test"])
}

func TestAdd_MultipleCallsDifferentValues_StoresValues(t *testing.T) {
	s := NewSet[string]()
	s.Add("test")
	s.Add("test2")
	require.True(t, s.m["test"])
	require.True(t, s.m["test2"])
}

func TestDelete_RemovesValue(t *testing.T) {
	s := NewSet[string]()
	s.Add("test")
	require.True(t, s.m["test"])
	s.Delete("test")
	require.False(t, s.m["test"])
}

func TestContains_ReturnsTrue_GivenValuePresent(t *testing.T) {
	s := NewSet[string]()
	s.Add("test")
	require.True(t, s.Contains("test"))
}

func TestContains_ReturnsFalse_GivenValueNotPresent(t *testing.T) {
	s := NewSet[string]()
	s.Add("test")
	require.False(t, s.Contains("test2"))
}

func TestLen_ReturnsZero_GivenEmptySet(t *testing.T) {
	s := NewSet[string]()
	require.Equal(t, 0, s.Len())
}

func TestLen_ReturnsFive_GivenSetWithFiveElements(t *testing.T) {
	s := NewSet[string]()
	s.Add("test")
	s.Add("test2")
	s.Add("test3")
	s.Add("test4")
	s.Add("test5")
	require.Equal(t, 5, s.Len())
}

func TestValues_YieldsAllValues_GivenSetWithMultipleElements(t *testing.T) {
	s := NewSet[string]()
	s.Add("test")
	s.Add("test2")
	s.Add("test3")

	values := slices.Collect(s.Values())
	require.ElementsMatch(t, []string{"test", "test2", "test3"}, values)
}
