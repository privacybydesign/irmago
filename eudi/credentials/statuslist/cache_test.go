package statuslist

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_InMemoryCache_GetMiss_ReturnsFalse(t *testing.T) {
	c := NewInMemoryCache()
	_, _, ok := c.Get("https://example.com/list")
	require.False(t, ok)
}

func Test_InMemoryCache_PutThenGet_RoundtripsValueAndExpiry(t *testing.T) {
	c := NewInMemoryCache()
	expires := time.Now().Add(time.Hour)
	require.NoError(t, c.Put("uri", []byte("raw-jwt"), expires))

	raw, gotExpires, ok := c.Get("uri")
	require.True(t, ok)
	require.Equal(t, []byte("raw-jwt"), raw)
	require.WithinDuration(t, expires, gotExpires, time.Millisecond)
}

func Test_InMemoryCache_Delete_RemovesEntry(t *testing.T) {
	c := NewInMemoryCache()
	require.NoError(t, c.Put("uri", []byte("v"), time.Now().Add(time.Hour)))
	require.NoError(t, c.Delete("uri"))
	_, _, ok := c.Get("uri")
	require.False(t, ok)
}

func Test_InMemoryCache_OverwritesExistingEntry(t *testing.T) {
	c := NewInMemoryCache()
	require.NoError(t, c.Put("uri", []byte("v1"), time.Now().Add(time.Hour)))
	require.NoError(t, c.Put("uri", []byte("v2"), time.Now().Add(2*time.Hour)))
	raw, _, ok := c.Get("uri")
	require.True(t, ok)
	require.Equal(t, []byte("v2"), raw)
}

func Test_InMemoryCache_ConcurrentReadsAndWrites(t *testing.T) {
	c := NewInMemoryCache()
	const n = 200
	var wg sync.WaitGroup
	wg.Add(2 * n)
	for range n {
		go func() { defer wg.Done(); _ = c.Put("uri", []byte("v"), time.Now().Add(time.Hour)) }()
		go func() { defer wg.Done(); _, _, _ = c.Get("uri") }()
	}
	wg.Wait()
}

func Test_ClampTTL_BelowFloor_ReturnsFloor(t *testing.T) {
	require.Equal(t, TTLMin, ClampTTL(5*time.Second))
}

func Test_ClampTTL_AboveCeiling_ReturnsCeiling(t *testing.T) {
	require.Equal(t, TTLMax, ClampTTL(7*24*time.Hour))
}

func Test_ClampTTL_Zero_ReturnsDefault(t *testing.T) {
	require.Equal(t, TTLDefault, ClampTTL(0))
}

func Test_ClampTTL_Negative_ReturnsDefault(t *testing.T) {
	require.Equal(t, TTLDefault, ClampTTL(-time.Hour))
}

func Test_ClampTTL_WithinBounds_PassesThrough(t *testing.T) {
	d := 30 * time.Minute
	require.Equal(t, d, ClampTTL(d))
}
