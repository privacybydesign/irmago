package clientmodels

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClaimPatternKey(t *testing.T) {
	// Every array position becomes the wildcard, however it is written.
	require.Equal(t, ClaimPathKey([]any{"degrees", nil, "name"}), ClaimPatternKey([]any{"degrees", 0, "name"}))
	require.Equal(t, ClaimPathKey([]any{"degrees", nil, "name"}), ClaimPatternKey([]any{"degrees", float64(3), "name"}))
	require.Equal(t, ClaimPathKey([]any{"degrees", nil, "name"}), ClaimPatternKey([]any{"degrees", nil, "name"}))
	// Names stay as they are.
	require.Equal(t, ClaimPathKey([]any{"address", "street"}), ClaimPatternKey([]any{"address", "street"}))
	require.Equal(t, ClaimPathKey([]any{"email"}), ClaimPatternKey([]any{"email"}))
}
