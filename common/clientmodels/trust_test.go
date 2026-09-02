package clientmodels

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// One rule decides the trusted marker for every party the wallet shows: somebody
// beyond the party itself vouches for it.
func TestTrustLevel_IsVouchedFor(t *testing.T) {
	vouchedFor := map[TrustLevel]bool{
		TrustLevel_Unevaluated: false,
		TrustLevel_Low:         false,
		TrustLevel_Medium:      true,
		TrustLevel_High:        true,
	}
	for level, expected := range vouchedFor {
		require.Equal(t, expected, level.IsVouchedFor(), "level %q", level)
	}
}

// The rung values are wire format: the app switches on them, and the wallet
// config spells them out.
func TestTrustLevel_WireValues(t *testing.T) {
	require.Equal(t, TrustLevel("low"), TrustLevel_Low)
	require.Equal(t, TrustLevel("medium"), TrustLevel_Medium)
	require.Equal(t, TrustLevel("high"), TrustLevel_High)
	require.Equal(t, TrustLevel(""), TrustLevel_Unevaluated)
}

func TestTrustLevel_IsRung(t *testing.T) {
	for _, rung := range []TrustLevel{TrustLevel_Low, TrustLevel_Medium, TrustLevel_High} {
		require.True(t, rung.IsRung(), "level %q", rung)
	}
	for _, notARung := range []TrustLevel{TrustLevel_Unevaluated, "LOW", "very_high", "mid"} {
		require.False(t, notARung.IsRung(), "level %q", notARung)
	}
}
