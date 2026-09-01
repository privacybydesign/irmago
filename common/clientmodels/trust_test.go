package clientmodels

import (
	"encoding/json"
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

// The rung values are wire format: the app switches on them.
func TestTrustLevel_WireValues(t *testing.T) {
	require.Equal(t, TrustLevel("low"), TrustLevel_Low)
	require.Equal(t, TrustLevel("medium"), TrustLevel_Medium)
	require.Equal(t, TrustLevel("high"), TrustLevel_High)
	require.Equal(t, TrustLevel(""), TrustLevel_Unevaluated)
}

// A party nothing was evaluated for must reach the app as an absent field, so it
// can render levelless rather than as a verdict of low.
func TestTrustedParty_UnevaluatedLevelIsOmittedFromJson(t *testing.T) {
	unevaluated, err := json.Marshal(TrustedParty{Id: "party"})
	require.NoError(t, err)
	require.NotContains(t, string(unevaluated), "trust_level")

	ranked, err := json.Marshal(TrustedParty{Id: "party", TrustLevel: TrustLevel_Low})
	require.NoError(t, err)
	require.Contains(t, string(ranked), `"trust_level":"low"`)
}
