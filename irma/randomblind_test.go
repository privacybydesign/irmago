package irma

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestGetCredentialInfoListLogRenderNilVersion guards the read-only log-render path. Stored
// issuance logs have their CredentialInfoList populated at session time and may have been written
// without a protocol version (older app versions). Rendering such a log calls GetCredentialInfoList
// with that possibly-nil version; it must return the cached list without running the random blind
// consistency check (which needs the negotiated version) and without dereferencing the nil version.
func TestGetCredentialInfoListLogRenderNilVersion(t *testing.T) {
	conf := parseConfiguration(t)

	ir := NewIssuanceRequest([]*CredentialRequest{{
		CredentialTypeID: NewCredentialTypeIdentifier("irma-demo.stemmen.stempas"),
		Attributes:       map[string]string{"election": "plantsoen"},
	}})
	// Simulate a stored log entry: info list already computed, and a mismatching identifier that
	// the old (in-GetCredentialInfoList) check would have rejected.
	ir.CredentialInfoList = CredentialInfoList{}
	ir.Credentials[0].RandomBlindAttributeTypeIDs = []string{"stale-identifier"}

	require.NotPanics(t, func() {
		list, err := ir.GetCredentialInfoList(conf, nil, time.Now())
		require.NoError(t, err)
		require.NotNil(t, list)
	})
}

// TestCheckRandomBlindConsistencyVersionGate covers the client half of the four cross-version cases:
// the identifiers the client expects on the wire depend on the negotiated protocol version, and a
// nil version is treated as pre-2.9.
func TestCheckRandomBlindConsistencyVersionGate(t *testing.T) {
	conf := parseConfiguration(t)

	credID := NewCredentialTypeIdentifier("irma-demo.stemmen.stempas")
	credtype := conf.CredentialTypes[credID]
	require.NotNil(t, credtype)

	corrected := credtype.RandomBlindAttributeNames()
	legacy := credtype.RandomBlindAttributeNamesLegacy()
	require.Equal(t, []string{"votingnumber"}, corrected)
	require.Empty(t, legacy) // votingnumber is the last attribute, so the off-by-one ran off the end

	request := func(wire []string) *IssuanceRequest {
		ir := NewIssuanceRequest([]*CredentialRequest{{
			CredentialTypeID: credID,
			Attributes:       map[string]string{"election": "plantsoen"},
		}})
		ir.Credentials[0].RandomBlindAttributeTypeIDs = wire
		return ir
	}

	v28, v29 := NewVersion(2, 8), NewVersion(2, 9)

	// Peers agree: accepted.
	require.NoError(t, request(corrected).CheckRandomBlindConsistency(conf, v29))
	require.NoError(t, request(legacy).CheckRandomBlindConsistency(conf, v28))
	require.NoError(t, request(legacy).CheckRandomBlindConsistency(conf, nil))

	// Wire value does not match what the negotiated version expects: rejected.
	require.Error(t, request(legacy).CheckRandomBlindConsistency(conf, v29))
	require.Error(t, request(corrected).CheckRandomBlindConsistency(conf, v28))
	require.Error(t, request(corrected).CheckRandomBlindConsistency(conf, nil))
}
