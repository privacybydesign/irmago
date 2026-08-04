package services

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

func TestTrustService_RunsDark(t *testing.T) {
	view := NewTrustService(nil).Snapshot(context.Background())

	certified := view.Verifier(trust.Evidence{Certificate: &x509.Certificate{}})
	require.Equal(t, clientmodels.TrustLevel_High, certified.Level)
	require.Nil(t, certified.Listing, "no list is consulted yet, so no verdict can carry a listing")

	bare := view.Issuer(trust.Evidence{Identifiers: []string{"https://issuer.example.com"}})
	require.Equal(t, clientmodels.TrustLevel_Low, bare.Level)
	require.Nil(t, bare.Listing)
}

func TestTrustService_SnapshotSurvivesACancelledContext(t *testing.T) {
	// Evaluation is fail-soft: a session whose context is already done still
	// gets a usable view rather than an error it would have to turn into a
	// session failure.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	view := NewTrustService(nil).Snapshot(ctx)
	require.NotNil(t, view)
	require.Equal(t, clientmodels.TrustLevel_Low, view.Verifier(trust.Evidence{}).Level)
}
