package services

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/lote"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

func TestTrustService_WithoutARecognizedList(t *testing.T) {
	view := NewTrustService(nil).Snapshot(context.Background())

	certified := view.Verifier(trust.Evidence{Certificate: &x509.Certificate{}})
	require.Equal(t, clientmodels.TrustLevel_High, certified.Level)
	require.Nil(t, certified.Listing, "no list is consulted, so no verdict can carry a listing")

	bare := view.Issuer(trust.Evidence{Identifiers: []string{"https://issuer.example.com"}})
	require.Equal(t, clientmodels.TrustLevel_Low, bare.Level)
	require.Nil(t, bare.Listing)
}

func TestTrustService_ListedPartyReachesMedium(t *testing.T) {
	signer := lote.NewTestListSigner(t)
	server := lote.NewTestListServer(t)
	server.Serve(t, signer, lote.NewTestList(lote.TestListOpts{
		Id:         "yivi-test",
		NextUpdate: time.Now().Add(time.Hour),
		Providers: []lote.TrustServiceProvider{
			lote.GrantedIssuer("Listed Issuer", lote.UriIdentity("https://issuer.example.com")),
		},
	}))
	checker := lote.NewChecker([]lote.RecognizedList{server.RecognizedList("yivi-test", signer)}, nil)

	view := NewTrustService(checker).Snapshot(context.Background())

	listed := view.Issuer(trust.Evidence{Identifiers: []string{"https://issuer.example.com"}})
	require.Equal(t, clientmodels.TrustLevel_Medium, listed.Level)
	require.NotNil(t, listed.Listing)
	require.Equal(t, "Listed Issuer", listed.Listing.Name["en"])

	require.Equal(t, clientmodels.TrustLevel_Low,
		view.Verifier(trust.Evidence{Identifiers: []string{"https://issuer.example.com"}}).Level,
		"the same party is not thereby trusted to ask for credentials")
}

func TestTrustService_SnapshotSurvivesACancelledContext(t *testing.T) {
	// Evaluation is fail-soft: a session whose context is already done still
	// gets a usable view rather than an error it would have to turn into a
	// session failure. The list fetch it cannot make is simply absent evidence.
	signer := lote.NewTestListSigner(t)
	server := lote.NewTestListServer(t)
	server.Serve(t, signer, lote.NewTestList(lote.TestListOpts{
		Id: "yivi-test",
		Providers: []lote.TrustServiceProvider{
			lote.GrantedVerifier("Listed Verifier", lote.DidIdentity("did:web:verifier.example.com")),
		},
	}))
	checker := lote.NewChecker([]lote.RecognizedList{server.RecognizedList("yivi-test", signer)}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	view := NewTrustService(checker).Snapshot(ctx)
	require.NotNil(t, view)
	require.Equal(t, clientmodels.TrustLevel_Low,
		view.Verifier(trust.Evidence{Identifiers: []string{"did:web:verifier.example.com"}}).Level)
}
