package lote

import (
	"context"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/trust"
	"github.com/stretchr/testify/require"
)

// eudi.Logger is a package global that client.New assigns, so it is nil in any
// process that has not built a wallet — and NewChecker takes no logger, so
// nothing in this package's API tells a caller that one has to exist first. Every
// fail-soft path here logs, which is precisely where a nil logger would turn
// "carry on without this list" into a crash. TestMain sets the global, which is
// what otherwise hides this.

func TestChecker_FailSoftPathsSurviveANilLogger(t *testing.T) {
	t.Run("Refresh reporting an unreachable source", testRefreshWithoutALogger)
	t.Run("Snapshot ignoring a list past its next_update", testSnapshotWithoutALogger)
}

func testRefreshWithoutALogger(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	f.server.SetStatus(503)

	withoutLogger(t)

	_, err := NewChecker(f.config).Refresh(context.Background())

	require.Error(t, err, "the source failed, and saying so must not depend on a logger")
}

func testSnapshotWithoutALogger(t *testing.T) {
	f := newFixture(t, clientmodels.TrustLevel_Medium)
	party := f.signer.NewTestPartyCertificate(t, "party.example.com", "")
	list := NewTestList(testListId, 1,
		NewTestEntity("Listed BV", "", NewTestCertificateService(trust.RoleVerifier, party)))
	list.SchemeInformation.NextUpdate = time.Now().Add(time.Hour)
	f.server.Serve(t, f.signer, list)

	// A clock the test moves past the list's next_update: Snapshot then says so
	// and drops the list, on the evaluation path.
	now := time.Now()
	f.config.Now = func() time.Time { return now }
	checker := f.refreshed(t)
	now = now.Add(2 * time.Hour)

	withoutLogger(t)

	require.Nil(t, checker.Snapshot().Lookup(trust.RoleVerifier, trust.Evidence{Certificate: party}))
}

// withoutLogger drops the package global for the duration of one test.
func withoutLogger(t *testing.T) {
	t.Helper()

	logger := eudi.Logger
	eudi.Logger = nil
	t.Cleanup(func() { eudi.Logger = logger })
}
