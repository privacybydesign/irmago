package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	dbpkg "github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// newRefreshService builds a RevocationService for the status-refresh tests.
func newRefreshService(db *gorm.DB, checker *statuslist.Checker) *RevocationService {
	return NewRevocationService(checker, dbpkg.NewCredentialStore(db))
}

func seedBatch(t *testing.T, db *gorm.DB, hash, issuer string, instances []models.IssuedCredentialInstance) *models.CredentialBatch {
	t.Helper()
	batch := &models.CredentialBatch{
		IssuerIdentifier:           issuer,
		VerifiableCredentialType:   "https://vct.example/x",
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       hash,
		ProcessedSdJwtPayload:      datatypes.JSON(`{"sub":"u"}`),
		IssuedAt:                   datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                  uint(len(instances)),
		RemainingCount:             uint(len(instances)),
		CredentialIssuerIdentifier: issuer,
		Instances:                  instances,
	}
	require.NoError(t, db.Create(batch).Error)
	return batch
}

// refresh runs one sweep and returns the number of status changes it observed.
func refresh(t *testing.T, svc *RevocationService) int {
	t.Helper()
	changed, err := svc.RefreshStatuses(context.Background())
	require.NoError(t, err)
	return changed
}

func instanceWithStatus(uri string, idx uint64) models.IssuedCredentialInstance {
	u := uri
	i := idx
	return models.IssuedCredentialInstance{
		RawCredential: []byte("raw"),
		StatusListURI: &u,
		StatusListIdx: &i,
	}
}

func Test_RefreshStatuses_NilChecker_NoOp(t *testing.T) {
	db := newTestHolderDB(t)
	svc := newRefreshService(db, nil)
	require.Zero(t, refresh(t, svc))
}

func Test_RefreshStatuses_NoInstancesWithStatus_NoOp(t *testing.T) {
	db := newTestHolderDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())
	// Seed a batch but no status references.
	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{
		{RawCredential: []byte("raw")},
	})

	svc := newRefreshService(db, checker)
	require.Zero(t, refresh(t, svc))
}

func Test_RefreshStatuses_OneFetchPerSharedURI_OneRepresentativePerBatch(t *testing.T) {
	db := newTestHolderDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	// One status list shared across batches, all copies Valid.
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 0, 2: 0},
	})
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	// Two batches sharing one status list URI: batch A has two instances
	// (idx 0,1), batch B one (idx 2). The sweep must fetch the shared URI once
	// and refresh exactly one representative per batch.
	batchA := seedBatch(t, db, "hA", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus(srv.URL(), 0),
		instanceWithStatus(srv.URL(), 1),
	})
	seedBatch(t, db, "hB", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus(srv.URL(), 2),
	})

	svc := newRefreshService(db, checker)
	// One change per batch, not per row: both representatives moved off their
	// seeded default, and batch A's second instance was never looked at.
	require.Equal(t, 2, refresh(t, svc))

	// Shared URI fetched exactly once (Refresh warms the cache; each
	// representative's Check reads from it).
	require.Equal(t, int64(1), srv.Hits())

	// Exactly one instance per batch was refreshed (LastStatusCheckAt set),
	// i.e. two across the two batches, each reading Valid.
	var all []models.IssuedCredentialInstance
	require.NoError(t, db.Find(&all).Error)
	checked := 0
	for _, r := range all {
		if r.LastStatusCheckAt != nil {
			checked++
			require.Equal(t, uint8(statuslist.StatusValid), r.LastKnownStatus)
		}
	}
	require.Equal(t, 2, checked, "one representative per batch (2 batches)")

	// The multi-instance batch A had only one of its two instances refreshed.
	var batchARows []models.IssuedCredentialInstance
	require.NoError(t, db.Where("credential_batch_id = ?", batchA.ID).Find(&batchARows).Error)
	require.Len(t, batchARows, 2)
	batchAChecked := 0
	for _, r := range batchARows {
		if r.LastStatusCheckAt != nil {
			batchAChecked++
		}
	}
	require.Equal(t, 1, batchAChecked, "only one representative refreshed in a multi-instance batch")
}

// Test_RefreshStatuses_MultiInstanceBatch_OneRepresentativeDrivesRevocation
// verifies that for a batch with several instances the sweep refreshes only a
// single representative, yet the batch is still reported revoked once that
// representative's bit reads Invalid (the read path's "any invalid" rule).
func Test_RefreshStatuses_MultiInstanceBatch_OneRepresentativeDrivesRevocation(t *testing.T) {
	db := newTestHolderDB(t)
	signer := statuslist.NewTestStatusListSigner(t)

	// All three copies of the batch are revoked together by the issuer.
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 1, 1: 1, 2: 1},
	})
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus(srv.URL(), 0),
		instanceWithStatus(srv.URL(), 1),
		instanceWithStatus(srv.URL(), 2),
	})

	svc := newRefreshService(db, checker)
	// A three-instance batch yields one change, not three: the count is per
	// batch, because only the representative is ever checked.
	require.Equal(t, 1, refresh(t, svc))

	// Only one representative was checked and flipped to Invalid; the others
	// keep their default status.
	var rows []models.IssuedCredentialInstance
	require.NoError(t, db.Find(&rows).Error)
	checked, invalid := 0, 0
	for _, r := range rows {
		if r.LastStatusCheckAt != nil {
			checked++
		}
		if statuslist.Status(r.LastKnownStatus) == statuslist.StatusInvalid {
			invalid++
		}
	}
	require.Equal(t, 1, checked, "exactly one representative refreshed")
	require.Equal(t, 1, invalid, "only the representative flipped to Invalid")

	// The batch's derived revocation ("any status-referenced instance Invalid")
	// is still true from the single representative.
	statuses, err := dbpkg.NewCredentialStore(db).ListStatusReferencedInstanceStatuses()
	require.NoError(t, err)
	revoked := false
	for _, st := range statuses {
		if st.Hash == "h1" && statuslist.Status(st.LastKnownStatus) == statuslist.StatusInvalid {
			revoked = true
		}
	}
	require.True(t, revoked, "batch revoked once its representative reads Invalid")
}

// Test_RefreshStatuses_DetectsRevocationTransition is the end-to-end guarantee
// behind the background refresh: a credential seen as Valid on one sweep is
// reported as Invalid on the next once the issuer flips its status bit. It
// also pins the cache-bypass property — RefreshStatuses must re-fetch and not
// return the previously-cached "valid" value, otherwise a revocation would
// never be observed until the TTL happened to expire.
func Test_RefreshStatuses_DetectsRevocationTransition(t *testing.T) {
	db := newTestHolderDB(t)
	signer := statuslist.NewTestStatusListSigner(t)

	// Initially the credential at idx 4 is Valid.
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{4: 0}, // Valid
	})
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus(srv.URL(), 4),
	})
	svc := newRefreshService(db, checker)

	// First sweep: the wallet records the credential as Valid.
	require.Equal(t, 1, refresh(t, svc), "moving off the seeded default is a change")
	var row models.IssuedCredentialInstance
	require.NoError(t, db.First(&row, "status_list_uri = ?", srv.URL()).Error)
	require.Equal(t, uint8(statuslist.StatusValid), row.LastKnownStatus)

	// Sweeping again over an unchanged list re-confirms Valid and reports no
	// change: the freshness stamp moves, the status does not.
	require.Zero(t, refresh(t, svc), "re-confirming the same status is not a change")

	// The issuer revokes the credential by flipping the bit at idx 4.
	srv.Serve(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{4: 1}, // Invalid (revoked)
	})

	// Next sweep must pick up the revocation despite the earlier cached
	// Valid value — RefreshStatuses re-fetches by design.
	require.Equal(t, 1, refresh(t, svc), "Valid -> Invalid is a change")
	require.NoError(t, db.First(&row, "status_list_uri = ?", srv.URL()).Error)
	require.Equal(t, uint8(statuslist.StatusInvalid), row.LastKnownStatus)

	// And the revocation, once recorded, is not re-reported on every later sweep.
	require.Zero(t, refresh(t, svc), "a known revocation is re-confirmed silently")
}

func Test_RefreshStatuses_OneURIFailure_DoesNotAbortSweep(t *testing.T) {
	db := newTestHolderDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	good := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	// One representative per batch is checked, so put the failing and the good
	// URI in SEPARATE batches to prove one batch's failure doesn't abort the
	// sweep for the other.
	seedBatch(t, db, "hbad", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus("http://127.0.0.1:0/nope", 0), // unreachable
	})
	seedBatch(t, db, "hgood", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus(good.URL(), 0), // good
	})

	svc := newRefreshService(db, checker)
	// Only the reachable batch counts: the failure left the other's status
	// alone, so nothing about it changed.
	require.Equal(t, 1, refresh(t, svc))

	// The good one should be updated to Valid; the failing one
	// should remain at default (Unknown == 0).
	var rows []models.IssuedCredentialInstance
	require.NoError(t, db.Find(&rows).Error)
	statusesByURI := map[string]uint8{}
	for _, r := range rows {
		statusesByURI[*r.StatusListURI] = r.LastKnownStatus
	}
	require.Equal(t, uint8(statuslist.StatusValid), statusesByURI[good.URL()])
	require.Equal(t, uint8(0), statusesByURI["http://127.0.0.1:0/nope"])
}

// Test_RefreshStatuses_CancelledFetch_ReportsCancellation separates the two
// kinds of fetch failure: an unreachable URI is fail-soft and skipped, but a
// fetch aborted because ctx was cancelled means the sweep was cut short, and the
// caller has to be able to tell that from a sweep that looked at everything.
// Without it, cancellation landing in the last group's fetch returns nil.
func Test_RefreshStatuses_CancelledFetch_ReportsCancellation(t *testing.T) {
	db := newTestHolderDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A status list whose fetch never completes: it cancels the sweep and then
	// waits for the aborted request to be dropped.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cancel()
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus(srv.URL, 0),
	})

	svc := newRefreshService(db, checker)
	changed, err := svc.RefreshStatuses(ctx)
	require.ErrorIs(t, err, context.Canceled, "a cancelled fetch is a cut-short sweep, not a skipped URI")
	require.Zero(t, changed)

	// And nothing was written back, so the change is still there to find.
	var row models.IssuedCredentialInstance
	require.NoError(t, db.First(&row, "status_list_uri = ?", srv.URL).Error)
	require.Nil(t, row.LastStatusCheckAt)
}

func Test_RefreshStatuses_OnlyUpdatesOnSuccess(t *testing.T) {
	db := newTestHolderDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	// Pre-seed an instance with LastKnownStatus = Suspended (set on
	// the row directly). After a failing refresh, the value must
	// remain Suspended.
	uri := "http://127.0.0.1:0/nope"
	idx := uint64(0)
	checked := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	inst := models.IssuedCredentialInstance{
		RawCredential:     []byte("raw"),
		StatusListURI:     &uri,
		StatusListIdx:     &idx,
		LastKnownStatus:   uint8(statuslist.StatusSuspended),
		LastStatusCheckAt: &checked,
	}
	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{inst})

	svc := newRefreshService(db, checker)
	// A sweep whose every fetch failed changed nothing, so it reports nothing.
	require.Zero(t, refresh(t, svc), "a failed refresh is not a status change")

	var row models.IssuedCredentialInstance
	require.NoError(t, db.First(&row, "status_list_uri = ?", uri).Error)
	require.Equal(t, uint8(statuslist.StatusSuspended), row.LastKnownStatus, "failed refresh must not overwrite previous status")
	require.WithinDuration(t, checked, row.LastStatusCheckAt.UTC(), time.Second)
}

// Test_ScheduledRefresh_PicksUpRevocation is the closest robust analogue of a
// full client-level test: it drives the sweep on a real gocron scheduler wired
// exactly as client.InitJobs does (a DurationJob that starts immediately and
// repeats), against a real DB, a real Checker and a real status server. It
// proves the *automatic*, timer-driven path detects a Valid -> revoked
// transition without any manual RefreshStatuses call.
//
// The client-side wiring — that a status change reaches the app — is pinned
// separately in client/status_change_notification_test.go, which seeds a
// status-bearing batch into a real Client's eudi DB. This test stays at the
// service layer and covers the timer.
func Test_ScheduledRefresh_PicksUpRevocation(t *testing.T) {
	db := newTestHolderDB(t)
	signer := statuslist.NewTestStatusListSigner(t)

	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{9: 0}, // Valid
	})
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus(srv.URL(), 9),
	})
	svc := newRefreshService(db, checker)

	// Wire the sweep onto a gocron scheduler exactly as client.InitJobs does.
	scheduler, err := gocron.NewScheduler()
	require.NoError(t, err)
	_, err = scheduler.NewJob(
		gocron.DurationJob(30*time.Millisecond),
		gocron.NewTask(func() { _, _ = svc.RefreshStatuses(context.Background()) }),
		gocron.WithStartAt(gocron.WithStartImmediately()),
	)
	require.NoError(t, err)
	scheduler.Start()
	t.Cleanup(func() { _ = scheduler.Shutdown() })

	statusOf := func() uint8 {
		var row models.IssuedCredentialInstance
		require.NoError(t, db.First(&row, "status_list_uri = ?", srv.URL()).Error)
		return row.LastKnownStatus
	}

	// The scheduled sweep records the credential as Valid.
	require.Eventually(t, func() bool { return statusOf() == uint8(statuslist.StatusValid) },
		3*time.Second, 20*time.Millisecond, "scheduled refresh should record Valid")

	// Issuer revokes the credential by flipping the bit at idx 9.
	srv.Serve(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{9: 1}, // Invalid (revoked)
	})

	// A later scheduled sweep must pick up the revocation automatically —
	// RefreshStatuses bypasses the cache, so the flip is observed on the next tick.
	require.Eventually(t, func() bool { return statusOf() == uint8(statuslist.StatusInvalid) },
		3*time.Second, 20*time.Millisecond, "scheduled refresh should pick up the revocation")
}
