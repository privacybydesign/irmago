package services

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	dbpkg "github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/db/sqlcipher"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func newTestRefreshDB(t *testing.T) *gorm.DB {
	t.Helper()
	d, err := gorm.Open(sqlcipher.Dialector{Connector: sqlcipher.NewConnector(":memory:", []byte("test-key-refresh"))}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, d.AutoMigrate(
		&models.HolderBindingKey{},
		&models.ECDSAKeyMetadata{},
		&models.RSAKeyMetadata{},
		&models.IssuerMetadataDisplay{},
		&models.CredentialMetadata{},
		&models.CredentialDisplay{},
		&models.CredentialClaim{},
		&models.ClaimDisplay{},
		&models.CredentialBatch{},
		&models.IssuedCredentialInstance{},
		&models.StatusListCacheEntry{},
	))
	return d
}

func seedBatch(t *testing.T, db *gorm.DB, hash, issuer string, instances []models.IssuedCredentialInstance) *models.CredentialBatch {
	t.Helper()
	batch := &models.CredentialBatch{
		IssuerURL:                issuer,
		VerifiableCredentialType: "https://vct.example/x",
		Format:                   models.CredentialFormatSdJwtVc,
		Hash:                     hash,
		ProcessedSdJwtPayload:    datatypes.JSON(`{"sub":"u"}`),
		IssuedAt:                 datatypes.NullTime{V: time.Now().UTC().Truncate(time.Second), Valid: true},
		BatchSize:                uint(len(instances)),
		RemainingCount:           uint(len(instances)),
		CredentialIssuer:         issuer,
		Instances:                instances,
	}
	require.NoError(t, db.Create(batch).Error)
	return batch
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

func Test_RefreshAll_NilChecker_NoOp(t *testing.T) {
	db := newTestRefreshDB(t)
	svc := NewStatusRefreshService(dbpkg.NewCredentialStore(db), nil)
	require.NoError(t, svc.RefreshAll(context.Background()))
}

func Test_RefreshAll_NoInstancesWithStatus_NoOp(t *testing.T) {
	db := newTestRefreshDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())
	// Seed a batch but no status references.
	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{
		{RawCredential: []byte("raw")},
	})

	svc := NewStatusRefreshService(dbpkg.NewCredentialStore(db), checker)
	require.NoError(t, svc.RefreshAll(context.Background()))
}

func Test_RefreshAll_GroupsByURI_OneFetchPerURI(t *testing.T) {
	db := newTestRefreshDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	// Single URI, multiple credentials at different idx values.
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 0, 2: 1},
	})
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus(srv.URL(), 0),
		instanceWithStatus(srv.URL(), 1),
		instanceWithStatus(srv.URL(), 2),
	})

	svc := NewStatusRefreshService(dbpkg.NewCredentialStore(db), checker)
	require.NoError(t, svc.RefreshAll(context.Background()))

	// Exactly one HTTP hit per Refresh + per Check would be 1 + 3,
	// but the Check calls read from cache populated by Refresh, so
	// only 1 backend hit overall.
	require.Equal(t, int64(1), srv.Hits())

	// Status writeback: idx 0,1 → Valid; idx 2 → Invalid.
	var rows []models.IssuedCredentialInstance
	require.NoError(t, db.Find(&rows).Error)
	statuses := map[uint64]uint8{}
	for _, r := range rows {
		require.NotNil(t, r.StatusListIdx)
		statuses[*r.StatusListIdx] = r.LastKnownStatus
		require.NotNil(t, r.LastStatusCheckAt)
	}
	require.Equal(t, uint8(statuslist.StatusValid), statuses[0])
	require.Equal(t, uint8(statuslist.StatusValid), statuses[1])
	require.Equal(t, uint8(statuslist.StatusInvalid), statuses[2])
}

// Test_RefreshAll_DetectsRevocationTransition is the end-to-end guarantee
// behind the background refresh: a credential seen as Valid on one sweep is
// reported as Invalid on the next once the issuer flips its status bit. It
// also pins the cache-bypass property — RefreshAll must re-fetch and not
// return the previously-cached "valid" value, otherwise a revocation would
// never be observed until the TTL happened to expire.
func Test_RefreshAll_DetectsRevocationTransition(t *testing.T) {
	db := newTestRefreshDB(t)
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
	svc := NewStatusRefreshService(dbpkg.NewCredentialStore(db), checker)

	// First sweep: the wallet records the credential as Valid.
	require.NoError(t, svc.RefreshAll(context.Background()))
	var row models.IssuedCredentialInstance
	require.NoError(t, db.First(&row, "status_list_uri = ?", srv.URL()).Error)
	require.Equal(t, uint8(statuslist.StatusValid), row.LastKnownStatus)

	// The issuer revokes the credential by flipping the bit at idx 4.
	srv.Serve(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{4: 1}, // Invalid (revoked)
	})

	// Next sweep must pick up the revocation despite the earlier cached
	// Valid value — RefreshAll re-fetches by design.
	require.NoError(t, svc.RefreshAll(context.Background()))
	require.NoError(t, db.First(&row, "status_list_uri = ?", srv.URL()).Error)
	require.Equal(t, uint8(statuslist.StatusInvalid), row.LastKnownStatus)
}

func Test_RefreshAll_OneURIFailure_DoesNotAbortSweep(t *testing.T) {
	db := newTestRefreshDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	good := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus("http://127.0.0.1:0/nope", 0), // unreachable
		instanceWithStatus(good.URL(), 0),                // good
	})

	svc := NewStatusRefreshService(dbpkg.NewCredentialStore(db), checker)
	require.NoError(t, svc.RefreshAll(context.Background()))

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

func Test_RefreshAll_OnlyUpdatesOnSuccess(t *testing.T) {
	db := newTestRefreshDB(t)
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

	svc := NewStatusRefreshService(dbpkg.NewCredentialStore(db), checker)
	require.NoError(t, svc.RefreshAll(context.Background()))

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
// transition without any manual RefreshAll call.
//
// A literal through-client.New() test is not achievable today: no issuer-side
// code emits a status_list claim (so real issuance can't produce a
// status-bearing credential), and the Client exposes no seam to seed one into
// its eudi DB. This test therefore mirrors the client's wiring at the service
// layer instead.
func Test_ScheduledRefresh_PicksUpRevocation(t *testing.T) {
	db := newTestRefreshDB(t)
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
	svc := NewStatusRefreshService(dbpkg.NewCredentialStore(db), checker)

	// Wire the sweep onto a gocron scheduler exactly as client.InitJobs does.
	scheduler, err := gocron.NewScheduler()
	require.NoError(t, err)
	_, err = scheduler.NewJob(
		gocron.DurationJob(30*time.Millisecond),
		gocron.NewTask(func() { _ = svc.RefreshAll(context.Background()) }),
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
	// RefreshAll bypasses the cache, so the flip is observed on the next tick.
	require.Eventually(t, func() bool { return statusOf() == uint8(statuslist.StatusInvalid) },
		3*time.Second, 20*time.Millisecond, "scheduled refresh should pick up the revocation")
}

func Test_StartTicker_FiresAndStops(t *testing.T) {
	db := newTestRefreshDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	var hits atomic.Int64
	tracker := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})
	// Wrap server hits via the underlying tracker.Hits() count.

	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	seedBatch(t, db, "h1", "https://issuer.example", []models.IssuedCredentialInstance{
		instanceWithStatus(tracker.URL(), 0),
	})

	svc := NewStatusRefreshService(dbpkg.NewCredentialStore(db), checker)
	stop := svc.StartTicker(context.Background(), 30*time.Millisecond)
	// Let at least one tick fire.
	require.Eventually(t, func() bool { return tracker.Hits() >= 1 }, 2*time.Second, 5*time.Millisecond)
	stop()

	// After stop, no further hits within a small window.
	before := tracker.Hits()
	hits.Store(before)
	time.Sleep(150 * time.Millisecond)
	require.Equal(t, before, tracker.Hits(), "ticker must stop firing after stop()")
}

func Test_StartTicker_NoOpForNonPositiveInterval(t *testing.T) {
	db := newTestRefreshDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())
	svc := NewStatusRefreshService(dbpkg.NewCredentialStore(db), checker)

	// Should return without panicking and be safely callable.
	stop := svc.StartTicker(context.Background(), 0)
	stop()
}
