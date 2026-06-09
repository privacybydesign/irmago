package services

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

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
	dsn := sqlcipher.DSN(":memory:", "test-key-refresh")
	d, err := gorm.Open(sqlcipher.Dialector{DSN: dsn}, &gorm.Config{})
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
		IssuedAt:                 time.Now().UTC().Truncate(time.Second),
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
	srv := statuslist.NewTestStatusListServer(t, signer.SignToken(t, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 0, 2: 1},
	}))
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

func Test_RefreshAll_OneURIFailure_DoesNotAbortSweep(t *testing.T) {
	db := newTestRefreshDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	good := statuslist.NewTestStatusListServer(t, signer.SignToken(t, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	}))
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

func Test_StartTicker_FiresAndStops(t *testing.T) {
	db := newTestRefreshDB(t)
	signer := statuslist.NewTestStatusListSigner(t)
	var hits atomic.Int64
	tracker := statuslist.NewTestStatusListServer(t, signer.SignToken(t, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	}))
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
