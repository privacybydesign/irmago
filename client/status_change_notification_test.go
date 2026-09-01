package client

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	eudi_jwt "github.com/privacybydesign/irmago/eudi/jwt"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testhelpers"
	"github.com/privacybydesign/irmago/irma"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// newClientForStatusRefresh builds an empty client whose status-list checker
// trusts signer. New builds one against the real issuer trust store, which would
// reject a test-signed token; everything else is the production wiring.
func newClientForStatusRefresh(t *testing.T, signer *statuslist.TestStatusListSigner) (*Client, *testhelpers.TestClientHandler) {
	t.Helper()

	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	handler := &testhelpers.TestClientHandler{T: t}
	c, err := New(Config{
		StoragePath:           storagePath,
		IrmaConfigurationPath: filepath.Join(path, "irma_configuration"),
		EudiAppDataPath:       eudiAppDataPath,
		Handler:               handler,
		Signer:                test.NewSigner(t),
		AesKey:                aesKey,
		Locale:                "en",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	c.revocationService = services.NewRevocationService(
		newStatusChecker(signer),
		db.NewCredentialStore(c.eudiStorage.Db()),
	)

	return c, handler
}

// newStatusChecker returns a checker that trusts signer, as the production one
// trusts the real issuer trust store.
func newStatusChecker(signer *statuslist.TestStatusListSigner) *statuslist.Checker {
	return statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
		Clock:       eudi_jwt.NewSystemClock(),
	}, statuslist.NewInMemoryCache())
}

// cancellingStore cancels a context as soon as a status writeback commits: the
// state a sweep is in when cancellation lands after it has already persisted a
// change (a later group's fetch that outlives the caller, or a shutdown
// mid-sweep).
type cancellingStore struct {
	db.CredentialStore
	cancel context.CancelFunc
}

func (s *cancellingStore) UpdateInstanceStatus(instanceID datatypes.UUID, status uint8, checkedAt time.Time) error {
	err := s.CredentialStore.UpdateInstanceStatus(instanceID, status, checkedAt)
	s.cancel()
	return err
}

// seedStatusBearingBatch stores a single-instance batch carrying a status list
// reference, seeded to Valid exactly as issuance does.
func seedStatusBearingBatch(t *testing.T, gdb *gorm.DB, hash, uri string, idx uint64) {
	t.Helper()

	iss := "https://issuer.example.com"
	u, i, now := uri, idx, time.Now().UTC()
	require.NoError(t, gdb.Create(&models.CredentialBatch{
		IssuerIdentifier:           iss,
		CredentialIssuerIdentifier: iss,
		VerifiableCredentialType:   "https://vct.example/x",
		Format:                     models.CredentialFormatSdJwtVc,
		Hash:                       hash,
		ProcessedSdJwtPayload:      datatypes.JSON(`{"sub":"u"}`),
		IssuedAt:                   datatypes.NullTime{V: now.Truncate(time.Second), Valid: true},
		BatchSize:                  1,
		RemainingCount:             1,
		Instances: []models.IssuedCredentialInstance{{
			RawCredential:     []byte("raw"),
			StatusListURI:     &u,
			StatusListIdx:     &i,
			LastKnownStatus:   uint8(statuslist.StatusValid),
			LastStatusCheckAt: &now,
		}},
	}).Error)
}

// TestIrmaHandlerReportsEachRevocationOnce pins the idemix half of the contract:
// IrmaClient rediscovers a revocation every few tens of seconds, and the adapter
// is what stops that reaching the app more than once.
func TestIrmaHandlerReportsEachRevocationOnce(t *testing.T) {
	handler := &testhelpers.TestClientHandler{T: t}
	adapter := newIrmaHandler(handler)

	credType := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
	first := &irma.CredentialIdentifier{Type: credType, Hash: "hash-1"}

	adapter.Revoked(first)
	require.Equal(t, 1, handler.CredentialsChangedCount(), "the first discovery reaches the app")

	adapter.Revoked(first)
	adapter.Revoked(first)
	require.Equal(t, 1, handler.CredentialsChangedCount(), "rediscovering the same revocation is silent")

	adapter.Revoked(&irma.CredentialIdentifier{Type: credType, Hash: "hash-2"})
	require.Equal(t, 2, handler.CredentialsChangedCount(), "a different credential is its own change")
}

// TestRefreshStatusesNotifiesOnStatusChange pins the wiring between the status
// refresh sweep and the app: a status change wakes the UI, a re-confirmation
// does not.
func TestRefreshStatusesNotifiesOnStatusChange(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{7: 0}, // Valid
	})

	c, handler := newClientForStatusRefresh(t, signer)
	seedStatusBearingBatch(t, c.eudiStorage.Db(), "h1", srv.URL(), 7)

	// Still valid, so the sweep re-confirms and stays silent — otherwise every
	// scheduled sweep would cost the app a full credential refetch.
	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Zero(t, handler.CredentialsChangedCount(), "re-confirming a status must not wake the app")

	// The issuer revokes the credential.
	srv.Serve(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{7: 1}, // Invalid
	})

	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, 1, handler.CredentialsChangedCount(), "a status change must wake the app")

	// And the wallet reflects it, which is what the app finds when it re-reads.
	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.True(t, creds[0].Revoked, "the revocation the app was woken for")

	// Sweeping again re-confirms the revocation it already knows about.
	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, 1, handler.CredentialsChangedCount(), "a known revocation is not re-reported")
}

// TestRefreshStatusesSilentOnCancelledContext pins that a sweep that never got
// as far as a status list reports nothing: a ctx cancelled on entry
// short-circuits inside the service, before any writeback. Cancellation landing
// after a writeback is the opposite case and does signal — see
// TestRefreshStatusesNotifiesOnChangeCommittedBeforeCancellation.
func TestRefreshStatusesSilentOnCancelledContext(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{7: 1}, // Invalid: a change is waiting to be found
	})

	c, handler := newClientForStatusRefresh(t, signer)
	seedStatusBearingBatch(t, c.eudiStorage.Db(), "h1", srv.URL(), 7)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.Error(t, c.RefreshStatuses(ctx))
	require.Zero(t, handler.CredentialsChangedCount(), "a sweep that wrote nothing back has nothing to report")

	// The change was not consumed by the abandoned sweep: the next real one
	// still finds and reports it.
	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, 1, handler.CredentialsChangedCount())
}

// TestRefreshStatusesNotifiesOnChangeCommittedBeforeCancellation pins the
// counterpart: once the sweep has written a status change back, cancelling the
// ctx must not swallow the signal. The writeback is committed, so the next sweep
// re-reads it and finds a re-confirmation — a signal dropped here is a
// revocation the app is never told about at all.
func TestRefreshStatusesNotifiesOnChangeCommittedBeforeCancellation(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{7: 1}, // Invalid: the revocation to be found
	})

	c, handler := newClientForStatusRefresh(t, signer)
	seedStatusBearingBatch(t, c.eudiStorage.Db(), "h1", srv.URL(), 7)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.revocationService = services.NewRevocationService(newStatusChecker(signer), &cancellingStore{
		CredentialStore: db.NewCredentialStore(c.eudiStorage.Db()),
		cancel:          cancel,
	})

	require.NoError(t, c.RefreshStatuses(ctx))
	require.Equal(t, 1, handler.CredentialsChangedCount(), "a committed change must reach the app even though the caller gave up")

	// And the wallet holds the revocation, which is what the woken app reads.
	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	require.True(t, creds[0].Revoked)

	// Nothing left for a later sweep to report: it re-confirms the status the
	// cancelled one already recorded. This is why suppressing the signal above
	// would lose the revocation rather than defer it.
	require.NoError(t, c.RefreshStatuses(context.Background()))
	require.Equal(t, 1, handler.CredentialsChangedCount(), "the change was already reported, not deferred")
}

// TestNewRejectsNilHandler pins that the now-required handler is checked where
// the app can see the failure. Unguarded calls from background jobs and from
// IrmaClient would otherwise panic on a goroutine with no recover.
func TestNewRejectsNilHandler(t *testing.T) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storagePath := filepath.Join(test.CreateTestStorage(t), "client")

	_, err := New(Config{
		StoragePath:           storagePath,
		IrmaConfigurationPath: filepath.Join(path, "irma_configuration"),
		EudiAppDataPath:       filepath.Join(storagePath, "eudi"),
		Signer:                test.NewSigner(t),
		AesKey:                aesKey,
		Locale:                "en",
	})
	require.ErrorContains(t, err, "handler is required")
}
