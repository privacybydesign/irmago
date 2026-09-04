package services

import (
	"context"
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIsRevokedFixture wires a RevocationService to a bits-wide status list
// serving value at index 3 via a freshly-signed test token, and returns an
// instance pointing at that index. The cache starts cold; call warmCache to
// populate it. IsRevoked reads the cache only (never the network), and does not
// touch the store, so it is left nil.
func newIsRevokedFixture(t *testing.T, bits int, value uint8) (*RevocationService, *statuslist.TestStatusListServer, *models.SdJwtVcBatchInstance) {
	t.Helper()
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example.com",
		Bits:     bits,
		Statuses: map[uint64]uint8{3: value},
	})
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	uri := srv.URL()
	idx := uint64(3)
	inst := &models.SdJwtVcBatchInstance{StatusListURI: &uri, StatusListIdx: &idx}
	return NewRevocationService(checker, nil), srv, inst
}

// warmCache populates rc's status-list cache from the test server, the way the
// background RefreshStatuses sweep would.
func warmCache(t *testing.T, rc *RevocationService, inst *models.SdJwtVcBatchInstance) {
	t.Helper()
	_, err := rc.checker.Refresh(context.Background(), statuslist.Reference{URI: *inst.StatusListURI})
	require.NoError(t, err)
}

func Test_RevocationService_IsRevoked_InvalidBit(t *testing.T) {
	rc, _, inst := newIsRevokedFixture(t, 1, 1) // idx 3 -> invalid
	warmCache(t, rc, inst)
	assert.True(t, rc.IsRevoked(inst))
}

func Test_RevocationService_IsRevoked_ValidBit(t *testing.T) {
	rc, _, inst := newIsRevokedFixture(t, 1, 0) // idx 3 -> valid
	warmCache(t, rc, inst)
	assert.False(t, rc.IsRevoked(inst))
}

func Test_RevocationService_IsRevoked_Suspended(t *testing.T) {
	rc, _, inst := newIsRevokedFixture(t, 2, 2) // idx 3 -> suspended
	warmCache(t, rc, inst)
	assert.True(t, rc.IsRevoked(inst), "suspended is not a usable candidate")
}

func Test_RevocationService_IsRevoked_ApplicationSpecific(t *testing.T) {
	rc, _, inst := newIsRevokedFixture(t, 2, 3) // idx 3 -> application-specific
	warmCache(t, rc, inst)
	assert.True(t, rc.IsRevoked(inst), "anything other than valid is revoked")
}

// IsRevoked reads the cache only: once warm, a broken/unreachable server does
// not change the answer and triggers no further fetch.
func Test_RevocationService_IsRevoked_NoLiveFetch(t *testing.T) {
	rc, srv, inst := newIsRevokedFixture(t, 1, 1) // idx 3 -> invalid
	warmCache(t, rc, inst)
	hitsAfterWarm := srv.Hits()
	srv.SetBody([]byte("not-a-status-list-jwt")) // any live fetch would now fail
	assert.True(t, rc.IsRevoked(inst), "served from warm cache")
	assert.Equal(t, hitsAfterWarm, srv.Hits(), "IsRevoked must not fetch")
}

// Cold cache (never refreshed) -> advisory not-revoked, and no fetch attempted.
func Test_RevocationService_IsRevoked_ColdCache_NotRevoked(t *testing.T) {
	rc, srv, inst := newIsRevokedFixture(t, 1, 1) // would read invalid if fetched
	assert.False(t, rc.IsRevoked(inst), "cold cache -> advisory not revoked")
	assert.Zero(t, srv.Hits(), "IsRevoked must not fetch")
}

func Test_RevocationService_IsRevoked_NoStatusReference(t *testing.T) {
	rc, _, _ := newIsRevokedFixture(t, 1, 1)
	require.False(t, rc.IsRevoked(&models.SdJwtVcBatchInstance{}), "no status_list reference -> never revoked")
}

func Test_RevocationService_IsRevoked_NilChecker(t *testing.T) {
	uri := "https://issuer.example/sl"
	idx := uint64(0)
	rc := NewRevocationService(nil, nil)
	require.False(t, rc.IsRevoked(&models.SdJwtVcBatchInstance{StatusListURI: &uri, StatusListIdx: &idx}),
		"disabled (nil checker) -> not revoked")
}
