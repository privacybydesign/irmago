package services

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIsRevokedFixture wires a RevocationService to a status list served by a
// freshly-signed test token, and returns an instance pointing at index 3.
// IsRevoked does not touch the store, so it is left nil.
func newIsRevokedFixture(t *testing.T, bit uint8) (*RevocationService, *statuslist.TestStatusListServer, *models.IssuedCredentialInstance) {
	t.Helper()
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServerWithToken(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example.com",
		Bits:     1,
		Statuses: map[uint64]uint8{3: bit},
	})
	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	uri := srv.URL()
	idx := uint64(3)
	inst := &models.IssuedCredentialInstance{StatusListURI: &uri, StatusListIdx: &idx}
	return NewRevocationService(checker, nil), srv, inst
}

func Test_RevocationService_IsRevoked_InvalidBit(t *testing.T) {
	rc, _, inst := newIsRevokedFixture(t, 1) // idx 3 -> invalid
	assert.True(t, rc.IsRevoked(inst))
}

func Test_RevocationService_IsRevoked_ValidBit(t *testing.T) {
	rc, _, inst := newIsRevokedFixture(t, 0) // idx 3 -> valid
	assert.False(t, rc.IsRevoked(inst))
}

func Test_RevocationService_IsRevoked_CheckFails_FailsSafe(t *testing.T) {
	rc, srv, inst := newIsRevokedFixture(t, 0)
	srv.SetBody([]byte("not-a-status-list-jwt")) // fetch succeeds, verify fails -> Check errors
	assert.True(t, rc.IsRevoked(inst), "no verifiable status -> fail-safe revoked")
}

func Test_RevocationService_IsRevoked_NoStatusReference(t *testing.T) {
	rc, _, _ := newIsRevokedFixture(t, 1)
	require.False(t, rc.IsRevoked(&models.IssuedCredentialInstance{}), "no status_list reference -> never revoked")
}

func Test_RevocationService_IsRevoked_NilChecker(t *testing.T) {
	uri := "https://issuer.example/sl"
	idx := uint64(0)
	rc := NewRevocationService(nil, nil)
	require.False(t, rc.IsRevoked(&models.IssuedCredentialInstance{StatusListURI: &uri, StatusListIdx: &idx}),
		"disabled (nil checker) -> not revoked")
}
