package eudi_sdjwt_dcql

import (
	"testing"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/stretchr/testify/require"
	"gorm.io/datatypes"
)

// H2 — status check at disclosure time. The helper does not depend
// on storage; testing it in isolation isolates the status-policy
// logic from the rest of the disclosure flow.

func Test_CheckInstanceStatus_NilChecker_AllowsAnyInstance(t *testing.T) {
	h := &SdJwtVcDcqlHandler{}
	inst := &models.IssuedCredentialInstance{ID: datatypes.NewUUIDv4()}
	require.NoError(t, h.checkInstanceStatus(inst, "https://issuer.example"))
}

func Test_CheckInstanceStatus_NoStatusReference_AllowsInstance(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	h := &SdJwtVcDcqlHandler{
		statusChecker: statuslist.NewChecker(statuslist.VerificationContext{
			X509Context: signer.X509VerificationContext(),
		}, statuslist.NewInMemoryCache()),
	}
	// Instance has no StatusListURI/Idx — should be allowed without
	// any network call.
	inst := &models.IssuedCredentialInstance{ID: datatypes.NewUUIDv4()}
	require.NoError(t, h.checkInstanceStatus(inst, "https://issuer.example"))
}

func Test_CheckInstanceStatus_ValidList_AllowsInstance(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServer(t, signer.SignToken(t, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{3: 0},
	}))
	h := &SdJwtVcDcqlHandler{
		statusChecker: statuslist.NewChecker(statuslist.VerificationContext{
			X509Context: signer.X509VerificationContext(),
		}, statuslist.NewInMemoryCache()),
	}
	uri := srv.URL()
	idx := uint64(3)
	inst := &models.IssuedCredentialInstance{
		ID:            datatypes.NewUUIDv4(),
		StatusListURI: &uri,
		StatusListIdx: &idx,
	}
	require.NoError(t, h.checkInstanceStatus(inst, "https://issuer.example"))
}

func Test_CheckInstanceStatus_InvalidList_RefusesInstance(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServer(t, signer.SignToken(t, statuslist.TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{3: 1},
	}))
	h := &SdJwtVcDcqlHandler{
		statusChecker: statuslist.NewChecker(statuslist.VerificationContext{
			X509Context: signer.X509VerificationContext(),
		}, statuslist.NewInMemoryCache()),
	}
	uri := srv.URL()
	idx := uint64(3)
	inst := &models.IssuedCredentialInstance{
		ID:            datatypes.NewUUIDv4(),
		StatusListURI: &uri,
		StatusListIdx: &idx,
	}
	err := h.checkInstanceStatus(inst, "https://issuer.example")
	require.ErrorContains(t, err, "not valid")
}

func Test_CheckInstanceStatus_UnreachableURI_FailsClosed(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	h := &SdJwtVcDcqlHandler{
		statusChecker: statuslist.NewChecker(statuslist.VerificationContext{
			X509Context: signer.X509VerificationContext(),
		}, statuslist.NewInMemoryCache()),
	}
	uri := "http://127.0.0.1:0/nope"
	idx := uint64(0)
	inst := &models.IssuedCredentialInstance{
		ID:            datatypes.NewUUIDv4(),
		StatusListURI: &uri,
		StatusListIdx: &idx,
	}
	err := h.checkInstanceStatus(inst, "https://issuer.example")
	require.ErrorContains(t, err, "status list check failed")
}

func Test_CheckInstanceStatus_IssMismatch_FailsClosed(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServer(t, signer.SignToken(t, statuslist.TestStatusListOpts{
		Issuer:   "https://attacker.example", // wrong iss
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	}))
	h := &SdJwtVcDcqlHandler{
		statusChecker: statuslist.NewChecker(statuslist.VerificationContext{
			X509Context: signer.X509VerificationContext(),
		}, statuslist.NewInMemoryCache()),
	}
	uri := srv.URL()
	idx := uint64(0)
	inst := &models.IssuedCredentialInstance{
		ID:            datatypes.NewUUIDv4(),
		StatusListURI: &uri,
		StatusListIdx: &idx,
	}
	err := h.checkInstanceStatus(inst, "https://issuer.example")
	require.ErrorContains(t, err, "status list check failed")
}

func Test_WithStatusChecker_InstallsChecker(t *testing.T) {
	h := &SdJwtVcDcqlHandler{}
	checker := statuslist.NewChecker(statuslist.VerificationContext{}, statuslist.NewInMemoryCache())
	h = h.WithStatusChecker(checker)
	require.NotNil(t, h.statusChecker)
}
