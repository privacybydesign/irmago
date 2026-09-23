package statuslist

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_VerifyStatusListTokenCWT_ValidX5ChainSignature(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignCWTToken(t, TestStatusListOpts{
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 1},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	v, err := verifyStatusListTokenCWT(body, vc, "https://issuer.example/sl/1", time.Now())
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example/sl/1", v.payload.Subject)
	require.Equal(t, 1, v.payload.StatusList.Bits)
	require.NotEmpty(t, v.payload.StatusList.Lst)

	status, err := v.statusAt(Reference{Index: 1}, 0)
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, status)
}

func Test_VerifyStatusListTokenCWT_WrongType_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignCWTTokenWithTyp(t, TestStatusListOpts{
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	}, "application/statuslist+jwt")

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListTokenCWT(body, vc, "https://issuer.example/sl/1", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListTokenCWT_WithoutTrustAnchor_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignCWTToken(t, TestStatusListOpts{
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{}
	_, err := verifyStatusListTokenCWT(body, vc, "https://issuer.example/sl/1", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListTokenCWT_SubMismatch_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignCWTToken(t, TestStatusListOpts{
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListTokenCWT(body, vc, "https://issuer.example/sl/DIFFERENT", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListTokenCWT_MissingIat_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignCWTToken(t, TestStatusListOpts{
		Subject:      "https://issuer.example/sl/1",
		OmitIssuedAt: true,
		Bits:         1,
		Statuses:     map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListTokenCWT(body, vc, "https://issuer.example/sl/1", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListTokenCWT_ExpiredBeyondSkew_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	now := time.Now()
	body := signer.SignCWTToken(t, TestStatusListOpts{
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: now.Add(-2 * time.Hour),
		Expiry:   now.Add(-time.Hour),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListTokenCWT(body, vc, "https://issuer.example/sl/1", now)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListTokenCWT_FutureIatBeyondSkew_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignCWTToken(t, TestStatusListOpts{
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now().Add(2 * time.Hour),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListTokenCWT(body, vc, "https://issuer.example/sl/1", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListTokenCWT_InvalidBitSize_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignCWTToken(t, TestStatusListOpts{
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     3,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListTokenCWT(body, vc, "https://issuer.example/sl/1", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_LooksLikeCWT(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	jwtBody := signer.SignToken(t, TestStatusListOpts{
		Issuer: "https://issuer.example", Subject: "https://issuer.example/sl/1",
		IssuedAt: time.Now(), Bits: 1, Statuses: map[uint64]uint8{0: 0},
	})
	cwtBody := signer.SignCWTToken(t, TestStatusListOpts{
		Subject: "https://issuer.example/sl/1", IssuedAt: time.Now(), Bits: 1,
		Statuses: map[uint64]uint8{0: 0},
	})

	require.False(t, looksLikeCWT(jwtBody), "a JWT is ASCII and must not be sniffed as CWT")
	require.True(t, looksLikeCWT(cwtBody), "a COSE_Sign1-encoded CWT must be sniffed as CWT")
	require.False(t, looksLikeCWT(nil))
}

// Test_VerifyStatusList_DispatchesByEncoding pins verifyStatusList (the
// entry point Checker uses) as the single place that decides which of the
// two verify functions handles a given Status List Token — both must
// succeed against the same signer/context/uri/status shape, and each must
// come back through the encoding it was actually signed with.
func Test_VerifyStatusList_DispatchesByEncoding(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	uri := "https://issuer.example/sl/1"

	jwtBody := signer.SignToken(t, TestStatusListOpts{
		Issuer: "https://issuer.example", Subject: uri,
		IssuedAt: time.Now(), Bits: 1, Statuses: map[uint64]uint8{0: 1},
	})
	v, err := verifyStatusList(jwtBody, vc, uri, time.Now())
	require.NoError(t, err)
	require.IsType(t, &verifiedStatusList{}, v)
	status, err := v.statusAt(Reference{Index: 0}, 0)
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, status)

	cwtBody := signer.SignCWTToken(t, TestStatusListOpts{
		Subject: uri, IssuedAt: time.Now(), Bits: 1,
		Statuses: map[uint64]uint8{0: 1},
	})
	v, err = verifyStatusList(cwtBody, vc, uri, time.Now())
	require.NoError(t, err)
	require.IsType(t, &verifiedStatusListCWT{}, v)
	status, err = v.statusAt(Reference{Index: 0}, 0)
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, status)
}
