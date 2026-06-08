package statuslist

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_VerifyStatusListToken_ValidX5cSignature(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 1},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	v, err := verifyStatusListToken(body, vc, "https://issuer.example", time.Now())
	require.NoError(t, err)
	require.Equal(t, "https://issuer.example", v.payload.Issuer)
	require.Equal(t, 1, v.payload.StatusList.Bits)
	require.NotEmpty(t, v.payload.StatusList.Lst)
}

func Test_VerifyStatusListToken_IssMismatch_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(body, vc, "https://other-issuer.example", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
	require.Contains(t, err.Error(), "iss mismatch")
}

func Test_VerifyStatusListToken_WrongTyp_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignTokenWithTyp(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	}, "dc+sd-jwt")

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListToken_X5cWithoutTrustAnchor_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	// No X509Context configured — x5c path can't validate.
	vc := VerificationContext{}
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListToken_FutureIat_BeyondSkew_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	farFuture := time.Now().Add(2 * time.Hour)
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: farFuture,
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListToken_ExpiredBeyondSkew_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	now := time.Now()
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: now.Add(-2 * time.Hour),
		Expiry:   now.Add(-time.Hour),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", now)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListToken_InvalidBitSize_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	// Build a token manually with bits=3 (invalid) — go through the
	// builder by setting status_list directly.
	bits3Token := buildTokenWithBits(t, signer, 3)

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(bits3Token, vc, "https://issuer.example", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
	require.Contains(t, err.Error(), "bits")
}

func Test_VerifyStatusListToken_TTLClaim_ReadOnPayload(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:     "https://issuer.example",
		Subject:    "https://issuer.example/sl/1",
		IssuedAt:   time.Now(),
		Bits:       1,
		Statuses:   map[uint64]uint8{0: 0},
		TTLSeconds: 600,
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	v, err := verifyStatusListToken(body, vc, "https://issuer.example", time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(600), v.payload.TTLSeconds)
}

func Test_VerifyStatusListToken_TTLFromPayload_Precedence(t *testing.T) {
	// Explicit TTL claim wins over remaining exp duration.
	v := &verifiedStatusList{payload: statusListPayload{
		TTLSeconds: 60,
		Expiry:     time.Now().Add(2 * time.Hour).Unix(),
	}}
	require.Equal(t, time.Minute, v.ttlFromPayload())
}

func Test_VerifyStatusListToken_TTLFromPayload_FallsBackToExp(t *testing.T) {
	exp := time.Now().Add(30 * time.Minute)
	v := &verifiedStatusList{payload: statusListPayload{Expiry: exp.Unix()}}
	// Allow a small window so the test isn't time-sensitive.
	require.InDelta(t, 30*time.Minute, v.ttlFromPayload(), float64(2*time.Second))
}

func Test_VerifyStatusListToken_TTLFromPayload_FallsBackToDefault(t *testing.T) {
	v := &verifiedStatusList{}
	require.Equal(t, TTLDefault, v.ttlFromPayload())
}

// buildTokenWithBits builds a token whose status_list.bits is set to
// an arbitrary integer for negative-path tests.
func buildTokenWithBits(t *testing.T, s *TestStatusListSigner, bits int) []byte {
	t.Helper()
	// Reuse SignToken's machinery by signing with bits=1, then we
	// patch the JWT payload below — but that breaks the signature.
	// Instead, build via a parallel path that calls into the same
	// token builder with arbitrary bits.
	opts := TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     bits,
		Statuses: map[uint64]uint8{0: 0},
	}
	// encodeStatusBits guards against invalid bits indirectly; for
	// bits=3 the bit-packing math still produces *a* byte sequence
	// (mask becomes 0b00000111). That's exactly what we want for
	// this test — a verifiable token with bits=3 on the wire so we
	// confirm the verifier rejects it.
	return s.SignToken(t, opts)
}
