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
	v, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/1", time.Now())
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

	// iss-match is opt-in: only enforced when RequireStatusListIssuerMatch is set.
	vc := VerificationContext{X509Context: signer.X509VerificationContext(), RequireStatusListIssuerMatch: true}
	_, err := verifyStatusListToken(body, vc, "https://other-issuer.example", "https://issuer.example/sl/1", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
	require.Contains(t, err.Error(), "iss mismatch")
}

func Test_VerifyStatusListToken_IssMismatch_AllowedWhenNotRequired(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	// Token signed by a delegated Status Issuer: trusted signature, sub
	// matches the uri, but iss differs from the credential issuer.
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://delegated-status-issuer.example",
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	// Default context: RequireStatusListIssuerMatch off -> accepted (spec behavior).
	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/1", time.Now())
	require.NoError(t, err)
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
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/1", time.Now())
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
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/1", time.Now())
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
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/1", time.Now())
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
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/1", now)
	require.ErrorIs(t, err, ErrUnauthorized)
}

func Test_VerifyStatusListToken_InvalidBitSize_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	// Build a token manually with bits=3 (invalid) — go through the
	// builder by setting status_list directly.
	bits3Token := buildTokenWithBits(t, signer, 3)

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(bits3Token, vc, "https://issuer.example", "https://issuer.example/sl/1", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
	require.Contains(t, err.Error(), "bits")
}

func Test_VerifyStatusListToken_SubMismatch_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:   "https://issuer.example",
		Subject:  "https://issuer.example/sl/1",
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/DIFFERENT", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
	require.Contains(t, err.Error(), "sub")
}

func Test_VerifyStatusListToken_MissingSub_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer: "https://issuer.example",
		// no Subject
		IssuedAt: time.Now(),
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/1", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
	require.Contains(t, err.Error(), "sub")
}

func Test_VerifyStatusListToken_MissingIat_Rejected(t *testing.T) {
	signer := NewTestStatusListSigner(t)
	body := signer.SignToken(t, TestStatusListOpts{
		Issuer:       "https://issuer.example",
		Subject:      "https://issuer.example/sl/1",
		OmitIssuedAt: true,
		Bits:         1,
		Statuses:     map[uint64]uint8{0: 0},
	})

	vc := VerificationContext{X509Context: signer.X509VerificationContext()}
	_, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/1", time.Now())
	require.ErrorIs(t, err, ErrUnauthorized)
	require.Contains(t, err.Error(), "iat")
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
	v, err := verifyStatusListToken(body, vc, "https://issuer.example", "https://issuer.example/sl/1", time.Now())
	require.NoError(t, err)
	require.Equal(t, int64(600), v.payload.TTLSeconds)
}

func Test_VerifyStatusListToken_TTLSignal_Precedence(t *testing.T) {
	// Explicit TTL claim wins over remaining exp duration.
	v := &verifiedStatusList{payload: statusListPayload{
		TTLSeconds: 60,
		Expiry:     time.Now().Add(2 * time.Hour).Unix(),
	}}
	d, ok := v.payloadTTLSignal()
	require.True(t, ok)
	require.Equal(t, time.Minute, d)
}

func Test_VerifyStatusListToken_TTLSignal_FallsBackToExp(t *testing.T) {
	exp := time.Now().Add(30 * time.Minute)
	v := &verifiedStatusList{payload: statusListPayload{Expiry: exp.Unix()}}
	d, ok := v.payloadTTLSignal()
	require.True(t, ok)
	// Allow a small window so the test isn't time-sensitive.
	require.InDelta(t, 30*time.Minute, d, float64(2*time.Second))
}

func Test_VerifyStatusListToken_TTLSignal_AbsentWhenNoTTLorExp(t *testing.T) {
	// No ttl and no exp: the token advertises no lifetime, so the caller
	// falls back to the HTTP max-age (and ultimately ClampTTL's default).
	v := &verifiedStatusList{}
	_, ok := v.payloadTTLSignal()
	require.False(t, ok)
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
