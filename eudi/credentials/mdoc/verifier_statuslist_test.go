package mdoc

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
)

// ============================================================
// TOKEN STATUS LIST (draft-ietf-oauth-status-list-15 §6.3.2)
// ============================================================

func buildStatusIssuerAndDoc(t *testing.T, status *statuslist.StatusClaim) (*TestIssuer, *MDoc) {
	t.Helper()
	const dt = "eu.europa.ec.av.1"
	iss, err := NewTestIssuer()
	require.NoError(t, err)
	h, err := GenerateDeviceSigner()
	require.NoError(t, err)
	doc, err := iss.IssueWithStatus(dt, dt, map[string]any{"age_over_18": true}, h.PublicKey(), status)
	require.NoError(t, err)
	return iss, doc
}

func TestMSOStatusReference_AbsentWhenNotIssued(t *testing.T) {
	iss, doc := buildStatusIssuerAndDoc(t, nil)
	r := NewVerifier([]*x509.Certificate{iss.IACACert()}).Verify(doc, "eu.europa.ec.av.1")
	require.True(t, r.Valid, "verification without a status reference must succeed: %s", r.Error)
	require.Nil(t, r.StatusReference)
}

func TestMSOStatusReference_PopulatedFromMSO(t *testing.T) {
	want := statuslist.Reference{URI: "https://issuer.example/statuslists/1", Index: 42}
	iss, doc := buildStatusIssuerAndDoc(t, &statuslist.StatusClaim{StatusList: &want})

	r := NewVerifier([]*x509.Certificate{iss.IACACert()}).Verify(doc, "eu.europa.ec.av.1")
	require.True(t, r.Valid, "no StatusChecker configured: a status reference alone must not block verification: %s", r.Error)
	require.NotNil(t, r.StatusReference)
	require.Equal(t, want, *r.StatusReference)
}

// TestVerifier_StatusChecker_FailClosed exercises the Token Status List
// check end to end against a real statuslist.Checker and HTTP server: an
// mdoc whose MSO references a status list entry that reads non-Valid is
// refused, and one that reads Valid verifies — mirroring
// sdjwtvc's runStatusListCheck fail-closed policy for the CBOR/COSE format.
func TestVerifier_StatusChecker_FailClosed(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServer(t, nil)
	srv.ServeJWT(t, signer, statuslist.TestStatusListOpts{
		Issuer:   "https://status-issuer.example",
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 1}, // idx 0 valid, idx 1 invalid
	})

	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	t.Run("valid status passes", func(t *testing.T) {
		iss, doc := buildStatusIssuerAndDoc(t, &statuslist.StatusClaim{
			StatusList: &statuslist.Reference{URI: srv.URL(), Index: 0},
		})
		v := NewVerifier([]*x509.Certificate{iss.IACACert()})
		v.SetStatusChecker(checker)
		r := v.Verify(doc, "eu.europa.ec.av.1")
		require.True(t, r.Valid, "a status_list bit reading Valid must not block verification: %s", r.Error)
	})

	t.Run("non-valid status is refused", func(t *testing.T) {
		iss, doc := buildStatusIssuerAndDoc(t, &statuslist.StatusClaim{
			StatusList: &statuslist.Reference{URI: srv.URL(), Index: 1},
		})
		v := NewVerifier([]*x509.Certificate{iss.IACACert()})
		v.SetStatusChecker(checker)
		r := v.Verify(doc, "eu.europa.ec.av.1")
		require.False(t, r.Valid, "a status_list bit reading Invalid must block verification")
		require.Contains(t, r.Error, "not valid")
	})

	t.Run("unreachable status list is refused", func(t *testing.T) {
		iss, doc := buildStatusIssuerAndDoc(t, &statuslist.StatusClaim{
			StatusList: &statuslist.Reference{URI: srv.URL() + "/does-not-match-sub", Index: 0},
		})
		v := NewVerifier([]*x509.Certificate{iss.IACACert()})
		v.SetStatusChecker(checker)
		r := v.Verify(doc, "eu.europa.ec.av.1")
		require.False(t, r.Valid, "a status list token that fails to verify must block verification")
	})

	t.Run("no checker configured skips the check even with a reference present", func(t *testing.T) {
		iss, doc := buildStatusIssuerAndDoc(t, &statuslist.StatusClaim{
			StatusList: &statuslist.Reference{URI: srv.URL(), Index: 1}, // would fail if checked
		})
		r := NewVerifier([]*x509.Certificate{iss.IACACert()}).Verify(doc, "eu.europa.ec.av.1")
		require.True(t, r.Valid, "without SetStatusChecker, a status reference must not be consulted: %s", r.Error)
	})
}

// TestVerifier_StatusChecker_CWT is the same fail-closed exercise, but
// against a CWT-encoded Status List Token — the encoding an ISO mdoc
// ecosystem is expected to actually use in practice.
func TestVerifier_StatusChecker_CWT(t *testing.T) {
	signer := statuslist.NewTestStatusListSigner(t)
	srv := statuslist.NewTestStatusListServer(t, nil)
	srv.ServeCWT(t, signer, statuslist.TestStatusListOpts{
		Bits:     1,
		Statuses: map[uint64]uint8{0: 0, 1: 1},
	})

	checker := statuslist.NewChecker(statuslist.VerificationContext{
		X509Context: signer.X509VerificationContext(),
	}, statuslist.NewInMemoryCache())

	iss, doc := buildStatusIssuerAndDoc(t, &statuslist.StatusClaim{
		StatusList: &statuslist.Reference{URI: srv.URL(), Index: 1},
	})
	v := NewVerifier([]*x509.Certificate{iss.IACACert()})
	v.SetStatusChecker(checker)
	r := v.Verify(doc, "eu.europa.ec.av.1")
	require.False(t, r.Valid, "an Invalid bit on a CWT-encoded status list must block verification")
	require.Contains(t, r.Error, "not valid")
}
