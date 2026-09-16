package mdoc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ============================================================
// REVOCATION
// ============================================================

// staticTrustSource is the minimal TrustSource a test needs: fixed anchors and a
// fixed CRL set.
type staticTrustSource struct {
	roots *x509.CertPool
	crls  []*x509.RevocationList
}

func (s staticTrustSource) GetVerificationOptionsTemplate() x509.VerifyOptions {
	return x509.VerifyOptions{Roots: s.roots}
}
func (s staticTrustSource) GetRevocationLists() []*x509.RevocationList { return s.crls }

// revokeCert issues a CRL from issuerCert/issuerKey listing revoked's serial.
func revokeCert(t *testing.T, issuerCert *x509.Certificate, issuerKey *ecdsa.PrivateKey, revoked ...*x509.Certificate) *x509.RevocationList {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, c := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   c.SerialNumber,
			RevocationTime: time.Now().Add(-time.Hour),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, issuerCert, issuerKey)
	require.NoError(t, err, "CreateRevocationList: %v", err)
	crl, err := x509.ParseRevocationList(der)
	require.NoError(t, err, "ParseRevocationList: %v", err)
	return crl
}

// TestRevokedDocumentSignerIsRefused closes the 9.3.3 gap: "mdoc readers ...
// performing certification path validation ... shall have access to certificate
// revocation information".
//
// The credential here is entirely genuine — real chain, real signature, valid
// dates — and the only thing wrong with it is that its document signer has been
// withdrawn. Chain validation cannot see that, which is the whole point: a
// compromised key stays inside its validity window until it expires.
func TestRevokedDocumentSignerIsRefused(t *testing.T) {
	const dt = "eu.europa.ec.av.1"

	build := func(t *testing.T) (*TestIssuer, *MDoc, *x509.CertPool) {
		t.Helper()
		iss, err := NewTestIssuer()
		require.NoError(t, err, "NewTestIssuer: %v", err)
		h, err := NewHolder()
		require.NoError(t, err, "NewHolder: %v", err)
		doc, err := iss.Issue(dt, dt, map[string]any{"age_over_18": true}, h.PublicKey())
		require.NoError(t, err, "Issue: %v", err)
		pool := x509.NewCertPool()
		pool.AddCert(iss.IACACert())
		return iss, doc, pool
	}

	t.Run("no CRLs means no revocation checking", func(t *testing.T) {
		iss, doc, pool := build(t)
		_ = iss
		v := NewVerifierFromTrustSource(staticTrustSource{roots: pool})
		r := v.Verify(doc, dt)
		require.True(t, r.Valid, "an unrevoked signer with no CRLs available must still verify: %s", r.Error)
	})

	t.Run("an unrelated CRL does not reject", func(t *testing.T) {
		iss, doc, pool := build(t)
		other, err := NewTestIssuer()
		require.NoError(t, err, "NewTestIssuer: %v", err)
		// A CRL from a different CA, revoking a different serial.
		crl := revokeCert(t, other.IACACert(), other.iacakey, other.DSCert())
		v := NewVerifierFromTrustSource(staticTrustSource{roots: pool, crls: []*x509.RevocationList{crl}})
		r := v.Verify(doc, dt)
		require.True(t, r.Valid, "a CRL from an unrelated issuer must not reject this signer: %s", r.Error)
		_ = iss
	})

	t.Run("the document signer's own revocation rejects", func(t *testing.T) {
		iss, doc, pool := build(t)
		crl := revokeCert(t, iss.IACACert(), iss.iacakey, iss.DSCert())
		v := NewVerifierFromTrustSource(staticTrustSource{roots: pool, crls: []*x509.RevocationList{crl}})

		r := v.Verify(doc, dt)
		require.False(t, r.Valid, "a credential signed by a revoked document signer must be refused")
		require.Contains(t, r.Error, "revoked", "rejection should say the certificate is revoked, got: %s", r.Error)
		// The operator acting on this needs to know which certificate, not just that
		// something in the chain was withdrawn.
		require.Contains(t, r.Error, iss.DSCert().Subject.String(), "rejection should name the revoked certificate, got: %s", r.Error)
	})

	t.Run("options-only verifiers still skip revocation", func(t *testing.T) {
		iss, doc, pool := build(t)
		crl := revokeCert(t, iss.IACACert(), iss.iacakey, iss.DSCert())
		_ = crl
		// NewVerifier has no trust source, so it has no lists — unchanged behaviour,
		// pinned so the options-only constructors keep working for tests and demos.
		r := NewVerifier([]*x509.Certificate{iss.IACACert()}).Verify(doc, dt)
		require.True(t, r.Valid, "a verifier built without a trust source cannot check revocation: %s", r.Error)
		_ = pool
	})
}
