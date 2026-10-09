package eudi_jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

const verifyTestHostname = "example.com"

// verifyTestPki is a root > CA > end-entity hierarchy, shaped the way the wallet's
// TrustModel presents it to VerifyCertificateChain: the root in the root pool, the CA in
// the intermediate pool.
type verifyTestPki struct {
	rootCert *x509.Certificate
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
	leafCert *x509.Certificate
}

func newVerifyTestPki(t *testing.T, opts testdata.PkiGenerationOptions) verifyTestPki {
	t.Helper()

	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, opts, nil)
	_, leafCert, _ := testdata.CreateEndEntityCertificate(t, testdata.CreateDistinguishedName("END ENTITY CERT"), verifyTestHostname, caCerts[0], caKeys[0], testdata.VerifierCertSchemeData, opts)

	return verifyTestPki{
		rootCert: rootCert,
		caKey:    caKeys[0],
		caCert:   caCerts[0],
		leafCert: leafCert,
	}
}

// context builds a verification context trusting this hierarchy's root.
func (p verifyTestPki) context(revocationLists ...*x509.RevocationList) *StaticVerificationContext {
	roots := x509.NewCertPool()
	roots.AddCert(p.rootCert)
	return p.contextWithRoots(roots, revocationLists)
}

// contextWithoutRoot builds a verification context with an empty root pool, so the
// chain to the leaf cannot be built.
func (p verifyTestPki) contextWithoutRoot() *StaticVerificationContext {
	return p.contextWithRoots(x509.NewCertPool(), nil)
}

func (p verifyTestPki) contextWithRoots(roots *x509.CertPool, revocationLists []*x509.RevocationList) *StaticVerificationContext {
	intermediates := x509.NewCertPool()
	intermediates.AddCert(p.caCert)

	return &StaticVerificationContext{
		VerifyOpts: x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			// Mirrors TrustModel.GetVerificationOptionsTemplate: the keyUsage extension is
			// checked by VerifyCertificateChain itself, not by x509.Certificate.Verify.
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		},
		RevocationLists: revocationLists,
	}
}

// crlRevoking returns a CRL signed by this hierarchy's CA listing the given serial number.
func (p verifyTestPki) crlRevoking(t *testing.T, serialNumber *big.Int) *x509.RevocationList {
	t.Helper()

	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(time.Duration(-1 * time.Hour)),
		NextUpdate: time.Now().Add(time.Duration(1 * time.Hour)),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{
				SerialNumber:   serialNumber,
				RevocationTime: time.Now().Add(time.Duration(-1 * time.Hour)),
				ReasonCode:     0,
			},
		},
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, p.caCert, p.caKey)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(crlBytes)
	require.NoError(t, err)

	return crl
}

func Test_VerifyCertificateChain_PKI_ValidLeafWithRootInPool_ReturnsNoError(t *testing.T) {
	pki := newVerifyTestPki(t, testdata.PkiOption_None)

	err := VerifyCertificateChain(pki.context(), []*x509.Certificate{pki.leafCert}, nil)

	require.NoError(t, err)
}

func Test_VerifyCertificateChain_PKI_ExpiredLeaf_ReturnsError(t *testing.T) {
	pki := newVerifyTestPki(t, testdata.PkiOption_ExpiredEndEntity)

	err := VerifyCertificateChain(pki.context(), []*x509.Certificate{pki.leafCert}, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to verify x5c certificate")
	require.Contains(t, err.Error(), "x509: certificate has expired or is not yet valid")
}

func Test_VerifyCertificateChain_PKI_LeafWithoutDigitalSignatureKeyUsage_ReturnsError(t *testing.T) {
	pki := newVerifyTestPki(t, testdata.PkiOption_NoEndEntityDigitalSignatureKeyUsage)

	err := VerifyCertificateChain(pki.context(), []*x509.Certificate{pki.leafCert}, nil)

	require.EqualError(t, err, "end-entity certificate missing digitalSignature key usage")
}

func Test_VerifyCertificateChain_PKI_LeafRevokedByIssuerCrl_ReturnsError(t *testing.T) {
	pki := newVerifyTestPki(t, testdata.PkiOption_None)

	err := VerifyCertificateChain(pki.context(pki.crlRevoking(t, pki.leafCert.SerialNumber)), []*x509.Certificate{pki.leafCert}, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to verify x5c certificate against revocation lists")
	require.Contains(t, err.Error(), "certificate is revoked by issuer CN=CA CERT 0,OU=Test Unit,O=Test Organization,C=NL in revocation list with number 1")
}

func Test_VerifyCertificateChain_PKI_LeafRevokedByCrlFromAnotherAuthority_ReturnsNoError(t *testing.T) {
	pki := newVerifyTestPki(t, testdata.PkiOption_None)

	// A CRL listing the leaf's serial number, signed by a CA that shares the issuer DN
	// but has a different subject key id. Revocation lists are matched on authority key
	// id as well as issuer DN, so this one does not apply to the leaf.
	other := newVerifyTestPki(t, testdata.PkiOption_None)
	require.Equal(t, pki.caCert.Subject.String(), other.caCert.Subject.String())
	require.NotEqual(t, pki.caCert.SubjectKeyId, other.caCert.SubjectKeyId)

	err := VerifyCertificateChain(pki.context(other.crlRevoking(t, pki.leafCert.SerialNumber)), []*x509.Certificate{pki.leafCert}, nil)

	require.NoError(t, err)
}

func Test_VerifyCertificateChain_PKI_LeafWithRootMissingFromPool_ReturnsError(t *testing.T) {
	pki := newVerifyTestPki(t, testdata.PkiOption_None)

	err := VerifyCertificateChain(pki.contextWithoutRoot(), []*x509.Certificate{pki.leafCert}, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to verify x5c certificate")
	require.Contains(t, err.Error(), "x509: certificate signed by unknown authority")
}
