package utils

import (
	"crypto/x509"
	"testing"

	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// PKI setup
// ROOT CERT 1
//   - CA CERT 1
//   - CA CERT 2
//
// ROOT CERT 2
//   - CA CERT 1
func TestTrustModelGetRevocationListsForIssuerReturnsCorrectCRLs(t *testing.T) {
	// Setup multiple CRLs
	crlDistPoint1 := "https://yivi.app/crl1.crl"
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, _, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN1, 1, testdata.PkiOption_None, &crlDistPoint1)
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert2, _, _, _ := testdata.CreateTestPkiHierarchy(t, rootDN2, 1, testdata.PkiOption_None, nil)

	revocationLists := []*x509.RevocationList{caCrls[0]}

	// Root certificate 1 has 1 CRLs
	crls := GetRevocationListsForIssuer(rootCert.AuthorityKeyId, rootCert.Subject, revocationLists)
	require.Len(t, crls, 1)
	require.Contains(t, crls, caCrls[0])

	// Root certificate 2 has no CRLs
	crls = GetRevocationListsForIssuer(rootCert2.AuthorityKeyId, rootCert2.Subject, revocationLists)
	require.Len(t, crls, 0)
}

// newTestEndEntityCert generates a CA-signed end-entity certificate for hostname,
// with opts controlling how it deviates from a well-formed one.
func newTestEndEntityCert(t *testing.T, hostname string, opts testdata.PkiGenerationOptions) *x509.Certificate {
	_, _, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT CERT"), 1, testdata.PkiOption_None, nil)
	_, cert, _ := testdata.CreateEndEntityCertificate(t, testdata.CreateDistinguishedName(hostname), hostname, caCerts[0], caKeys[0], "", opts)
	return cert
}

func TestObtainIssuerFromCert_ReturnsUri(t *testing.T) {
	cert := newTestEndEntityCert(t, "issuer.example.com", testdata.PkiOption_None)

	issuer, err := ObtainIssuerFromCert(cert)

	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com", issuer)
}

func TestObtainIssuerFromCert_ReturnsDns(t *testing.T) {
	cert := newTestEndEntityCert(t, "issuer.example.com", testdata.PkiOption_MissingUriSan)

	issuer, err := ObtainIssuerFromCert(cert)

	require.NoError(t, err)
	require.Equal(t, "issuer.example.com", issuer)
}

func TestObtainIssuerFromCertWithoutUriOrDnsSans(t *testing.T) {
	cert := newTestEndEntityCert(t, "issuer.example.com", testdata.PkiOption_MissingUriSan|testdata.PkiOption_MissingDnsSan)

	_, err := ObtainIssuerFromCert(cert)

	require.ErrorContains(t, err, "no URIs or DNS names in certificate")
}

func TestObtainIssuerFromNilCert(t *testing.T) {
	_, err := ObtainIssuerFromCert(nil)
	require.Error(t, err)
}

// VerifyCertificateUri is what binds an `iss` claim to the certificate that signed the
// credential, so an issuer holding a trusted certificate cannot claim another identity.
func TestVerifyCertificateUri(t *testing.T) {
	cert := newTestEndEntityCert(t, "issuer.example.com", testdata.PkiOption_None)

	require.NoError(t, VerifyCertificateUri(cert, "https://issuer.example.com"))
	require.ErrorContains(t, VerifyCertificateUri(cert, "https://other.example.com"), "is not in the SANs")
	// The DNS SAN carries the same host, but is not a URI SAN and must not match.
	require.ErrorContains(t, VerifyCertificateUri(cert, "issuer.example.com"), "is not in the SANs")
	require.Error(t, VerifyCertificateUri(cert, ""))
	require.Error(t, VerifyCertificateUri(nil, "https://issuer.example.com"))
}

func TestVerifyCertificateUriWithoutUriSan(t *testing.T) {
	cert := newTestEndEntityCert(t, "issuer.example.com", testdata.PkiOption_MissingUriSan)

	require.Error(t, VerifyCertificateUri(cert, "https://issuer.example.com"))
}
