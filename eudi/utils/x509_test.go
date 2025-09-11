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
