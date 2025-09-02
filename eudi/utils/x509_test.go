package utils

import (
	"crypto/x509"
	"testing"

	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestTrustModelVerifyRevocationListSignaturesReturnsNilOnNoRevocationLists(t *testing.T) {
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, _, rootCrl, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN1, 2, testdata.PkiOption_None)

	revocationLists := []*x509.RevocationList{rootCrl}

	err := VerifyRevocationListsSignatures(caCerts[0], revocationLists)
	require.NoError(t, err)
}

func TestTrustModelVerifyRevocationListSignaturesReturnsNoErrorOnValidSignatures(t *testing.T) {
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, _, rootCrl, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN1, 2, testdata.PkiOption_None)

	revocationLists := []*x509.RevocationList{rootCrl, caCrls[0], caCrls[1]}

	err := VerifyRevocationListsSignatures(caCerts[0], revocationLists)
	require.NoError(t, err)
}

// PKI setup
// ROOT CERT 1
//   - CA CERT 1
//   - CA CERT 2
//
// ROOT CERT 2
//   - CA CERT 1
func TestTrustModelGetRevocationListsForIssuerReturnsCorrectCRLs(t *testing.T) {
	// Setup multiple CRLs
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN1, 2, testdata.PkiOption_None)
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert2, rootCrl2, _, _, caCrls2 := testdata.CreateTestPkiHierarchy(t, rootDN2, 1, testdata.PkiOption_None)

	revocationLists := []*x509.RevocationList{rootCrl, rootCrl2, caCrls[0], caCrls2[0]}

	// Root certificate 1 has 1 CRL
	crls := GetRevocationListsForIssuer(rootCert.SubjectKeyId, rootCert.Subject, revocationLists)
	require.Len(t, crls, 1)
	require.Contains(t, crls, rootCrl)

	// Root certificate 2 has 1 CRL
	crls = GetRevocationListsForIssuer(rootCert2.SubjectKeyId, rootCert2.Subject, revocationLists)
	require.Len(t, crls, 1)
	require.Contains(t, crls, rootCrl2)

	// Root certificate 1, CA 1 has 1 CRL
	crls = GetRevocationListsForIssuer(caCerts[0].SubjectKeyId, caCerts[0].Subject, revocationLists)
	require.Len(t, crls, 1)
	require.Contains(t, crls, caCrls[0])

	// Root certificate 1, CA 2 has no CRL
	crls = GetRevocationListsForIssuer(caCerts[1].SubjectKeyId, caCerts[1].Subject, revocationLists)
	require.Len(t, crls, 0)
}
