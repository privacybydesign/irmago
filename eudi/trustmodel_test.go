package eudi

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestTrustModel(t *testing.T) {
	// Happy path tests
	t.Run("readTrustModel reads single certificate chain (root-only, no crl) successfully", testReadTrustModelReadsSingleChainRootOnlyNoCrlSuccessfully)
	t.Run("readTrustModel reads single certificate chain (root-only + crl) successfully", testReadTrustModelReadsSingleChainRootOnlyWithCrlSuccessfully)
	t.Run("readTrustModel reads multiple certificate chains (root-only + crls) successfully", testReadTrustModelReadsMultipleChainsWithCrlsRootOnlySuccessfully)
	t.Run("readTrustModel reads certificate chain (root + single sub-CA + crl) successfully", testReadTrustModelReadsSingleChainRootWithSingleSubCaAndCrlsSuccessfully)
	t.Run("readTrustModel reads certificate chains (root with multiple sub-CAs + crls) successfully", testReadTrustModelReadsMultipleChainsRootWithMultipleSubCAsAndCrlsSuccessfully)
	t.Run("readTrustModel reads certificate chain (root with multi level sub-CA + crls) successfully", testReadTrustModelReadsMultipleChainsRootWithMultiLevelSubCaAndCrlsSuccessfully)

	// Error handling tests
	t.Run("readTrustModel reads multiple chains (valid root + 1 valid sub-CA + 1 revoked sub-CA), should only add the valid chain", testReadTrustModelReadsMultipleChainsValidRootWithValidAndRevokedSubCaShouldOnlyAddValidChain)
	t.Run("readTrustModel reads multiple chains (1 valid + 1 expired root, both with sub-CAs), should add both root certs but only one sub-CA", testReadTrustModelReadsMultipleChainsValidRootAndExpiredRootWithSubCasShouldAddBothRootCertsButOnlyValidSubCa)
	t.Run("readTrustModel reads chain (valid root + expired sub-CA), should only add root cert", testReadTrustModelReadsChainValidRootAndExpiredSubCaShouldOnlyAddRootCert)
	t.Run("readTrustModel reads invalid certificate chain (root + CA in reversed order), not add any certificates to the pools", testReadTrustModelReadsInvalidChainRootAndCAInReversedOrderNotAddAnyCertificates)

	// readRevocationLists tests
	// t.Run("readRevocationLists reads invalid revocation list, should .....", )

	// GetRevocationListsForIssuer tests
	t.Run("GetRevocationListsForIssuer returns correct CRLs", testTrustModelGetRevocationListsForIssuerReturnsCorrectCRLs)

	// VerifyRevocationListSignatures tests
	t.Run("verifyRevocationListSignatures returns no error on valid signatures", testTrustModelVerifyRevocationListSignaturesReturnsNoErrorOnValidSignatures)
	t.Run("verifyRevocationListSignatures returns nil on no revocation lists", testTrustModelVerifyRevocationListSignaturesReturnsNilOnNoRevocationLists)
}

func testReadTrustModelReadsSingleChainRootOnlyNoCrlSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _ := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert.pem"), rootCert)

	// Read the trust model
	err := tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
	require.Len(t, tm.revocationLists, 0)
}

func testReadTrustModelReadsSingleChainRootOnlyWithCrlSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert.pem"), rootCert)
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
	require.Len(t, tm.revocationLists, 1)
}

func testReadTrustModelReadsMultipleChainsWithCrlsRootOnlySuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert2, rootCrl2 := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN2, testdata.PkiOption_None)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert.pem"), rootCert)
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert2.pem"), rootCert2)
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert2.crl"), rootCrl2.Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 2)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
	require.Len(t, tm.revocationLists, 2)
}

func testReadTrustModelReadsSingleChainRootWithSingleSubCaAndCrlsSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), rootCert, caCerts[0])
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "ca.crl"), caCrls[0].Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
	require.Len(t, tm.revocationLists, 2)
}

func testReadTrustModelReadsMultipleChainsRootWithMultipleSubCAsAndCrlsSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a (root > CA1) and (root > CA2) chains and write to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 2, testdata.PkiOption_None)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain1.pem"), rootCert, caCerts[0])
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain2.pem"), rootCert, caCerts[1])
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "ca1.crl"), caCrls[0].Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "ca2.crl"), caCrls[1].Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 2)
	require.Len(t, tm.revocationLists, 3)
}

func testReadTrustModelReadsMultipleChainsRootWithMultiLevelSubCaAndCrlsSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a (root > CA > CA) chain and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl, caKeys, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None)
	_, subCaCert, subCaCrl := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("SUB-CA CERT"), caCerts[0], caKeys[0], testdata.PkiOption_None)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), rootCert, caCerts[0], subCaCert)
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "ca.crl"), caCrls[0].Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), "sub-ca.crl"), subCaCrl.Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 2)
	require.Len(t, tm.revocationLists, 3)
}

func testReadTrustModelReadsMultipleChainsValidRootWithValidAndRevokedSubCaShouldOnlyAddValidChain(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a 2 roots certs (1 revoked, 1 valid) and write it to storage
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	rootKey, rootCert, rootCrl, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN1, 1, testdata.PkiOption_RevokedIntermediates)
	_, caCert2, _ := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("CA CERT 2"), rootCert, rootKey, testdata.PkiOption_None)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "revoked.pem"), rootCert, caCerts[0])
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "valid.pem"), rootCert, caCert2)
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.readTrustModel()
	require.NoError(t, err)

	// The revoked sub-CA should not be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
}

func testReadTrustModelReadsMultipleChainsValidRootAndExpiredRootWithSubCasShouldAddBothRootCertsButOnlyValidSubCa(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a 2 roots certs (1 expired, 1 valid) and write it to storage
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN1, 1, testdata.PkiOption_None)
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert2, _, _, caCerts2, _ := testdata.CreateTestPkiHierarchy(t, rootDN2, 1, testdata.PkiOption_ExpiredRoot)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), rootCert, caCerts[0])
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain2.pem"), rootCert2, caCerts2[0])

	// Read the trust model
	err := tm.readTrustModel()
	require.NoError(t, err)

	// The expired root (+intermediates) should not be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 2)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
}

func testReadTrustModelReadsChainValidRootAndExpiredSubCaShouldOnlyAddRootCert(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root cert and an expired sub-CA cert
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_ExpiredIntermediate)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), rootCert, caCerts[0])

	// Read the trust model
	err := tm.readTrustModel()
	require.NoError(t, err)

	// Only the root cert should be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)

	// The expired sub-CA cert should not be added to the pools
	require.NotContains(t, tm.trustedIntermediateCertificates.Subjects(), caCerts[0].Subject.ToRDNSequence().String())
}

func testReadTrustModelReadsInvalidChainRootAndCAInReversedOrderNotAddAnyCertificates(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root cert and a CA cert, but write them in reversed order
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None)
	// Write to disk in reversed order
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), caCerts[0], rootCert)

	// Read the trust model
	err := tm.readTrustModel()
	require.NoError(t, err)

	// No certificates should be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 0)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
}

// PKI setup
// ROOT CERT 1
//   - CA CERT 1
//   - CA CERT 2
//
// ROOT CERT 2
//   - CA CERT 1
func testTrustModelGetRevocationListsForIssuerReturnsCorrectCRLs(t *testing.T) {
	// Setup multiple CRLs
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN1, 2, testdata.PkiOption_None)
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert2, rootCrl2, _, _, caCrls2 := testdata.CreateTestPkiHierarchy(t, rootDN2, 1, testdata.PkiOption_None)

	tm := &TrustModel{
		// Add all CRLs except the one for ROOT CERT 1 > CA CERT 2
		revocationLists: []*x509.RevocationList{rootCrl, rootCrl2, caCrls[0], caCrls2[0]},
		logger:          logrus.New(),
	}

	// Root certificate 1 has 1 CRL
	crls := utils.GetRevocationListsForIssuer(rootCert.SubjectKeyId, rootCert.Subject, tm.revocationLists)
	require.Len(t, crls, 1)
	require.Contains(t, crls, rootCrl)

	// Root certificate 2 has 1 CRL
	crls = utils.GetRevocationListsForIssuer(rootCert2.SubjectKeyId, rootCert2.Subject, tm.revocationLists)
	require.Len(t, crls, 1)
	require.Contains(t, crls, rootCrl2)

	// Root certificate 1, CA 1 has 1 CRL
	crls = utils.GetRevocationListsForIssuer(caCerts[0].SubjectKeyId, caCerts[0].Subject, tm.revocationLists)
	require.Len(t, crls, 1)
	require.Contains(t, crls, caCrls[0])

	// Root certificate 1, CA 2 has no CRL
	crls = utils.GetRevocationListsForIssuer(caCerts[1].SubjectKeyId, caCerts[1].Subject, tm.revocationLists)
	require.Len(t, crls, 0)
}

func testTrustModelVerifyRevocationListSignaturesReturnsNoErrorOnValidSignatures(t *testing.T) {
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, _, rootCrl, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN1, 2, testdata.PkiOption_None)

	tm := &TrustModel{
		revocationLists: []*x509.RevocationList{rootCrl, caCrls[0], caCrls[1]},
		logger:          logrus.New(),
	}

	err := utils.VerifyRevocationListsSignatures(caCerts[0], tm.revocationLists)
	require.NoError(t, err)
}

func testTrustModelVerifyRevocationListSignaturesReturnsNilOnNoRevocationLists(t *testing.T) {
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, _, rootCrl, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN1, 2, testdata.PkiOption_None)

	tm := &TrustModel{
		revocationLists: []*x509.RevocationList{rootCrl},
		logger:          logrus.New(),
	}

	err := utils.VerifyRevocationListsSignatures(caCerts[0], tm.revocationLists)
	require.NoError(t, err)
}

func setupTrustModelWithStoragePath(t *testing.T) *TrustModel {
	storageFolder := test.CreateTestStorage(t)

	tm := &TrustModel{
		basePath: filepath.Join(storageFolder, "eudi_configuration", "issuers"),
		logger:   logrus.New(),
	}
	tm.clear()

	_ = common.EnsureDirectoryExists(tm.GetCertificatePath())
	_ = common.EnsureDirectoryExists(tm.GetCrlPath())

	return tm
}

func writeCertAsPemFile(t *testing.T, path string, certs ...*x509.Certificate) {
	file, err := os.Create(path)
	require.NoError(t, err)
	defer file.Close()

	for _, cert := range certs {
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		err = pem.Encode(file, pemBlock)
	}
	require.NoError(t, err)
}
