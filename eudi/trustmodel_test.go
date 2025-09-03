package eudi

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestTrustModel(t *testing.T) {
	// Happy path tests
	t.Run("loadTrustChains reads single certificate chain (root-only, no crl) successfully", testLoadTrustChainsReadsSingleChainRootOnlyNoCrlSuccessfully)
	t.Run("loadTrustChains reads single certificate chain (root-only + crl) successfully", testLoadTrustChainsReadsSingleChainRootOnlyWithCrlSuccessfully)
	t.Run("loadTrustChains reads multiple certificate chains (root-only + crls) successfully", testLoadTrustChainsReadsMultipleChainsWithCrlsRootOnlySuccessfully)
	t.Run("loadTrustChains reads certificate chain (root + single sub-CA + crl) successfully", testLoadTrustChainsReadsSingleChainRootWithSingleSubCaAndCrlsSuccessfully)
	t.Run("loadTrustChains reads certificate chains (root with multiple sub-CAs + crls) successfully", testLoadTrustChainsReadsMultipleChainsRootWithMultipleSubCAsAndCrlsSuccessfully)
	t.Run("loadTrustChains reads certificate chain (root with multi level sub-CA + crls) successfully", testLoadTrustChainsReadsMultipleChainsRootWithMultiLevelSubCaAndCrlsSuccessfully)

	// Error handling tests
	t.Run("loadTrustChains reads multiple chains (valid root + 1 valid sub-CA + 1 revoked sub-CA), should only add the valid chain", testLoadTrustChainsReadsMultipleChainsValidRootWithValidAndRevokedSubCaShouldOnlyAddValidChain)
	t.Run("loadTrustChains reads multiple chains (1 valid + 1 expired root, both with sub-CAs), should add both root certs but only one sub-CA", testLoadTrustChainsReadsMultipleChainsValidRootAndExpiredRootWithSubCasShouldAddBothRootCertsButOnlyValidSubCa)
	t.Run("loadTrustChains reads chain (valid root + expired sub-CA), should only add root cert", testLoadTrustChainsReadsChainValidRootAndExpiredSubCaShouldOnlyAddRootCert)
	t.Run("loadTrustChains reads invalid certificate chain (root + CA in reversed order), not add any certificates to the pools", testLoadTrustChainsReadsInvalidChainRootAndCAInReversedOrderNotAddAnyCertificates)

	// Certificate revocation lists tests
	t.Run("getCrlIndexFileNameForCert generates correct index filename", testGetCrlIndexFileNameForCertGeneratesCorrectFilename)
	t.Run("getCrlFileNameForCertDistributionPoint generates correct filename", testGetCrlFileNameForCertDistributionPointGeneratesCorrectFilename)

	t.Run("readCRLIndex reads valid CRL index successfully", testReadCRLIndexReadsValidSuccessfully)
	t.Run("readCRLIndex tries to read non-existing index, returns empty index map", testReadCRLIndexReadsNonExistingIndexReturnsEmptyMap)
	t.Run("readCRLIndex reads index with one invalid line (3 parts in one line), returns only valid lines", testReadCRLIndexReadsIndexWithInvalidLineReturnsOnlyValidLines)

	t.Run("writeCRLIndex writes valid CRL index successfully", testWriteCRLIndexWritesValidSuccessfully)
	t.Run("writeCRLIndex overwrites existing CRL index successfully", testWriteCRLIndexOverwritesExistingSuccessfully)

	t.Run("syncCertificateRevocationLists does nothing, given no certificate chains", testSyncCertificateRevocationListsDoesNothingGivenNoCertificateChains)
	t.Run("syncCertificateRevocationLists creates empty index, given certificate without distribution points", testSyncCertificateRevocationListsCreatesEmptyIndexGivenCertificateWithoutDistributionPoints)
	t.Run("syncCertificateRevocationLists clears CRL files from old index, given new certificate without distribution points", testSyncCertificateRevocationListsClearsCrlFilesFromOldIndexGivenNewCertificateWithoutDistributionPoints)
	t.Run("syncCertificateRevocationLists reads CRL file and does not need to update", testSyncCertificateRevocationListsReadsCrlFileAndDoesNotNeedToUpdate)
	t.Run("syncCertificateRevocationLists reads CRL file and updates, given CRL NextUpdate is in the past", testSyncCertificateRevocationListsReadsCrlFileAndUpdatesGivenCrlNextUpdateIsInThePast)
	t.Run("syncCertificateRevocationLists first sync downloads CRL from distribution points", testSyncCertificateRevocationListsFirstSyncDownloadsCrlFromDistributionPoints)
	t.Run("syncCertificateRevocationLists fails CRL signature check and will re-sync from distribution points", testSyncCertificateRevocationListsFailsCrlSignatureCheckAndWillReSyncFromDistributionPoints)

	t.Run("downloadVerifyAndSaveCRL downloads, saves and verifies a CRL successfully", testDownloadVerifyAndSaveCRLDownloadsSavesAndVerifiesSuccessfully)
	t.Run("downloadVerifyAndSaveCRL throws error on unknown URL", testDownloadVerifyAndSaveCRLThrowsErrorOnUnknownURL)
	t.Run("downloadVerifyAndSaveCRL throws error on invalid CRL download content", testDownloadVerifyAndSaveCRLThrowsErrorOnInvalidCRLDownloadContent)
	t.Run("downloadVerifyAndSaveCRL throws error on invalid CRL signature", testDownloadVerifyAndSaveCRLThrowsErrorOnInvalidCRLSignature)
}

func testLoadTrustChainsReadsSingleChainRootOnlyNoCrlSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _ := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert.pem"), rootCert)

	// Read the trust model
	err := tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
	require.Len(t, tm.revocationLists, 0)
}

func testLoadTrustChainsReadsSingleChainRootOnlyWithCrlSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, rootCrl := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert.pem"), rootCert)
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), "root_cert.crl"), rootCrl.Raw, 0644)
	require.NoError(t, err)
	indexContent := "http://example.com/crls/root_cert.crl\troot_cert.crl\n"
	indexFilePath := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(rootCert))
	err = os.WriteFile(indexFilePath, []byte(indexContent), 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
	require.Len(t, tm.revocationLists, 1)
}

func testLoadTrustChainsReadsMultipleChainsWithCrlsRootOnlySuccessfully(t *testing.T) {
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

	indexContent := "http://example1.com/crls/root_cert.crl\troot_cert.crl\n"
	indexFilePath := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(rootCert))
	err = os.WriteFile(indexFilePath, []byte(indexContent), 0644)
	require.NoError(t, err)
	indexContent2 := "http://example2.com/crls/root_cert2.crl\troot_cert2.crl\n"
	indexFilePath2 := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(rootCert2))
	err = os.WriteFile(indexFilePath2, []byte(indexContent2), 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 2)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
	require.Len(t, tm.revocationLists, 2)
}

func testLoadTrustChainsReadsSingleChainRootWithSingleSubCaAndCrlsSuccessfully(t *testing.T) {
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

	indexContent := "http://example.com/crls/root_cert.crl\troot_cert.crl\n"
	indexFilePath := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(rootCert))
	err = os.WriteFile(indexFilePath, []byte(indexContent), 0644)
	require.NoError(t, err)

	indexContentCa := "http://example.com/crls/ca.crl\tca.crl\n"
	indexFilePathCa := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(caCerts[0]))
	err = os.WriteFile(indexFilePathCa, []byte(indexContentCa), 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
	require.Len(t, tm.revocationLists, 2)
}

func testLoadTrustChainsReadsMultipleChainsRootWithMultipleSubCAsAndCrlsSuccessfully(t *testing.T) {
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

	indexContentRoot := "http://example.com/crls/root_cert.crl\troot_cert.crl\n"
	indexFilePathRoot := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(rootCert))
	err = os.WriteFile(indexFilePathRoot, []byte(indexContentRoot), 0644)
	require.NoError(t, err)

	indexContentCa1 := "http://example.com/crls/ca1.crl\tca1.crl\n"
	indexFilePathCa1 := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(caCerts[0]))
	err = os.WriteFile(indexFilePathCa1, []byte(indexContentCa1), 0644)
	require.NoError(t, err)

	indexContentCa2 := "http://example.com/crls/ca2.crl\tca2.crl\n"
	indexFilePathCa2 := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(caCerts[1]))
	err = os.WriteFile(indexFilePathCa2, []byte(indexContentCa2), 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 2)
	require.Len(t, tm.revocationLists, 3)
}

func testLoadTrustChainsReadsMultipleChainsRootWithMultiLevelSubCaAndCrlsSuccessfully(t *testing.T) {
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

	indexContentRoot := "http://example.com/crls/root_cert.crl\troot_cert.crl\n"
	indexFilePathRoot := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(rootCert))
	err = os.WriteFile(indexFilePathRoot, []byte(indexContentRoot), 0644)
	require.NoError(t, err)

	indexContentCa := "http://example.com/crls/ca.crl\tca.crl\n"
	indexFilePathCa := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(caCerts[0]))
	err = os.WriteFile(indexFilePathCa, []byte(indexContentCa), 0644)
	require.NoError(t, err)

	indexContentSubCa := "http://example.com/crls/sub-ca.crl\tsub-ca.crl\n"
	indexFilePathSubCa := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(subCaCert))
	err = os.WriteFile(indexFilePathSubCa, []byte(indexContentSubCa), 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 2)
	require.Len(t, tm.revocationLists, 3)
}

func testLoadTrustChainsReadsMultipleChainsValidRootWithValidAndRevokedSubCaShouldOnlyAddValidChain(t *testing.T) {
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

	crlIndexContentRoot := "http://example.com/crls/root_cert.crl\troot_cert.crl\n"
	crlIndexFilePathRoot := filepath.Join(tm.GetCrlPath(), getCrlIndexFileNameForCert(rootCert))
	err = os.WriteFile(crlIndexFilePathRoot, []byte(crlIndexContentRoot), 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.loadTrustChains()
	require.NoError(t, err)

	// The revoked sub-CA should not be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
}

func testLoadTrustChainsReadsMultipleChainsValidRootAndExpiredRootWithSubCasShouldAddBothRootCertsButOnlyValidSubCa(t *testing.T) {
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
	err := tm.loadTrustChains()
	require.NoError(t, err)

	// The expired root (+intermediates) should not be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 2)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
}

func testLoadTrustChainsReadsChainValidRootAndExpiredSubCaShouldOnlyAddRootCert(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root cert and an expired sub-CA cert
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_ExpiredIntermediate)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), rootCert, caCerts[0])

	// Read the trust model
	err := tm.loadTrustChains()
	require.NoError(t, err)

	// Only the root cert should be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)

	// The expired sub-CA cert should not be added to the pools
	require.NotContains(t, tm.trustedIntermediateCertificates.Subjects(), caCerts[0].Subject.ToRDNSequence().String())
}

func testLoadTrustChainsReadsInvalidChainRootAndCAInReversedOrderNotAddAnyCertificates(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root cert and a CA cert, but write them in reversed order
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None)
	// Write to disk in reversed order
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), caCerts[0], rootCert)

	// Read the trust model
	err := tm.loadTrustChains()
	require.NoError(t, err)

	// No certificates should be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 0)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
}

func testGetCrlIndexFileNameForCertGeneratesCorrectFilename(t *testing.T) {
	// Arrange
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, cert := testdata.CreateRootCertificate(t, rootDN, testdata.PkiOption_None)

	// Act
	filename := getCrlIndexFileNameForCert(cert)

	// Assert
	require.Equal(t, "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index", filename)
}

func testGetCrlFileNameForCertDistributionPointGeneratesCorrectFilename(t *testing.T) {
	// Arrange
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, cert := testdata.CreateRootCertificate(t, rootDN, testdata.PkiOption_None)

	// Act
	filename := getCrlFileNameForCertDistributionPoint(cert, "https://yivi.app/crl.crl")

	// Assert
	require.Equal(t, "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c-6114ae2e097c5d91cfc94cc8aa7f026dd7348d68265e4dbb9fab59026d24e03d.crl", filename)
}

func testReadCRLIndexReadsValidSuccessfully(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	indexContent := "https://yivi.app/crl.crl\tcrl.crl"
	os.WriteFile(path.Join(tm.GetCrlPath(), "cert.index"), []byte(indexContent), 0644)

	// Act
	index, err := tm.readCRLIndex("cert.index")

	// Assert
	require.NoError(t, err)
	require.Equal(t, index["https://yivi.app/crl.crl"], "crl.crl")
}

func testReadCRLIndexReadsNonExistingIndexReturnsEmptyMap(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Act
	index, err := tm.readCRLIndex("non_existing.index")

	// Assert
	require.NoError(t, err)
	require.Empty(t, index)
}

func testReadCRLIndexReadsIndexWithInvalidLineReturnsOnlyValidLines(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)
	indexContent := "invalid_line\nhttps://yivi.app/crl.crl\tcrl.crl\nhttps://yivi.app/crl2.crl\tcrl2.crl"
	os.WriteFile(path.Join(tm.GetCrlPath(), "cert.index"), []byte(indexContent), 0644)

	// Act
	index, err := tm.readCRLIndex("cert.index")

	// Assert
	require.NoError(t, err)
	require.Len(t, index, 2)
	require.Equal(t, index["https://yivi.app/crl.crl"], "crl.crl")
	require.Equal(t, index["https://yivi.app/crl2.crl"], "crl2.crl")
}

func testWriteCRLIndexWritesValidSuccessfully(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)
	index := map[string]string{
		"https://yivi.app/crl.crl":  "crl.crl",
		"https://yivi.app/crl2.crl": "crl2.crl",
	}

	// Act
	err := tm.writeCRLIndex("cert.index", index)

	// Assert
	require.NoError(t, err)
	require.FileExists(t, path.Join(tm.GetCrlPath(), "cert.index"))
}

func testWriteCRLIndexOverwritesExistingSuccessfully(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)
	index := map[string]string{
		"https://yivi.app/crl.crl":  "crl.crl",
		"https://yivi.app/crl2.crl": "crl2.crl",
	}

	// Act
	err := tm.writeCRLIndex("cert.index", index)

	// Assert
	require.NoError(t, err)
	require.FileExists(t, path.Join(tm.GetCrlPath(), "cert.index"))

	bts, err := os.ReadFile(path.Join(tm.GetCrlPath(), "cert.index"))
	require.NoError(t, err)
	require.Equal(t, string(bts), "https://yivi.app/crl.crl\tcrl.crl\nhttps://yivi.app/crl2.crl\tcrl2.crl\n")

	// Arrange, again
	index = map[string]string{
		"https://test.app/crl.crl":  "crl.crl",
		"https://test.app/crl2.crl": "crl2.crl",
	}

	// Act, again
	err = tm.writeCRLIndex("cert.index", index)

	// Assert, again
	require.NoError(t, err)
	require.FileExists(t, path.Join(tm.GetCrlPath(), "cert.index"))

	bts, err = os.ReadFile(path.Join(tm.GetCrlPath(), "cert.index"))
	require.NoError(t, err)
	require.Equal(t, string(bts), "https://test.app/crl.crl\tcrl.crl\nhttps://test.app/crl2.crl\tcrl2.crl\n")
}

func testSyncCertificateRevocationListsDoesNothingGivenNoCertificateChains(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	crlIndexes, err := filepath.Glob(filepath.Join(tm.GetCrlPath(), "*.index"))
	require.NoError(t, err)
	require.Len(t, crlIndexes, 0)
}

func testSyncCertificateRevocationListsCreatesEmptyIndexGivenCertificateWithoutDistributionPoints(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _ := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	tm.allCerts = append(tm.allCerts, rootCert)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.FileExists(t, path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"))
}

func testSyncCertificateRevocationListsClearsCrlFilesFromOldIndexGivenNewCertificateWithoutDistributionPoints(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Pretend we had a CRL before, which needs to be empty after running the test
	indexContent := "https://yivi.app/crl.crl\tcrl.crl\n"
	os.WriteFile(path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"), []byte(indexContent), 0644)
	os.WriteFile(path.Join(tm.GetCrlPath(), "crl.crl"), []byte("test crl content"), 0644)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _ := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	tm.allCerts = append(tm.allCerts, rootCert)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.NoFileExists(t, path.Join(tm.GetCrlPath(), "crl.crl"))
	require.FileExists(t, path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"))

	bts, err := os.ReadFile(path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"))
	require.NoError(t, err)
	require.Equal(t, string(bts), "")
}

func testSyncCertificateRevocationListsReadsCrlFileAndDoesNotNeedToUpdate(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate with distribution point + CRL and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, crl := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	rootCert.CRLDistributionPoints = []string{"https://yivi.app/crl.crl"}
	tm.allCerts = append(tm.allCerts, rootCert)

	crl.NextUpdate = time.Now().Add(24 * time.Hour)

	indexContent := "https://yivi.app/crl.crl\tcrl.crl\n"
	os.WriteFile(path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"), []byte(indexContent), 0644)
	os.WriteFile(path.Join(tm.GetCrlPath(), "crl.crl"), crl.Raw, 0644)

	// Store the timestamp, so we can compare the time with the write to the index (which should be greater)
	currTime := time.Now().UnixMicro()

	// Startup a test server, which will count any requests made to it
	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCounter++
	}))
	defer ts.Close()

	// Change client configuration to use the test server
	tm.httpClient = ts.Client()

	// Sleep for a short time to allow for change in time on the index file modification
	time.Sleep(10 * time.Millisecond)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.Equal(t, 0, requestCounter) // Since the CRL will be up-to-date, no requests should be made

	// Assert the index file (last update time) has been changed, but the content should be the same
	indexFileInfo, err := os.Stat(path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"))
	require.NoError(t, err)
	indexFileLastUpdate := indexFileInfo.ModTime().UnixMicro()
	require.Greater(t, indexFileLastUpdate, currTime)

	bts, err := os.ReadFile(path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"))
	require.NoError(t, err)
	require.Equal(t, indexContent, string(bts))
}

func testSyncCertificateRevocationListsReadsCrlFileAndUpdatesGivenCrlNextUpdateIsInThePast(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate with distribution point + CRL and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	rootKey, rootCert, _ := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	tm.allCerts = append(tm.allCerts, rootCert)

	// Make sure the CRL's NextUpdate is in the past
	crlTemplate := testdata.GetDefaultCrlTemplate()
	crlTemplate.ThisUpdate = time.Now().Add(-5 * time.Hour)
	crlTemplate.NextUpdate = time.Now().Add(-time.Hour)

	crl := testdata.CreateRootRevocationList(t, crlTemplate, rootKey, rootCert, nil, testdata.PkiOption_None)

	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
		requestCounter++
	}))
	defer ts.Close()

	rootCert.CRLDistributionPoints = []string{fmt.Sprintf("%s/crl.crl", ts.URL)}
	tm.httpClient = ts.Client()

	crlFilename := fmt.Sprintf("%s-%x.crl", "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c", sha256.Sum256([]byte(rootCert.CRLDistributionPoints[0])))
	indexContent := fmt.Sprintf("%s\t%s\n", rootCert.CRLDistributionPoints[0], crlFilename)

	os.WriteFile(path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"), []byte(indexContent), 0644)
	os.WriteFile(path.Join(tm.GetCrlPath(), crlFilename), crl.Raw, 0644)

	currTime := time.Now().UnixMicro()

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.Equal(t, 1, requestCounter) // One request should have been made

	// Assert the index and CRL file last update times have been changed, but the content should be the same
	indexFileInfo, err := os.Stat(path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"))
	require.NoError(t, err)
	indexFileLastUpdate := indexFileInfo.ModTime().UnixMicro()
	require.Greater(t, indexFileLastUpdate, currTime)

	bts, err := os.ReadFile(path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index"))
	require.NoError(t, err)
	require.Equal(t, indexContent, string(bts))

	crlFileInfo, err := os.Stat(path.Join(tm.GetCrlPath(), crlFilename))
	require.NoError(t, err)
	crlFileLastUpdate := crlFileInfo.ModTime().UnixMicro()
	require.Greater(t, crlFileLastUpdate, currTime)
}

func testSyncCertificateRevocationListsFirstSyncDownloadsCrlFromDistributionPoints(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate with distribution point + CRL and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, crl := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	tm.allCerts = append(tm.allCerts, rootCert)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
	}))
	defer ts.Close()

	rootCert.CRLDistributionPoints = []string{fmt.Sprintf("%s/crl.crl", ts.URL)}
	tm.httpClient = ts.Client()

	expectedCrlFilename := fmt.Sprintf("%s-%x.crl", "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c", sha256.Sum256([]byte(rootCert.CRLDistributionPoints[0])))
	expectedIndexPath := path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index")

	require.NoFileExists(t, expectedIndexPath)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.FileExists(t, expectedIndexPath)                               // Index created
	require.FileExists(t, path.Join(tm.GetCrlPath(), expectedCrlFilename)) // CRL created
}

func testSyncCertificateRevocationListsFailsCrlSignatureCheckAndWillReSyncFromDistributionPoints(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert, crl := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	_, _, crl2 := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN2, testdata.PkiOption_None)

	tm.allCerts = append(tm.allCerts, rootCert)

	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
		requestCounter++
	}))
	defer ts.Close()

	rootCert.CRLDistributionPoints = []string{fmt.Sprintf("%s/crl.crl", ts.URL)}
	tm.httpClient = ts.Client()

	// Create a 'false' index to fake a signature check failure (store CRL2 under CA1 index)
	crlFilename := fmt.Sprintf("%s-%x.crl", "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c", sha256.Sum256([]byte(rootCert.CRLDistributionPoints[0])))
	indexPath := path.Join(tm.GetCrlPath(), "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c.index")
	indexContent := fmt.Sprintf("%s\t%s\n", rootCert.CRLDistributionPoints[0], crlFilename)

	os.WriteFile(indexPath, []byte(indexContent), 0644)
	os.WriteFile(path.Join(tm.GetCrlPath(), crlFilename), crl2.Raw, 0644)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.FileExists(t, indexPath)                               // Index created
	require.FileExists(t, path.Join(tm.GetCrlPath(), crlFilename)) // CRL created

	// Assert CRL file now contains CRL1 content
	bts, err := os.ReadFile(path.Join(tm.GetCrlPath(), crlFilename))
	require.NoError(t, err)
	require.Equal(t, crl.Raw, bts)
}

func testDownloadVerifyAndSaveCRLDownloadsSavesAndVerifiesSuccessfully(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, crl := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	tm.allCerts = append(tm.allCerts, rootCert)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
	}))
	defer ts.Close()

	tm.httpClient = ts.Client()

	crlDownloadUrl := fmt.Sprintf("%s/crl.crl", ts.URL)
	expectedFilename := fmt.Sprintf("%s-%x.crl", "56e34de4a851a4566fe635d447d592f85e2edc34cbcdaec9e61bb19fcf1e2f0c", sha256.Sum256([]byte(crlDownloadUrl)))

	// Act
	crlFilename, err := tm.downloadVerifyAndSaveCRL(crlDownloadUrl, rootCert)

	// Assert
	require.NoError(t, err)
	require.Equal(t, expectedFilename, crlFilename)
}

func testDownloadVerifyAndSaveCRLThrowsErrorOnUnknownURL(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	tm.httpClient = ts.Client()

	invalidCrlUri := fmt.Sprintf("%s/crl.crl", ts.URL)

	// Act
	_, err := tm.downloadVerifyAndSaveCRL(invalidCrlUri, nil)

	// Assert
	require.Error(t, err, "error downloading CRL file")
	require.ErrorContains(t, err, "error downloading CRL file")
}

func testDownloadVerifyAndSaveCRLThrowsErrorOnInvalidCRLDownloadContent(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid crl content"))
	}))
	defer ts.Close()

	tm.httpClient = ts.Client()

	// Act
	_, err := tm.downloadVerifyAndSaveCRL(ts.URL, nil)

	// Assert
	require.Error(t, err, "error reading CRL file")
	require.ErrorContains(t, err, "error reading CRL file")
}

func testDownloadVerifyAndSaveCRLThrowsErrorOnInvalidCRLSignature(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, _, crl := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN, testdata.PkiOption_None)
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert2, _ := testdata.CreateRootCertificateWithEmptyRevocationList(t, rootDN2, testdata.PkiOption_None)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
	}))
	defer ts.Close()

	tm.httpClient = ts.Client()

	// Act; server returns CRL from root1, but verifies with root2 cert to 'fake' signature failure
	_, err := tm.downloadVerifyAndSaveCRL(ts.URL, rootCert2)

	// Assert
	require.Error(t, err, "error verifying CRL signature")
	require.ErrorContains(t, err, "error verifying CRL signature")
}

// HELPER FUNCTIONS
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
