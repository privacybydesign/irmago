package eudi

import (
	"crypto/rand"
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

var yiviCrlDistPoint = "https://yivi.app/crl.crl"

func TestTrustModel(t *testing.T) {
	// Happy path tests
	t.Run("loadTrustChains reads single certificate chain (root-only, no crl) successfully", testLoadTrustChainsReadsSingleChainRootOnlyNoCrlSuccessfully)
	t.Run("loadTrustChains reads certificate chain (root + single sub-CA + crl) successfully", testLoadTrustChainsReadsSingleChainRootWithSingleSubCaAndCrlsSuccessfully)
	t.Run("loadTrustChains reads certificate chains (root with multiple sub-CAs + crls) successfully", testLoadTrustChainsReadsMultipleChainsRootWithMultipleSubCAsAndCrlsSuccessfully)
	t.Run("loadTrustChains reads certificate chain (root with multi level sub-CA + crls) successfully", testLoadTrustChainsReadsMultipleChainsRootWithMultiLevelSubCaAndCrlsSuccessfully)

	// Error handling tests
	t.Run("loadTrustChains reads multiple chains (valid root + 1 valid sub-CA + 1 revoked sub-CA), should only add the valid chain", testLoadTrustChainsReadsMultipleChainsValidRootWithValidAndRevokedSubCaShouldOnlyAddValidChain)
	t.Run("loadTrustChains reads multiple chains (1 valid + 1 expired root, both with sub-CAs), should add both root certs but only one sub-CA", testLoadTrustChainsReadsMultipleChainsValidRootAndExpiredRootWithSubCasShouldAddBothRootCertsButOnlyValidSubCa)
	t.Run("loadTrustChains reads chain (valid root + expired sub-CA), should only add root cert", testLoadTrustChainsReadsChainValidRootAndExpiredSubCaShouldOnlyAddRootCert)
	t.Run("loadTrustChains reads invalid certificate chain (root + CA in reversed order), not add any certificates to the pools", testLoadTrustChainsReadsInvalidChainRootAndCAInReversedOrderNotAddAnyCertificates)

	// Certificate revocation lists tests
	t.Run("getCrlFileNameForCertDistributionPoint generates correct filename", testGetCrlFileNameForCertDistributionPointGeneratesCorrectFilename)

	t.Run("syncCertificateRevocationLists does nothing, given no certificate chains", testSyncCertificateRevocationListsDoesNothingGivenNoCertificateChains)
	t.Run("syncCertificateRevocationLists does not create CRL files for root cert", testSyncCertificateRevocationListsDoesNotCreateCrlFileForRootCert)
	t.Run("syncCertificateRevocationLists clears unused cached CRL and downloads new CRL given updated distribution points", testSyncCertificateRevocationListsClearsUnusedCachedCrlAndDownloadsNewCrlGivenUpdatedDistributionPoints)
	t.Run("syncCertificateRevocationLists reads CRL file and does not need to update", testSyncCertificateRevocationListsReadsCrlFileAndDoesNotNeedToUpdate)
	t.Run("syncCertificateRevocationLists reads CRL file and updates, given CRL NextUpdate is in the past", testSyncCertificateRevocationListsReadsCrlFileAndUpdatesGivenCrlNextUpdateIsInThePast)
	t.Run("syncCertificateRevocationLists first sync downloads CRL from distribution points", testSyncCertificateRevocationListsFirstSyncDownloadsCrlFromDistributionPoints)
	t.Run("syncCertificateRevocationLists fails CRL signature check and will re-sync from distribution points", testSyncCertificateRevocationListsFailsCrlSignatureCheckAndWillReSyncFromDistributionPoints)

	t.Run("downloadVerifyAndCacheCrl downloads, saves and verifies a CRL successfully", testDownloadVerifyAndCacheCrlDownloadsSavesAndVerifiesSuccessfully)
	t.Run("downloadVerifyAndCacheCrl throws error on unknown URL", testDownloadVerifyAndCacheCrlThrowsErrorOnUnknownURL)
	t.Run("downloadVerifyAndCacheCrl throws error on invalid CRL download content", testDownloadVerifyAndCacheCrlThrowsErrorOnInvalidCRLDownloadContent)
	t.Run("downloadVerifyAndCacheCrl throws error on invalid CRL signature", testDownloadVerifyAndCacheCrlThrowsErrorOnInvalidCRLSignature)

	t.Run("cacheCrl caches CRL successfully", testCacheCrlCachesCRLSuccessfully)
	t.Run("cacheCrl fails, given nil CRL", testCacheCrlFailsGivenNilCRL)
	t.Run("cacheCrl fails, given invalid CRL file name", testCacheCrlFailsGivenInvalidCrlFileName)
}

func testLoadTrustChainsReadsSingleChainRootOnlyNoCrlSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert := testdata.CreateRootCertificate(t, rootDN, testdata.PkiOption_None)
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "root_cert.pem"), rootCert)

	// Read the trust model
	err := tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
	require.Len(t, tm.revocationLists, 0)
}

func testLoadTrustChainsReadsSingleChainRootWithSingleSubCaAndCrlsSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), rootCert, caCerts[0])
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(yiviCrlDistPoint)), caCrls[0].Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
	require.Len(t, tm.revocationLists, 1)
}

func testLoadTrustChainsReadsMultipleChainsRootWithMultipleSubCAsAndCrlsSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	// Create a (root > CA1) and (root > CA2) chains and write to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 2, testdata.PkiOption_None, &yiviCrlDistPoint)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain1.pem"), rootCert, caCerts[0])
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain2.pem"), rootCert, caCerts[1])
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(yiviCrlDistPoint)), caCrls[0].Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 2)
	require.Len(t, tm.revocationLists, 1)
}

func testLoadTrustChainsReadsMultipleChainsRootWithMultiLevelSubCaAndCrlsSuccessfully(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)

	yiviSubCrlDistPoint := "https://sub.yivi.app/crl.crl"

	// Create a (root > CA > CA) chain and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, caKeys, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)
	_, subCaCert, subCaCrl := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("SUB-CA CERT"), caCerts[0], caKeys[0], testdata.PkiOption_None, &yiviSubCrlDistPoint)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), rootCert, caCerts[0], subCaCert)
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(yiviCrlDistPoint)), caCrls[0].Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(yiviSubCrlDistPoint)), subCaCrl.Raw, 0644)
	require.NoError(t, err)

	// Read the trust model
	err = tm.loadTrustChains()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 2)
	require.Len(t, tm.revocationLists, 2)
}

func testLoadTrustChainsReadsMultipleChainsValidRootWithValidAndRevokedSubCaShouldOnlyAddValidChain(t *testing.T) {
	tm := setupTrustModelWithStoragePath(t)
	yivi2CrlDistPoint := "https://yivi.app/crl2.crl"

	// Create a 2 roots certs (1 revoked, 1 valid) and write it to storage
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	rootKey, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN1, 1, testdata.PkiOption_RevokedIntermediates, &yiviCrlDistPoint)
	_, caCert2, caCrl2 := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("CA CERT 2"), rootCert, rootKey, testdata.PkiOption_None, &yivi2CrlDistPoint)

	// Write to disk
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "revoked.pem"), rootCert, caCerts[0])
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "valid.pem"), rootCert, caCert2)
	err := os.WriteFile(filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(yiviCrlDistPoint)), caCrls[0].Raw, 0644)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(yivi2CrlDistPoint)), caCrl2.Raw, 0644)
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
	_, rootCert, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN1, 1, testdata.PkiOption_None, &yiviCrlDistPoint)
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert2, _, caCerts2, _ := testdata.CreateTestPkiHierarchy(t, rootDN2, 1, testdata.PkiOption_ExpiredRoot, &yiviCrlDistPoint)

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
	_, rootCert, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_ExpiredIntermediate, &yiviCrlDistPoint)

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
	_, rootCert, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)
	// Write to disk in reversed order
	writeCertAsPemFile(t, filepath.Join(tm.GetCertificatePath(), "chain.pem"), caCerts[0], rootCert)

	// Read the trust model
	err := tm.loadTrustChains()
	require.NoError(t, err)

	// No certificates should be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 0)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
}

func testGetCrlFileNameForCertDistributionPointGeneratesCorrectFilename(t *testing.T) {
	// Act
	filename := getCrlFileNameForCertDistributionPoint("https://yivi.app/crl.crl")

	// Assert
	require.Equal(t, "6114ae2e097c5d91cfc94cc8aa7f026dd7348d68265e4dbb9fab59026d24e03d.crl", filename)
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

func testSyncCertificateRevocationListsDoesNotCreateCrlFileForRootCert(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert := testdata.CreateRootCertificate(t, rootDN, testdata.PkiOption_None)
	tm.allCerts = append(tm.allCerts, rootCert)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	files, err := filepath.Glob(filepath.Join(tm.GetCrlPath(), "*.crl"))
	require.NoError(t, err)
	require.Len(t, files, 0)
}

func testSyncCertificateRevocationListsClearsUnusedCachedCrlAndDownloadsNewCrlGivenUpdatedDistributionPoints(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)

	// Pretend we already had a cached CRL
	expectedFilePathToBeRemoved := filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(yiviCrlDistPoint))
	err := os.WriteFile(expectedFilePathToBeRemoved, caCrls[0].Raw, 0644)
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(caCrls[0].Raw)
	}))
	defer ts.Close()

	tm.allCerts = append(tm.allCerts, rootCert)
	tm.allCerts = append(tm.allCerts, caCerts...)
	tm.httpClient = ts.Client()

	// Change the distribution point URL to fake changing the URL
	caCerts[0].CRLDistributionPoints = []string{ts.URL + "/NEWcrl.crl"}
	expectedFilePathToBeAdded := filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(ts.URL+"/NEWcrl.crl"))

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.NoFileExists(t, expectedFilePathToBeRemoved)
	require.FileExists(t, expectedFilePathToBeAdded)
}

func testSyncCertificateRevocationListsReadsCrlFileAndDoesNotNeedToUpdate(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)
	crlFilePath := filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(yiviCrlDistPoint))

	// Create a root certificate with distribution point + CRL and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)

	tm.allCerts = append(tm.allCerts, rootCert)
	tm.allCerts = append(tm.allCerts, caCerts...)

	caCrls[0].NextUpdate = time.Now().Add(24 * time.Hour)
	os.WriteFile(crlFilePath, caCrls[0].Raw, 0644)

	// Startup a test server, which will count any requests made to it
	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCounter++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	}))
	defer ts.Close()

	// Change client configuration to use the test server
	tm.httpClient = ts.Client()

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.Equal(t, 0, requestCounter) // Since the CRL will be up-to-date, no requests should be made

	// Assert the CRL file has not been changed
	require.FileExists(t, crlFilePath)
	bts, err := os.ReadFile(crlFilePath)
	require.NoError(t, err)
	require.Equal(t, caCrls[0].Raw, bts)
}

func testSyncCertificateRevocationListsReadsCrlFileAndUpdatesGivenCrlNextUpdateIsInThePast(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Startup a test server, which will count any requests made to it
	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCounter++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
	}))
	defer ts.Close()

	// Change client configuration to use the test server
	tm.httpClient = ts.Client()

	crlDistPoint := ts.URL + "/crl.crl"
	crlFilePath := filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(crlDistPoint))

	// Create a root certificate with distribution point + CRL and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	rootKey, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &crlDistPoint)

	oldCrlTemplate := testdata.GetDefaultCrlTemplate(rootCert)
	oldCrlTemplate.NextUpdate = time.Now().Add(-time.Hour)
	oldCrl, err := x509.CreateRevocationList(rand.Reader, oldCrlTemplate, rootCert, rootKey)
	require.NoError(t, err)

	os.WriteFile(crlFilePath, oldCrl, 0644)

	tm.allCerts = append(tm.allCerts, rootCert)
	tm.allCerts = append(tm.allCerts, caCerts...)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.Equal(t, 1, requestCounter) // Since the CRL will be up-to-date, no requests should be made

	// Assert the CRL file has changed
	require.FileExists(t, crlFilePath)
	bts, err := os.ReadFile(crlFilePath)
	require.NoError(t, err)
	require.NotEqual(t, caCrls[0].Raw, bts)
}

func testSyncCertificateRevocationListsFirstSyncDownloadsCrlFromDistributionPoints(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)
	var crl *x509.RevocationList

	// Setup test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
	}))
	defer ts.Close()

	crlDistPoint := ts.URL + "/crl.crl"
	expectedCrlFilePath := filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(crlDistPoint))

	// Create a root certificate with distribution point + CRL and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &crlDistPoint)

	tm.allCerts = append(tm.allCerts, rootCert)
	tm.allCerts = append(tm.allCerts, caCerts...)

	crl = caCrls[0]
	tm.httpClient = ts.Client()

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.FileExists(t, expectedCrlFilePath) // CRL created
}

func testSyncCertificateRevocationListsFailsCrlSignatureCheckAndWillReSyncFromDistributionPoints(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)
	var crl *x509.RevocationList

	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
		requestCounter++
	}))
	defer ts.Close()

	crlDistPoint := ts.URL + "/crl.crl"

	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &crlDistPoint)
	_, _, _, _, caCrls2 := testdata.CreateTestPkiHierarchy(t, rootDN2, 1, testdata.PkiOption_None, &crlDistPoint)

	tm.allCerts = append(tm.allCerts, rootCert)
	tm.allCerts = append(tm.allCerts, caCerts...)

	crl = caCrls[0]

	tm.httpClient = ts.Client()

	// Create a 'false' CRL to fake a signature check failure (store CRL2 under CA1 index)
	crlFilePath := filepath.Join(tm.GetCrlPath(), getCrlFileNameForCertDistributionPoint(crlDistPoint))
	os.WriteFile(crlFilePath, caCrls2[0].Raw, 0644)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.Equal(t, 1, requestCounter) // Since the CRL signature will fail, it should re-download

	// Assert CRL file now contains CRL1 content
	bts, err := os.ReadFile(crlFilePath)
	require.NoError(t, err)
	require.Equal(t, caCrls[0].Raw, bts)
}

func testDownloadVerifyAndCacheCrlDownloadsSavesAndVerifiesSuccessfully(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, _, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(caCrls[0].Raw)
	}))
	defer ts.Close()

	tm.allCerts = append(tm.allCerts, rootCert)
	tm.httpClient = ts.Client()

	crlDownloadUrl := fmt.Sprintf("%s/crl.crl", ts.URL)
	expectedFilename := fmt.Sprintf("%x.crl", sha256.Sum256([]byte(crlDownloadUrl)))

	// Act
	err := tm.downloadVerifyAndCacheCrl(crlDownloadUrl, expectedFilename)

	// Assert
	require.NoError(t, err)
	require.FileExists(t, path.Join(tm.GetCrlPath(), expectedFilename))
}

func testDownloadVerifyAndCacheCrlThrowsErrorOnUnknownURL(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	tm.httpClient = ts.Client()

	invalidCrlUri := fmt.Sprintf("%s/crl.crl", ts.URL)
	expectedFilename := fmt.Sprintf("%x.crl", sha256.Sum256([]byte(invalidCrlUri)))

	// Act
	err := tm.downloadVerifyAndCacheCrl(invalidCrlUri, expectedFilename)

	// Assert
	require.Error(t, err, "error downloading CRL file")
	require.ErrorContains(t, err, "error downloading CRL file")
}

func testDownloadVerifyAndCacheCrlThrowsErrorOnInvalidCRLDownloadContent(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid crl content"))
	}))
	defer ts.Close()

	tm.httpClient = ts.Client()

	// Act
	err := tm.downloadVerifyAndCacheCrl(ts.URL, "")

	// Assert
	require.Error(t, err, "error reading CRL file")
	require.ErrorContains(t, err, "error reading CRL file")
}

func testDownloadVerifyAndCacheCrlThrowsErrorOnInvalidCRLSignature(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	yivi2CrlDistPoint := "https://yivi.app/crl2.crl"

	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	rootKey, rootCert, _, _, _ := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)
	_, _, caCrl2 := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("CA CERT 2"), rootCert, rootKey, testdata.PkiOption_None, &yivi2CrlDistPoint)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Download a 'wrong' CRL to force invalid signature failure
		w.Write(caCrl2.Raw)
	}))
	defer ts.Close()

	tm.httpClient = ts.Client()

	// Act; server returns CRL from root1, but verifies with root2 cert to 'fake' signature failure
	err := tm.downloadVerifyAndCacheCrl(ts.URL, "")

	// Assert
	require.ErrorContains(t, err, "CRL signature is invalid")
}

func testCacheCrlCachesCRLSuccessfully(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, _, _, _, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)

	expectedFilename := fmt.Sprintf("%x.crl", sha256.Sum256([]byte(yiviCrlDistPoint)))

	// Act
	err := tm.cacheCrl(caCrls[0], expectedFilename)

	// Assert
	require.NoError(t, err)
	require.FileExists(t, path.Join(tm.GetCrlPath(), expectedFilename))
}

func testCacheCrlFailsGivenNilCRL(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Act
	err := tm.cacheCrl(nil, "invalid.crl")

	// Assert
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid CRL: crl cannot be nil")
}

func testCacheCrlFailsGivenInvalidCrlFileName(t *testing.T) {
	// Arrange
	tm := setupTrustModelWithStoragePath(t)

	// Act
	err := tm.cacheCrl(&x509.RevocationList{}, "invalid.txt")

	// Assert
	require.Error(t, err)
	require.ErrorContains(t, err, "invalid CRL: crlFileName must have .crl extension")
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
