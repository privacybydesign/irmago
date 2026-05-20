package eudi

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/scheme"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/filesystem"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var yiviCrlDistPoint = "https://yivi.app/crl.crl"

func TestTrustModel(t *testing.T) {
	// Happy path tests
	t.Run("Reload reads single certificate chain (root-only, no crl) successfully", testReloadReadsSingleChainRootOnlyNoCrlSuccessfully)
	t.Run("Reload reads certificate chain (root + single sub-CA + crl) successfully", testReloadReadsSingleChainRootWithSingleSubCaAndCrlsSuccessfully)
	t.Run("Reload reads certificate chains (root with multiple sub-CAs + crls) successfully", testReloadReadsMultipleChainsRootWithMultipleSubCAsAndCrlsSuccessfully)
	t.Run("Reload reads certificate chain (root with multi level sub-CA + crls) successfully", testReloadReadsMultipleChainsRootWithMultiLevelSubCaAndCrlsSuccessfully)

	// Error handling tests
	t.Run("Reload reads multiple chains (valid root + 1 valid sub-CA + 1 revoked sub-CA), should only add the valid chain", testReloadReadsMultipleChainsValidRootWithValidAndRevokedSubCaShouldOnlyAddValidChain)
	t.Run("Reload reads multiple chains (1 valid + 1 expired root, both with sub-CAs), should add both root certs but only one sub-CA", testReloadReadsMultipleChainsValidRootAndExpiredRootWithSubCasShouldAddBothRootCertsButOnlyValidSubCa)
	t.Run("Reload reads chain (valid root + expired sub-CA), should only add root cert", testReloadReadsChainValidRootAndExpiredSubCaShouldOnlyAddRootCert)
	t.Run("Reload reads invalid certificate chain (root + CA in reversed order), not add any certificates to the pools", testReloadReadsInvalidChainRootAndCAInReversedOrderNotAddAnyCertificates)

	// Certificate revocation lists tests
	t.Run("syncCertificateRevocationLists does nothing, given no certificate chains", testSyncCertificateRevocationListsDoesNothingGivenNoCertificateChains)
	t.Run("syncCertificateRevocationLists downloads file for non-cached CRL successfully", testSyncCertificateRevocationListsDownloadsFileForNonCachedCrlSuccessfully)
	t.Run("syncCertificateRevocationLists downloads file for cached CRL with invalid content successfully", testSyncCertificateRevocationListsDownloadsFileForCachedCrlWithInvalidContentSuccessfully)
	t.Run("syncCertificateRevocationLists removes CRL given no authority certificate present", testSyncCertificateRevocationListsRemovesCrlGivenNoAuthorityCertificatePresent)
	t.Run("syncCertificateRevocationLists reads cached CRL and does not need to update", testSyncCertificateRevocationListsReadsCachedCrlAndDoesNotNeedToUpdate)
	t.Run("syncCertificateRevocationLists reads CRL file and updates, given CRL NextUpdate is in the past", testSyncCertificateRevocationListsReadsCrlFileAndUpdatesGivenCrlNextUpdateIsInThePast)

	t.Run("downloadVerifyAndCacheCrl downloads, saves and verifies a CRL successfully", testDownloadVerifyAndCacheCrlDownloadsSavesAndVerifiesSuccessfully)
	t.Run("downloadVerifyAndCacheCrl throws error on unknown URL", testDownloadVerifyAndCacheCrlThrowsErrorOnUnknownURL)
	t.Run("downloadVerifyAndCacheCrl throws error on invalid CRL download content", testDownloadVerifyAndCacheCrlThrowsErrorOnInvalidCRLDownloadContent)
	t.Run("downloadVerifyAndCacheCrl throws error on invalid CRL signature", testDownloadVerifyAndCacheCrlThrowsErrorOnInvalidCRLSignature)

	// Logo cache tests
	t.Run("CacheVerifierLogo caches logo successfully", testCacheLogoCachesLogoSuccessfully)
	t.Run("CacheVerifierLogo caches logo multiple times successfully", testCacheVerifierLogoCachesLogoMultipleTimesSuccessfully)
	t.Run("CacheVerifierLogo returns error on nil logo", testCacheVerifierLogoReturnsErrorOnNilLogo)
	t.Run("CacheVerifierLogo returns error on empty logo data", testCacheVerifierLogoReturnsErrorOnEmptyLogoData)
}

func testReloadReadsSingleChainRootOnlyNoCrlSuccessfully(t *testing.T) {
	tm, _ := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert := testdata.CreateRootCertificate(t, rootDN, testdata.PkiOption_None)

	installCertChain(t, tm, rootCert)

	// Read the trust model
	err := tm.Reload()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
	require.Len(t, tm.revocationLists, 0)
}

func testReloadReadsSingleChainRootWithSingleSubCaAndCrlsSuccessfully(t *testing.T) {
	tm, _ := setupTrustModelWithStoragePath(t)

	// Create a root certificate and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)

	// Write to disk (leaf-to-root order; see installCertChain)
	installCertChain(t, tm, caCerts[0], rootCert)
	require.NoError(t, tm.storageContainer.CertificateRevocationListManager().Save(caCrls[0], yiviCrlDistPoint))

	// Read the trust model
	err := tm.Reload()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
	require.Len(t, tm.revocationLists, 1)
}

func testReloadReadsMultipleChainsRootWithMultipleSubCAsAndCrlsSuccessfully(t *testing.T) {
	tm, _ := setupTrustModelWithStoragePath(t)

	// Create a (root > CA1) and (root > CA2) chains and write to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 2, testdata.PkiOption_None, &yiviCrlDistPoint)

	// Write to disk (leaf-to-root order; see installCertChain)
	installCertChain(t, tm, caCerts[0], rootCert)
	installCertChain(t, tm, caCerts[1], rootCert)
	require.NoError(t, tm.storageContainer.CertificateRevocationListManager().Save(caCrls[0], yiviCrlDistPoint))

	// Read the trust model
	err := tm.Reload()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 2)
	require.Len(t, tm.revocationLists, 1)
}

func testReloadReadsMultipleChainsRootWithMultiLevelSubCaAndCrlsSuccessfully(t *testing.T) {
	tm, _ := setupTrustModelWithStoragePath(t)

	yiviSubCrlDistPoint := "https://sub.yivi.app/crl.crl"

	// Create a (root > CA > CA) chain and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, caKeys, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)
	_, subCaCert, subCaCrl := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("SUB-CA CERT"), caCerts[0], caKeys[0], testdata.PkiOption_None, &yiviSubCrlDistPoint)

	// Write to disk (leaf-to-root order; see installCertChain)
	installCertChain(t, tm, subCaCert, caCerts[0], rootCert)
	mgr := tm.storageContainer.CertificateRevocationListManager()
	require.NoError(t, mgr.Save(caCrls[0], yiviCrlDistPoint))
	require.NoError(t, mgr.Save(subCaCrl, yiviSubCrlDistPoint))

	// Read the trust model
	err := tm.Reload()
	require.NoError(t, err)

	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 2)
	require.Len(t, tm.revocationLists, 2)
}

func testReloadReadsMultipleChainsValidRootWithValidAndRevokedSubCaShouldOnlyAddValidChain(t *testing.T) {
	tm, _ := setupTrustModelWithStoragePath(t)
	yivi2CrlDistPoint := "https://yivi.app/crl2.crl"

	// Create a 2 roots certs (1 revoked, 1 valid) and write it to storage
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	rootKey, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN1, 1, testdata.PkiOption_RevokedIntermediates, &yiviCrlDistPoint)
	_, caCert2, caCrl2 := testdata.CreateCaCertificate(t, testdata.CreateDistinguishedName("CA CERT 2"), rootCert, rootKey, testdata.PkiOption_None, &yivi2CrlDistPoint)

	// Write to disk (leaf-to-root order; see installCertChain)
	installCertChain(t, tm, caCerts[0], rootCert)
	installCertChain(t, tm, caCert2, rootCert)
	mgr := tm.storageContainer.CertificateRevocationListManager()
	require.NoError(t, mgr.Save(caCrls[0], yiviCrlDistPoint))
	require.NoError(t, mgr.Save(caCrl2, yivi2CrlDistPoint))

	// Read the trust model
	err := tm.Reload()
	require.NoError(t, err)

	// The revoked sub-CA should not be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
}

func testReloadReadsMultipleChainsValidRootAndExpiredRootWithSubCasShouldAddBothRootCertsButOnlyValidSubCa(t *testing.T) {
	tm, _ := setupTrustModelWithStoragePath(t)

	// Create a 2 roots certs (1 expired, 1 valid) and write it to storage
	rootDN1 := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN1, 1, testdata.PkiOption_None, &yiviCrlDistPoint)
	rootDN2 := testdata.CreateDistinguishedName("ROOT CERT 2")
	_, rootCert2, _, caCerts2, _ := testdata.CreateTestPkiHierarchy(t, rootDN2, 1, testdata.PkiOption_ExpiredRoot, &yiviCrlDistPoint)

	// Write to disk (leaf-to-root order; see installCertChain)
	installCertChain(t, tm, caCerts[0], rootCert)
	installCertChain(t, tm, caCerts2[0], rootCert2)

	// Read the trust model
	err := tm.Reload()
	require.NoError(t, err)

	// The expired root (+intermediates) should not be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 1)
}

func testReloadReadsChainValidRootAndExpiredSubCaShouldOnlyAddRootCert(t *testing.T) {
	tm, _ := setupTrustModelWithStoragePath(t)

	// Create a root cert and an expired sub-CA cert
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_ExpiredIntermediate, &yiviCrlDistPoint)

	// Write to disk (leaf-to-root order; see installCertChain)
	installCertChain(t, tm, caCerts[0], rootCert)

	// Read the trust model
	err := tm.Reload()
	require.NoError(t, err)

	// Only the root cert should be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 1)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)

	// The expired sub-CA cert should not be added to the pools
	require.NotContains(t, tm.trustedIntermediateCertificates.Subjects(), caCerts[0].Subject.ToRDNSequence().String())
}

func testReloadReadsInvalidChainRootAndCAInReversedOrderNotAddAnyCertificates(t *testing.T) {
	tm, _ := setupTrustModelWithStoragePath(t)

	// Create a root cert and a CA cert, but write them in reversed order.
	// The on-disk convention is leaf-to-root, so writing root-to-leaf here
	// makes the chain unparseable: addTrustAnchors will treat the leaf as
	// the root and reject it (not self-signed).
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, _ := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)

	// Write to disk in reversed (root-to-leaf) order.
	installCertChain(t, tm, rootCert, caCerts[0])

	// Read the trust model
	err := tm.Reload()
	require.NoError(t, err)

	// No certificates should be added to the pools
	require.Len(t, tm.trustedRootCertificates.Subjects(), 0)
	require.Len(t, tm.trustedIntermediateCertificates.Subjects(), 0)
}

func testSyncCertificateRevocationListsDoesNothingGivenNoCertificateChains(t *testing.T) {
	// Arrange
	tm, basePath := setupTrustModelWithStoragePath(t)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	crlFiles, err := filepath.Glob(filepath.Join(basePath, "issuers", "crls", "*.crl"))
	require.NoError(t, err)
	require.Len(t, crlFiles, 0)
}

func testSyncCertificateRevocationListsDownloadsFileForNonCachedCrlSuccessfully(t *testing.T) {
	// Arrange
	tm, basePath := setupTrustModelWithStoragePath(t)
	var crl *x509.RevocationList

	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
		requestCounter++
	}))
	defer ts.Close()

	// Create PKI hierarchy
	crlDistpoint := ts.URL + "/crl.crl"
	_, rootCert, _, _, caCrls := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, testdata.PkiOption_None, &crlDistpoint)
	crl = caCrls[0]

	tm.httpClient = ts.Client()
	tm.revocationListsDistributionPoints = []string{crlDistpoint}
	tm.allCerts = append(tm.allCerts, rootCert)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.Equal(t, 1, requestCounter)
	files, _ := filepath.Glob(filepath.Join(basePath, "issuers", "crls", "*.crl"))
	require.Len(t, files, 1)
}

func testSyncCertificateRevocationListsDownloadsFileForCachedCrlWithInvalidContentSuccessfully(t *testing.T) {
	// Arrange
	tm, basePath := setupTrustModelWithStoragePath(t)
	var crl *x509.RevocationList

	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
		requestCounter++
	}))
	defer ts.Close()

	// Create PKI hierarchy
	crlDistpoint := ts.URL + "/crl.crl"
	_, rootCert, _, _, caCrls := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, testdata.PkiOption_None, &crlDistpoint)
	crl = caCrls[0]

	tm.httpClient = ts.Client()
	tm.revocationListsDistributionPoints = []string{crlDistpoint}
	tm.allCerts = append(tm.allCerts, rootCert)

	// Save a valid CRL through the manager (so the file lands at the correct hashed path
	// and is encrypted), then overwrite it with garbage to simulate corruption.
	require.NoError(t, tm.storageContainer.CertificateRevocationListManager().Save(crl, crlDistpoint))
	files, _ := filepath.Glob(filepath.Join(basePath, "issuers", "crls", "*.crl"))
	require.Len(t, files, 1)
	require.NoError(t, os.WriteFile(files[0], []byte("invalid"), 0644))

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.Equal(t, 1, requestCounter)
	files, _ = filepath.Glob(filepath.Join(basePath, "issuers", "crls", "*.crl"))
	require.Len(t, files, 1)
}

func testSyncCertificateRevocationListsRemovesCrlGivenNoAuthorityCertificatePresent(t *testing.T) {
	// Arrange
	tm, basePath := setupTrustModelWithStoragePath(t)
	var crl *x509.RevocationList

	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
		requestCounter++
	}))
	defer ts.Close()

	// Create PKI hierarchy
	crlDistpoint := ts.URL + "/crl.crl"
	_, _, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT CERT 1"), 2, testdata.PkiOption_None, &crlDistpoint)

	tm.httpClient = ts.Client()
	tm.revocationListsDistributionPoints = []string{crlDistpoint}

	// Store a valid CRL file
	tm.allCerts = []*x509.Certificate{caCerts[0]}
	require.NoError(t, tm.storageContainer.CertificateRevocationListManager().Save(caCrls[0], crlDistpoint))

	// Make sure a 'wrong' CRL is returned, so it will not find the authoritive certificate
	crl = caCrls[1]

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.Equal(t, 1, requestCounter)
	files, _ := filepath.Glob(filepath.Join(basePath, "issuers", "crls", "*.crl"))
	require.Len(t, files, 0)
}

func testSyncCertificateRevocationListsReadsCachedCrlAndDoesNotNeedToUpdate(t *testing.T) {
	// Arrange
	tm, _ := setupTrustModelWithStoragePath(t)

	// Create a root certificate with distribution point + CRL and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	_, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &yiviCrlDistPoint)

	tm.allCerts = append(tm.allCerts, rootCert)
	tm.allCerts = append(tm.allCerts, caCerts...)

	mgr := tm.storageContainer.CertificateRevocationListManager()
	require.NoError(t, mgr.Save(caCrls[0], yiviCrlDistPoint))

	// Startup a test server, which will count any requests made to it
	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte{0x01, 0x02, 0x03, 0x04, 0x05})
		requestCounter++
	}))
	defer ts.Close()

	// Change client configuration to use the test server
	tm.httpClient = ts.Client()

	// Act
	tm.syncCertificateRevocationLists()

	// Assert there were no HTTP calls and the CRL is still cached
	require.Equal(t, 0, requestCounter)
	exists, err := mgr.Exists(yiviCrlDistPoint)
	require.NoError(t, err)
	require.True(t, exists)
}

func testSyncCertificateRevocationListsReadsCrlFileAndUpdatesGivenCrlNextUpdateIsInThePast(t *testing.T) {
	// Arrange
	tm, _ := setupTrustModelWithStoragePath(t)
	var updatedCrl *x509.RevocationList

	// Startup a test server, which will count any requests made to it
	requestCounter := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(updatedCrl.Raw)
		requestCounter++
	}))
	defer ts.Close()

	crlDistPoint := ts.URL + "/crl.crl"

	// Create a root certificate with distribution point + CRL and write it to storage
	rootDN := testdata.CreateDistinguishedName("ROOT CERT 1")
	rootKey, rootCert, _, _, caCrls := testdata.CreateTestPkiHierarchy(t, rootDN, 1, testdata.PkiOption_None, &crlDistPoint)
	updatedCrl = caCrls[0]

	// Setup an expired CRL and cache it
	oldCrlTemplate := testdata.GetDefaultCrlTemplate(rootCert)
	oldCrlTemplate.NextUpdate = time.Now().Add(-time.Hour)
	oldCrlBytes, err := x509.CreateRevocationList(rand.Reader, oldCrlTemplate, rootCert, rootKey)
	require.NoError(t, err)
	oldCrl, err := x509.ParseRevocationList(oldCrlBytes)
	require.NoError(t, err)
	mgr := tm.storageContainer.CertificateRevocationListManager()
	require.NoError(t, mgr.Save(oldCrl, crlDistPoint))

	tm.httpClient = ts.Client()
	tm.revocationListsDistributionPoints = []string{crlDistPoint}
	tm.allCerts = append(tm.allCerts, rootCert)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	require.Equal(t, 1, requestCounter)

	// The cached CRL should now be the updated one
	cached, err := mgr.Read(crlDistPoint)
	require.NoError(t, err)
	require.Equal(t, updatedCrl.Number, cached.Number)
	require.Equal(t, updatedCrl.ThisUpdate.Unix(), cached.ThisUpdate.Unix())
}

func testDownloadVerifyAndCacheCrlDownloadsSavesAndVerifiesSuccessfully(t *testing.T) {
	// Arrange
	tm, _ := setupTrustModelWithStoragePath(t)

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

	// Act
	err := tm.downloadVerifyAndCacheCrl(crlDownloadUrl)

	// Assert
	require.NoError(t, err)
	exists, err := tm.storageContainer.CertificateRevocationListManager().Exists(crlDownloadUrl)
	require.NoError(t, err)
	require.True(t, exists)
}

func testDownloadVerifyAndCacheCrlThrowsErrorOnUnknownURL(t *testing.T) {
	// Arrange
	tm, _ := setupTrustModelWithStoragePath(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	tm.httpClient = ts.Client()

	invalidCrlUri := fmt.Sprintf("%s/crl.crl", ts.URL)

	// Act
	err := tm.downloadVerifyAndCacheCrl(invalidCrlUri)

	// Assert
	require.Error(t, err, "error downloading CRL file")
	require.ErrorContains(t, err, "error downloading CRL file")
}

func testDownloadVerifyAndCacheCrlThrowsErrorOnInvalidCRLDownloadContent(t *testing.T) {
	// Arrange
	tm, _ := setupTrustModelWithStoragePath(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("invalid crl content"))
	}))
	defer ts.Close()

	tm.httpClient = ts.Client()

	// Act
	err := tm.downloadVerifyAndCacheCrl(ts.URL)

	// Assert
	require.Error(t, err, "error reading CRL file")
	require.ErrorContains(t, err, "error reading CRL file")
}

func testDownloadVerifyAndCacheCrlThrowsErrorOnInvalidCRLSignature(t *testing.T) {
	// Arrange
	tm, _ := setupTrustModelWithStoragePath(t)

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
	err := tm.downloadVerifyAndCacheCrl(ts.URL)

	// Assert
	require.ErrorContains(t, err, "CRL signature is invalid")
}

// installCertChain encodes the given certs as a single PEM block (in the order
// given) and installs them through the trust model's certificate manager, so
// the data lands at the hashed filename and is encrypted at rest. Replaces
// ad-hoc plaintext disk writes in tests now that the FS layer always encrypts.
//
// InstallCertificate derives the filename from the signature of the first
// certificate in the chain (leaf), so callers must pass certs in
// leaf-to-root order — otherwise chains sharing the same root would collide.
func installCertChain(t *testing.T, tm *TrustModel, certs ...*x509.Certificate) {
	t.Helper()
	var pemBytes []byte
	for _, cert := range certs {
		pemBytes = append(pemBytes, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})...)
	}
	require.NoError(t, tm.storageContainer.CertificateManager().InstallCertificate(pemBytes))
}

// HELPER FUNCTIONS
func setupTrustModelWithStoragePath(t *testing.T) (*TrustModel, string) {
	storageFolder := test.CreateTestStorage(t)

	basePath := filepath.Join(storageFolder, "eudi")

	s := filesystem.NewFileSystemStorage([32]byte{}, basePath)

	tm := &TrustModel{
		storageContainer: s.Issuers(),
		logger:           logrus.New(),
	}
	tm.clear()

	return tm, basePath
}

func testCacheLogoCachesLogoSuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiConfigPath := filepath.Join(storageFolder, "eudi")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := storage.NewStorage(aesKey, ":memory:", eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	logo := &scheme.Logo{
		Data:     []byte("test logo data"),
		MimeType: "image/png",
	}

	mgr := conf.Storage.FileSystem().Verifiers().LogoManager()
	require.NoError(t, mgr.Save("test_logo", logo.Data))

	got, err := mgr.Get("test_logo")
	require.NoError(t, err)
	require.Equal(t, logo.Data, got)
}

func testCacheVerifierLogoCachesLogoMultipleTimesSuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiConfigPath := filepath.Join(storageFolder, "eudi")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := storage.NewStorage(aesKey, ":memory:", eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	mgr := conf.Storage.FileSystem().Verifiers().LogoManager()

	logo := &scheme.Logo{
		Data:     []byte("test logo data"),
		MimeType: "image/png",
	}
	require.NoError(t, mgr.Save("test_logo", logo.Data))

	// A second Save with the same key should overwrite.
	logo.Data = []byte("updated logo data")
	require.NoError(t, mgr.Save("test_logo", logo.Data))

	got, err := mgr.Get("test_logo")
	require.NoError(t, err)
	require.Equal(t, logo.Data, got)
}

func testCacheVerifierLogoReturnsErrorOnNilLogo(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiConfigPath := filepath.Join(storageFolder, "eudi")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := storage.NewStorage(aesKey, ":memory:", eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	err = conf.Storage.FileSystem().Verifiers().LogoManager().Save("test_logo", nil)
	require.Error(t, err)
	require.EqualError(t, err, "invalid logo: data cannot be nil or empty")
}

func testCacheVerifierLogoReturnsErrorOnEmptyLogoData(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiConfigPath := filepath.Join(storageFolder, "eudi")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := storage.NewStorage(aesKey, ":memory:", eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	mgr := conf.Storage.FileSystem().Verifiers().LogoManager()

	err = mgr.Save("test_logo", []byte(""))
	require.Error(t, err)
	require.EqualError(t, err, "invalid logo: data cannot be nil or empty")

	err = mgr.Save("test_logo", nil)
	require.Error(t, err)
	require.EqualError(t, err, "invalid logo: data cannot be nil or empty")
}
