package eudi

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// ============================================================
// CRL FAIL-OPEN: a failed refresh must not delete usable revocation information
// ============================================================
//
// ISO/IEC 18013-5 9.3.3 requires a party performing certification path validation
// to have "access to certificate revocation information". These tests cover what
// happens when that access is temporarily lost — which, for an offline proximity
// wallet, is the normal case rather than the exceptional one.
//
// The defect they pin: syncCertificateRevocationLists used to remove the cached
// CRL whenever the download failed. Removing turns *stale data* into *no data*,
// and no data is indistinguishable from an issuer that publishes no CRL at all —
// GetRevocationListsForIssuer returns an empty slice and
// VerifyCertificateAgainstIssuerRevocationLists then accepts everything. A
// transient 500, a captive portal, or simply being offline past a CRL's
// NextUpdate silently switched revocation checking off.
//
// This matters more since mdoc reader authentication (9.1.4) landed: the wallet
// now validates a reader's chain through this same trust model, so the failure
// mode is a long-offline wallet accepting a *revoked reader* — precisely the
// scenario offline proximity exists for.

func TestTrustModelRevocationResilience(t *testing.T) {
	t.Run("a stale but usable CRL survives a failed refresh", testSyncKeepsStaleCrlWhenDownloadFails)
	t.Run("an unusable cached CRL is still removed on a failed refresh", testSyncRemovesUnusableCrlWhenDownloadFails)
	t.Run("a revoked certificate stays refused after a failed refresh", testStaleCrlStillRefusesRevokedCertificateAfterFailedSync)
	t.Run("RevocationInformationFor reports fresh, stale and absent", testRevocationInformationForReportsFreshness)
}

// failingCrlServer returns a server that always fails, and counts the attempts.
// A 500 rather than a closed port so the failure is a live endpoint misbehaving,
// which is the case that used to delete the cache while looking entirely routine
// in the logs.
func failingCrlServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	return server, &attempts
}

// backdatedCrl builds a genuine CRL, signed by issuer, whose NextUpdate is
// staleBy in the past — optionally listing certificates as revoked.
//
// ThisUpdate is moved back with it, which is the whole reason this helper
// exists. testdata.GetDefaultCrlTemplate puts ThisUpdate an hour in the past, so
// backdating NextUpdate on its own puts the two in the wrong order and
// x509.CreateRevocationList refuses the template with "template.ThisUpdate is
// after template.NextUpdate".
func backdatedCrl(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey crypto.Signer,
	staleBy time.Duration,
	revoked ...*x509.Certificate,
) *x509.RevocationList {
	t.Helper()

	template := testdata.GetDefaultCrlTemplate(issuer)
	template.NextUpdate = time.Now().Add(-staleBy)
	template.ThisUpdate = template.NextUpdate.Add(-time.Hour)
	for _, cert := range revoked {
		template.RevokedCertificateEntries = append(template.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   cert.SerialNumber,
			RevocationTime: template.ThisUpdate,
		})
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	require.NoError(t, err)
	crl, err := x509.ParseRevocationList(der)
	require.NoError(t, err)
	return crl
}

// testSyncKeepsStaleCrlWhenDownloadFails is the regression test. The cached CRL
// is genuine and signed by a known authority; it has simply gone past its
// NextUpdate, and the refresh cannot be completed.
func testSyncKeepsStaleCrlWhenDownloadFails(t *testing.T) {
	// Arrange
	tm, _ := setupTrustModelWithStoragePath(t)
	server, attempts := failingCrlServer(t)

	crlDistPoint := server.URL + "/crl.crl"
	rootKey, rootCert, _, _, _ := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, testdata.PkiOption_None, &crlDistPoint)

	cachedCrl := backdatedCrl(t, rootCert, rootKey, time.Hour)

	mgr := tm.storageContainer.CertificateRevocationListManager()
	require.NoError(t, mgr.Save(cachedCrl, crlDistPoint))

	tm.httpClient = server.Client()
	tm.revocationListsDistributionPoints = []string{crlDistPoint}
	tm.allCerts = append(tm.allCerts, rootCert)

	// Act
	tm.syncCertificateRevocationLists()

	// Assert: the refresh was attempted and failed...
	require.Equal(t, 1, *attempts)

	// ...and the cached copy survived it, unchanged.
	exists, err := mgr.Exists(crlDistPoint)
	require.NoError(t, err)
	require.True(t, exists,
		"a stale but usable CRL was deleted when its refresh failed, which switches revocation checking off entirely")

	reread, err := mgr.Read(crlDistPoint)
	require.NoError(t, err)
	require.Equal(t, cachedCrl.Number, reread.Number)
	require.Equal(t, cachedCrl.ThisUpdate.Unix(), reread.ThisUpdate.Unix())
}

// testSyncRemovesUnusableCrlWhenDownloadFails is the other half of the rule. A
// cached file whose signature cannot be verified against any known authority is
// not revocation information at all — loadRevocationLists already skips it — so
// keeping it would only mean re-parsing a useless file on every sync.
func testSyncRemovesUnusableCrlWhenDownloadFails(t *testing.T) {
	// Arrange
	tm, basePath := setupTrustModelWithStoragePath(t)
	server, _ := failingCrlServer(t)

	crlDistPoint := server.URL + "/crl.crl"
	_, _, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, testdata.PkiOption_None, &crlDistPoint)

	require.NoError(t, tm.storageContainer.CertificateRevocationListManager().Save(caCrls[0], crlDistPoint))

	tm.httpClient = server.Client()
	tm.revocationListsDistributionPoints = []string{crlDistPoint}
	// The CRL is signed by the root, which is deliberately NOT in allCerts, so no
	// authority can be found for it and isCrlValid rejects the cached copy.
	tm.allCerts = []*x509.Certificate{caCerts[0]}

	// Act
	tm.syncCertificateRevocationLists()

	// Assert
	files, _ := filepath.Glob(filepath.Join(basePath, "issuers", "crls", "*.crl"))
	require.Len(t, files, 0, "an unusable cached CRL should be removed rather than re-parsed on every sync")
}

// testStaleCrlStillRefusesRevokedCertificateAfterFailedSync is the property the
// whole fix exists for, end to end: an offline wallet must go on refusing a
// certificate it already knows was revoked.
//
// Everything here is genuine — real chain, real CRL, real revocation entry — and
// the only thing wrong is that the device cannot reach the distribution point.
// Before the fix the cached CRL was deleted at exactly this point and the revoked
// certificate was then accepted.
func testStaleCrlStillRefusesRevokedCertificateAfterFailedSync(t *testing.T) {
	// Arrange
	tm, _ := setupTrustModelWithStoragePath(t)
	server, _ := failingCrlServer(t)

	crlDistPoint := server.URL + "/crl.crl"
	rootKey, rootCert, _, caCerts, _ := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, testdata.PkiOption_None, &crlDistPoint)
	revokedCert := caCerts[0]

	cachedCrl := backdatedCrl(t, rootCert, rootKey, time.Hour, revokedCert)

	require.NoError(t, tm.storageContainer.CertificateRevocationListManager().Save(cachedCrl, crlDistPoint))

	tm.httpClient = server.Client()
	tm.revocationListsDistributionPoints = []string{crlDistPoint}
	tm.allCerts = append(tm.allCerts, rootCert)

	// Sanity: with the CRL loaded, the revoked certificate is refused. Without
	// this the assertion after the sync could pass for the wrong reason.
	require.NoError(t, tm.loadRevocationLists())
	require.Len(t, tm.GetRevocationLists(), 1)
	require.Error(t, utils.VerifyCertificateAgainstIssuerRevocationLists(revokedCert, tm.GetRevocationLists()))

	// Act: the refresh fails, as it would on a device with no connectivity.
	tm.syncCertificateRevocationLists()
	require.NoError(t, tm.loadRevocationLists())

	// Assert: the revocation is still known, and still enforced.
	require.Len(t, tm.GetRevocationLists(), 1,
		"revocation information was lost when the refresh failed, so a revoked certificate would now be accepted")
	require.Error(t, utils.VerifyCertificateAgainstIssuerRevocationLists(revokedCert, tm.GetRevocationLists()),
		"a certificate known to be revoked was accepted after a failed CRL refresh")
}

// testRevocationInformationForReportsFreshness covers the signal a caller needs
// in order to apply a grace window and then hard-fail — what turns "we kept the
// stale list" into a policy rather than indefinite trust in old data.
func testRevocationInformationForReportsFreshness(t *testing.T) {
	rootKey, rootCert, _, caCerts, caCrls := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("ROOT CERT 1"), 1, testdata.PkiOption_None, &yiviCrlDistPoint)
	// The sub-CA is issued by the root, and the CRL is issued by the root, so the
	// authority key id and issuer name line up the way GetRevocationListsForIssuer
	// requires.
	subject := caCerts[0]

	t.Run("absent when no CRL is held", func(t *testing.T) {
		tm, _ := setupTrustModelWithStoragePath(t)
		freshness, staleness := tm.RevocationInformationFor(subject)
		require.Equal(t, RevocationInformationAbsent, freshness)
		require.Zero(t, staleness)
		require.Equal(t, "absent", freshness.String())
	})

	t.Run("fresh before NextUpdate", func(t *testing.T) {
		tm, _ := setupTrustModelWithStoragePath(t)
		tm.allCerts = append(tm.allCerts, rootCert)
		tm.revocationLists = []*x509.RevocationList{caCrls[0]}

		freshness, staleness := tm.RevocationInformationFor(subject)
		require.Equal(t, RevocationInformationFresh, freshness)
		require.Zero(t, staleness)
		require.Equal(t, "fresh", freshness.String())
	})

	t.Run("stale, with its age, after NextUpdate", func(t *testing.T) {
		tm, _ := setupTrustModelWithStoragePath(t)
		tm.allCerts = append(tm.allCerts, rootCert)

		tm.revocationLists = []*x509.RevocationList{backdatedCrl(t, rootCert, rootKey, 3*time.Hour)}

		freshness, staleness := tm.RevocationInformationFor(subject)
		require.Equal(t, RevocationInformationStale, freshness)
		require.Equal(t, "stale", freshness.String())
		// Measured from NextUpdate, so roughly the three hours set above.
		require.InDelta(t, (3 * time.Hour).Seconds(), staleness.Seconds(), 60)
	})

	t.Run("the freshest list wins when several cover the issuer", func(t *testing.T) {
		tm, _ := setupTrustModelWithStoragePath(t)
		tm.allCerts = append(tm.allCerts, rootCert)

		oldCrl := backdatedCrl(t, rootCert, rootKey, 10*time.Hour)

		// Oldest first, so a naive implementation returning lists[0] fails here.
		tm.revocationLists = []*x509.RevocationList{oldCrl, caCrls[0]}

		freshness, _ := tm.RevocationInformationFor(subject)
		require.Equal(t, RevocationInformationFresh, freshness)
	})

	t.Run("a nil certificate is absent rather than a panic", func(t *testing.T) {
		tm, _ := setupTrustModelWithStoragePath(t)
		freshness, staleness := tm.RevocationInformationFor(nil)
		require.Equal(t, RevocationInformationAbsent, freshness)
		require.Zero(t, staleness)
	})
}
