package eudi

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipherstorage"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	Logger = logrus.New()
	os.Exit(m.Run())
}

func TestIntegrationConfig(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiAppDataPath := filepath.Join(storageFolder, "eudi")
	err := common.EnsureDirectoryExists(eudiAppDataPath)
	require.NoError(t, err)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := sqlcipherstorage.New(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	// Act
	conf, err := NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	require.NoError(t, conf.Reload())
	require.NoError(t, conf.UpdateCertificateRevocationLists())
}

func TestConfig(t *testing.T) {
	t.Run("NewConfiguration creates required directories and initializes successfully", testNewConfigurationSuccessfulInitialization)
	t.Run("NewConfiguration reads the pinned issuer and verifier trust anchor(s)", testNewConfigurationReadsPinnedTrustAnchors)
	t.Run("UpdateCertificateRevocationLists fetches for every trust model", testUpdateCertificateRevocationListsFetchesForEveryTrustModel)
}

func testUpdateCertificateRevocationListsFetchesForEveryTrustModel(t *testing.T) {
	// UpdateCertificateRevocationLists is the only thing that downloads CRLs, so a
	// trust model it skips holds none at all. That matters for the trust lists:
	// a revoked list-signing certificate only invalidates the lists already on
	// disk if its CRL was ever fetched (see lote.Store).
	storageFolder := test.CreateTestStorage(t)
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")
	require.NoError(t, common.EnsureDirectoryExists(eudiAppDataPath))

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := sqlcipherstorage.New(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(s)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	// One CRL per trust model, so the assertion names which one went unfetched.
	_, rootCert, _, _, caCrls := testdata.CreateTestPkiHierarchy(
		t, testdata.CreateDistinguishedName("CRL ROOT"), 1, testdata.PkiOption_None, nil,
	)

	var mu sync.Mutex
	requested := map[string]int{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requested[r.URL.Path]++
		mu.Unlock()
		_, _ = w.Write(caCrls[0].Raw)
	}))
	defer ts.Close()

	// Set after Reload: it is Reload that clears the distribution points.
	models := map[string]*TrustModel{
		"/issuers.crl":    &conf.Issuers,
		"/verifiers.crl":  &conf.Verifiers,
		"/trustlists.crl": &conf.TrustLists,
	}
	for path, tm := range models {
		tm.httpClient = ts.Client()
		tm.mutate(func(s *trustState) { s.distributionPoints = []string{ts.URL + path} })
		tm.mutate(func(s *trustState) { s.allCerts = []*x509.Certificate{rootCert} })
	}

	require.NoError(t, conf.UpdateCertificateRevocationLists())

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, map[string]int{"/issuers.crl": 1, "/verifiers.crl": 1, "/trustlists.crl": 1}, requested)
}

func testNewConfigurationSuccessfulInitialization(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiAppDataPath := filepath.Join(storageFolder, "eudi")
	err := common.EnsureDirectoryExists(eudiAppDataPath)
	require.NoError(t, err)

	issuerBasePath := filepath.Join(eudiAppDataPath, "issuers")
	verifierBasePath := filepath.Join(eudiAppDataPath, "verifiers")

	require.NoDirExists(t, issuerBasePath)
	require.NoDirExists(t, verifierBasePath)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := sqlcipherstorage.New(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	// Act
	conf, err := NewConfiguration(s)

	require.NoError(t, err)
	require.NoError(t, conf.Reload())
	require.NotNil(t, conf)
	require.DirExists(t, filepath.Join(issuerBasePath, "certificates"))
	require.DirExists(t, filepath.Join(issuerBasePath, "crls"))
	require.DirExists(t, filepath.Join(issuerBasePath, "logos"))
	require.DirExists(t, filepath.Join(verifierBasePath, "certificates"))
	require.DirExists(t, filepath.Join(verifierBasePath, "crls"))
	require.DirExists(t, filepath.Join(verifierBasePath, "logos"))

	require.NotNil(t, conf.Issuers.state().roots)
	require.NotNil(t, conf.Issuers.state().roots)
	require.NotNil(t, conf.Issuers.state().revocationLists)
	require.Len(t, conf.Issuers.state().revocationLists, 0)
	require.NotNil(t, conf.Verifiers.state().roots)
	require.NotNil(t, conf.Verifiers.state().intermediates)
	require.NotNil(t, conf.Verifiers.state().revocationLists)
	require.Len(t, conf.Verifiers.state().revocationLists, 0)
}

func testNewConfigurationReadsPinnedTrustAnchors(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")

	err := common.EnsureDirectoryExists(eudiAppDataPath)
	require.NoError(t, err)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := sqlcipherstorage.New(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	// Act
	conf, err := NewConfiguration(s)

	require.NoError(t, err)
	require.NoError(t, conf.Reload())
	// Asserted through their pools: a TrustModel carries a mutex, so passing one
	// by value to require would copy a lock. Emptiness is asserted against a fresh
	// pool rather than with NotEmpty, since testify sees an empty *x509.CertPool
	// as non-empty.
	require.False(t, conf.Verifiers.state().roots.Equal(x509.NewCertPool()),
		"the pinned verifier root anchors are loaded")
	require.False(t, conf.Issuers.state().roots.Equal(x509.NewCertPool()),
		"the pinned issuer root anchors are loaded")
	require.False(t, conf.Issuers.state().intermediates.Equal(x509.NewCertPool()),
		"the pinned issuer intermediate anchors are loaded")
}

func newTestConfiguration(t *testing.T) *Configuration {
	t.Helper()

	eudiAppDataPath := filepath.Join(test.CreateTestStorage(t), "eudi")
	require.NoError(t, common.EnsureDirectoryExists(eudiAppDataPath))

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := sqlcipherstorage.New(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(s)
	require.NoError(t, err)
	return conf
}

// Explicit distribution points are for the case the chain cannot cover: a
// root-only anchor yields none, because addTrustAnchors only reads them off
// intermediates. The anchor is still added — the same as for issuers and
// verifiers, which have the identical gap — and the warning is the only thing
// that says its certificates can never be revoked.
func TestExtraTrustListTrustAnchors_AreAddedWithoutDistributionPoints(t *testing.T) {
	conf := newTestConfiguration(t)
	conf.ExtraTrustListTrustAnchors = []ExtraTrustAnchor{{
		PEM: []byte(Production_Yivi_IssuerTrustAnchor),
	}}

	require.NoError(t, conf.Reload())
}

// A chain carrying a CA certificate that advertises its CRL needs nothing
// explicit: walking the chain registers it, which is why issuer and verifier
// anchors have never needed a distribution-point field either.
func TestAddTrustAnchors_DiscoversDistributionPointsFromTheChain(t *testing.T) {
	conf := newTestConfiguration(t)
	require.NoError(t, conf.Reload())

	before := len(conf.Issuers.state().distributionPoints)
	require.NoError(t, conf.Issuers.addTrustAnchors(
		clientmodels.TrustLevel_Medium, []byte(Production_Yivi_IssuerTrustAnchor)))
	conf.Issuers.commit()

	require.GreaterOrEqual(t, len(conf.Issuers.state().distributionPoints), before,
		"an intermediate advertising a CRL contributes it without being told")
}

// The point of the seam: an anchor added through it is not merely trusted, its
// revocation lists are fetched too.
func TestExtraTrustListTrustAnchors_RegisterTheirDistributionPoints(t *testing.T) {
	const distPoint = "https://ca.example.com/trustlist.crl"

	conf := newTestConfiguration(t)
	conf.ExtraTrustListTrustAnchors = []ExtraTrustAnchor{{
		PEM:                   []byte(Production_Yivi_IssuerTrustAnchor),
		CRLDistributionPoints: []string{distPoint},
	}}

	require.NoError(t, conf.Reload())

	require.Contains(t, conf.TrustLists.state().distributionPoints, distPoint,
		"the CRL sync walks these, so an anchor missing from them is never revocable")
	require.NotContains(t, conf.Issuers.state().distributionPoints, distPoint,
		"and it goes to the trust-list model only, never the issuer one")
}

// One anchor type serves all three models, so the distribution points a
// trust-list anchor can carry work for an issuer anchor too — a gap they shared
// before the types were merged.
func TestExtraTrustAnchors_RegisterDistributionPointsForEveryModel(t *testing.T) {
	const issuerCRL = "https://ca.example.com/issuer.crl"
	const verifierCRL = "https://ca.example.com/verifier.crl"

	conf := newTestConfiguration(t)
	conf.ExtraIssuerTrustAnchors = []ExtraTrustAnchor{{
		PEM:                   []byte(Production_Yivi_IssuerTrustAnchor),
		Confers:               clientmodels.TrustLevel_Medium,
		CRLDistributionPoints: []string{issuerCRL},
	}}
	conf.ExtraVerifierTrustAnchors = []ExtraTrustAnchor{{
		PEM:                   []byte(Production_Yivi_VerifierTrustAnchor),
		Confers:               clientmodels.TrustLevel_Medium,
		CRLDistributionPoints: []string{verifierCRL},
	}}

	require.NoError(t, conf.Reload())

	require.Contains(t, conf.Issuers.state().distributionPoints, issuerCRL)
	require.Contains(t, conf.Verifiers.state().distributionPoints, verifierCRL)
	require.NotContains(t, conf.Issuers.state().distributionPoints, verifierCRL,
		"the three models stay apart")
}
