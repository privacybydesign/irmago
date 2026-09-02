package eudi

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipherstorage"
	"github.com/privacybydesign/irmago/eudi/walletconfig"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
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
	t.Run("anchors follow the active environment", testAnchorsFollowTheActiveEnvironment)
	t.Run("Reload anchors the config's CA entities for their role", testReloadAnchorsTheConfigsCAEntities)
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

	require.NotNil(t, conf.Issuers.state().trustedRootCertificates)
	require.NotNil(t, conf.Issuers.state().trustedRootCertificates)
	require.NotNil(t, conf.Issuers.state().revocationLists)
	require.Len(t, conf.Issuers.state().revocationLists, 0)
	require.NotNil(t, conf.Verifiers.state().trustedRootCertificates)
	require.NotNil(t, conf.Verifiers.state().trustedIntermediateCertificates)
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
	conf.WalletConfig = newYiviManager(t, walletconfig.EnvironmentProduction)

	require.NoError(t, conf.Reload())
	require.NotNil(t, conf.Issuers.state().trustedRootCertificates)
	require.NotEmpty(t, conf.Issuers.state().trustedRootCertificates)
	require.NotNil(t, conf.Issuers.state().trustedIntermediateCertificates)
	require.NotEmpty(t, conf.Issuers.state().trustedIntermediateCertificates)
}

// The anchors follow the active environment: production anchors in production,
// staging anchors in staging, never both.
func testAnchorsFollowTheActiveEnvironment(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")

	err := common.EnsureDirectoryExists(eudiAppDataPath)
	require.NoError(t, err)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := sqlcipherstorage.New(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(s)
	require.NoError(t, err)
	manager := newYiviManager(t, walletconfig.EnvironmentProduction)
	conf.WalletConfig = manager

	trustsRoot := func(tm *TrustModel, commonName string) bool {
		return slices.ContainsFunc(tm.state().allCerts, func(cert *x509.Certificate) bool {
			return cert.Subject.CommonName == commonName
		})
	}

	require.NoError(t, conf.Reload())
	for _, tm := range []*TrustModel{&conf.Issuers, &conf.Verifiers} {
		require.True(t, trustsRoot(tm, "Yivi Requestors Root CA"))
		require.True(t, trustsRoot(tm, "Ver.iD Root CA"))
		require.False(t, trustsRoot(tm, "Yivi Staging Requestors Root CA"))
		require.False(t, trustsRoot(tm, "Ver.iD Dev Root CA"))
	}
	require.True(t, trustsRoot(&conf.Issuers, "Yivi Attestation Providers CA"))
	require.False(t, trustsRoot(&conf.Issuers, "Yivi Relying Parties CA"), "the verifier CA anchors verifiers only")
	require.True(t, trustsRoot(&conf.Verifiers, "Yivi Relying Parties CA"))
	require.False(t, trustsRoot(&conf.Verifiers, "Yivi Attestation Providers CA"))

	require.NoError(t, manager.SwitchEnvironment(walletconfig.EnvironmentStaging))
	require.NoError(t, conf.Reload())
	for _, tm := range []*TrustModel{&conf.Issuers, &conf.Verifiers} {
		require.False(t, trustsRoot(tm, "Yivi Requestors Root CA"), "staging never carries production anchors")
		require.False(t, trustsRoot(tm, "Ver.iD Root CA"))
		require.True(t, trustsRoot(tm, "Yivi Staging Requestors Root CA"))
		require.True(t, trustsRoot(tm, "Ver.iD Dev Root CA"))
	}
}

// A held config's CA entities anchor next to the built-in ones, and a
// certificate under one of them validates for the entity's role only.
func testReloadAnchorsTheConfigsCAEntities(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")
	require.NoError(t, common.EnsureDirectoryExists(eudiAppDataPath))

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := sqlcipherstorage.New(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	signer := walletconfig.NewTestSigner(t)
	caKey, ca := walletconfig.NewTestCA(t, "Listed Issuer CA", nil, nil)
	_, leaf := walletconfig.NewTestEndEntity(t, "issuer.example", ca, caKey, nil)

	config := walletconfig.NewTestConfig("test", 1, time.Now())
	config.TrustedEntities = []walletconfig.TrustedEntity{{
		ID:         "listed-issuer-ca",
		Name:       clientmodels.TranslatedString{"en": "Listed"},
		Roles:      []walletconfig.Role{walletconfig.RoleIssuer},
		TrustLevel: clientmodels.TrustLevel_Medium,
		Handles:    []walletconfig.Handle{{Type: walletconfig.HandleTypeX509CA, RootCertificate: &walletconfig.Certificate{Certificate: ca}}},
	}}
	store := walletconfig.NewMemoryStore()
	require.NoError(t, store.Put(config.ID, signer.Sign(t, config)))
	manager, err := walletconfig.NewManager(walletconfig.Options{
		Environments: []walletconfig.Environment{signer.Environment("test", "https://config.example/v1/")},
		Active:       "test",
		Store:        store,
	})
	require.NoError(t, err)

	conf, err := NewConfiguration(s)
	require.NoError(t, err)
	conf.WalletConfig = manager
	require.NoError(t, conf.Reload())

	chains, err := conf.Issuers.ValidateChain(leaf)
	require.NoError(t, err)
	require.Len(t, chains, 1)
	require.True(t, ca.Equal(chains[0][len(chains[0])-1]))

	_, err = conf.Verifiers.ValidateChain(leaf)
	require.ErrorContains(t, err, "unknown authority", "an issuer CA anchors nothing for verifiers")
}

// newYiviManager is a manager on the built-in Yivi environments, which are
// unpublished and so need no store, server or root.
func newYiviManager(t *testing.T, active string) *walletconfig.Manager {
	t.Helper()
	manager, err := walletconfig.NewManager(walletconfig.Options{
		Environments: walletconfig.YiviEnvironments(),
		Active:       active,
	})
	require.NoError(t, err)
	return manager
}
