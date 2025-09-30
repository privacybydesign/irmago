package eudi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/eudi/scheme"
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

	eudiConfigPath := filepath.Join(storageFolder, "eudi_configuration")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(eudiConfigPath)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	require.NoError(t, conf.Reload())
	require.NoError(t, conf.UpdateCertificateRevocationLists())
}

func TestConfig(t *testing.T) {
	t.Run("NewConfiguration creates required directories and initializes successfully", testNewConfigurationSuccessfulInitialization)
	t.Run("NewConfiguration reads the pinned issuer and verifier trust anchor(s)", testNewConfigurationReadsPinnedTrustAnchors)

	// Logo cache tests
	t.Run("CacheVerifierLogo caches logo successfully", testCacheVerifierLogoCachesLogoSuccessfully)
	t.Run("CacheVerifierLogo caches logo multiple times successfully", testCacheVerifierLogoCachesLogoMultipleTimesSuccessfully)
	t.Run("CacheVerifierLogo returns error on nil logo", testCacheVerifierLogoReturnsErrorOnNilLogo)
	t.Run("CacheVerifierLogo returns error on empty logo data", testCacheVerifierLogoReturnsErrorOnEmptyLogoData)
	t.Run("CacheVerifierLogo returns error on unknown mime type", testCacheVerifierLogoReturnsErrorOnUnknownMimeType)
}

func testNewConfigurationSuccessfulInitialization(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	err := common.EnsureDirectoryExists(filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)

	require.NoDirExists(t, filepath.Join(storageFolder, "eudi_configuration", "issuers"))
	require.NoDirExists(t, filepath.Join(storageFolder, "eudi_configuration", "verifiers"))

	conf, err := NewConfiguration(filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)
	require.NoError(t, conf.Reload())
	require.NotNil(t, conf)
	require.DirExists(t, conf.Issuers.GetCertificatePath())
	require.DirExists(t, conf.Issuers.GetCrlPath())
	require.DirExists(t, conf.Issuers.GetLogosPath())
	require.DirExists(t, conf.Verifiers.GetCertificatePath())
	require.DirExists(t, conf.Verifiers.GetCrlPath())
	require.DirExists(t, conf.Verifiers.GetLogosPath())

	require.NotNil(t, conf.Issuers.trustedRootCertificates)
	require.NotNil(t, conf.Issuers.trustedRootCertificates)
	require.NotNil(t, conf.Issuers.revocationLists)
	require.Len(t, conf.Issuers.revocationLists, 0)
	require.NotNil(t, conf.Verifiers.trustedRootCertificates)
	require.NotNil(t, conf.Verifiers.trustedIntermediateCertificates)
	require.NotNil(t, conf.Verifiers.revocationLists)
	require.Len(t, conf.Verifiers.revocationLists, 0)
}

func testNewConfigurationReadsPinnedTrustAnchors(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	err := common.EnsureDirectoryExists(filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)

	conf, err := NewConfiguration(filepath.Join(storageFolder, "eudi_configuration"))

	require.NoError(t, err)
	require.NoError(t, conf.Reload())
	require.NotEmpty(t, conf.Issuers)
	require.NotEmpty(t, conf.Verifiers)
	require.NotNil(t, conf.Issuers.trustedRootCertificates)
	require.NotEmpty(t, conf.Issuers.trustedRootCertificates)
	require.NotNil(t, conf.Issuers.trustedIntermediateCertificates)
	require.NotEmpty(t, conf.Issuers.trustedIntermediateCertificates)
}

func testCacheVerifierLogoCachesLogoSuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiConfigPath := filepath.Join(storageFolder, "eudi_configuration")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(eudiConfigPath)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	logo := &scheme.Logo{
		Data:     []byte("test logo data"),
		MimeType: "image/png",
	}

	fullFilename, path, err := conf.CacheVerifierLogo("test_logo", logo)
	require.NoError(t, err)
	require.NotEmpty(t, fullFilename)
	require.NotEmpty(t, path)

	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, "test_logo.png", fileInfo.Name())
}

func testCacheVerifierLogoCachesLogoMultipleTimesSuccessfully(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiConfigPath := filepath.Join(storageFolder, "eudi_configuration")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(eudiConfigPath)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	logo := &scheme.Logo{
		Data:     []byte("test logo data"),
		MimeType: "image/png",
	}

	fullFilename, path, err := conf.CacheVerifierLogo("test_logo", logo)
	require.NoError(t, err)
	require.NotEmpty(t, fullFilename)
	require.NotEmpty(t, path)

	// Change logo data to simulate an update
	logo.Data = []byte("updated logo data")
	fullFilename, path, err = conf.CacheVerifierLogo("test_logo", logo)
	require.NoError(t, err)
	require.NotEmpty(t, fullFilename)
	require.NotEmpty(t, path)

	fileInfo, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, "test_logo.png", fileInfo.Name())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "updated logo data", string(data))
}

func testCacheVerifierLogoReturnsErrorOnNilLogo(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiConfigPath := filepath.Join(storageFolder, "eudi_configuration")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(eudiConfigPath)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	_, _, err = conf.CacheVerifierLogo("test_logo", nil)
	require.Error(t, err)
	require.EqualError(t, err, "invalid logo")
}

func testCacheVerifierLogoReturnsErrorOnEmptyLogoData(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiConfigPath := filepath.Join(storageFolder, "eudi_configuration")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(eudiConfigPath)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	logo := &scheme.Logo{
		Data:     []byte(""),
		MimeType: "image/png",
	}

	_, _, err = conf.CacheVerifierLogo("test_logo", logo)
	require.Error(t, err)
	require.EqualError(t, err, "invalid logo")

	logo.Data = nil
	_, _, err = conf.CacheVerifierLogo("test_logo", logo)
	require.Error(t, err)
	require.EqualError(t, err, "invalid logo")
}

func testCacheVerifierLogoReturnsErrorOnUnknownMimeType(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)

	eudiConfigPath := filepath.Join(storageFolder, "eudi_configuration")

	err := common.EnsureDirectoryExists(eudiConfigPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(eudiConfigPath)
	require.NoError(t, err)
	require.NoError(t, conf.Reload())

	logo := &scheme.Logo{
		Data:     []byte("test data"),
		MimeType: "image/unknown",
	}

	_, _, err = conf.CacheVerifierLogo("test_logo", logo)
	require.Error(t, err)
	require.EqualError(t, err, "unknown mime type \"image/unknown\"")
}
