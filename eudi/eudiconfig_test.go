package eudi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	t.Run("NewConfiguration creates required directories and initializes successfully", testNewConfigurationSuccessfulInitialization)
	t.Run("NewConfiguration reads the pinned issuer and verifier trust anchor(s)", testNewConfigurationReadsPinnedTrustAnchors)

	// t.Run("NewConfiguration reads issuer and verifier trustmodels from file", testParseFolderReadsIssuerAndVerifierTrustModels)

	// // Logo cache tests
	// t.Run("CacheVerifierLogo caches logo successfully", testCacheVerifierLogoCachesLogoSuccessfully)
	// t.Run("CacheVerifierLogo caches logo multiple times successfully", testCacheVerifierLogoCachesLogoMultipleTimesSuccessfully)
	// t.Run("CacheVerifierLogo returns error on nil logo", testCacheVerifierLogoReturnsErrorOnNilLogo)
	// t.Run("CacheVerifierLogo returns error on empty logo data", testCacheVerifierLogoReturnsErrorOnEmptyLogoData)
	// t.Run("CacheVerifierLogo returns error on unknown mime type", testCacheVerifierLogoReturnsErrorOnUnknownMimeType)

}

func testNewConfigurationSuccessfulInitialization(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	defer os.RemoveAll(storageFolder)

	err := common.EnsureDirectoryExists(filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)

	require.NoDirExists(t, filepath.Join(storageFolder, "eudi_configuration", "issuers"))
	require.NoDirExists(t, filepath.Join(storageFolder, "eudi_configuration", "verifiers"))

	conf, err := NewConfiguration(filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)
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
	defer os.RemoveAll(storageFolder)

	err := common.EnsureDirectoryExists(filepath.Join(storageFolder, "eudi_configuration"))
	require.NoError(t, err)

	conf, err := NewConfiguration(filepath.Join(storageFolder, "eudi_configuration"))

	require.NoError(t, err)
	require.NotEmpty(t, conf.Issuers)
	require.NotEmpty(t, conf.Verifiers)
	require.NotNil(t, conf.Issuers.trustedRootCertificates)
	require.NotEmpty(t, conf.Issuers.trustedRootCertificates)
	require.NotNil(t, conf.Issuers.trustedIntermediateCertificates)
	require.NotEmpty(t, conf.Issuers.trustedIntermediateCertificates)
}
