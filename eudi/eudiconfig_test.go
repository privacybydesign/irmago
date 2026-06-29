package eudi

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/eudi/storage"
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
	s, err := storage.NewStorage(aesKey, ":memory:", eudiAppDataPath)
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
	t.Run("Strict jwt_vc_json verification toggle", testStrictJwtVcJsonVerificationToggle)
}

func testStrictJwtVcJsonVerificationToggle(t *testing.T) {
	storageFolder := test.CreateTestStorage(t)
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")
	err := common.EnsureDirectoryExists(eudiAppDataPath)
	require.NoError(t, err)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := storage.NewStorage(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	conf, err := NewConfiguration(s)
	require.NoError(t, err)

	// Default mode is compatibility-focused.
	require.False(t, conf.StrictJwtVcJsonVerificationEnabled())
	require.Equal(t, 5*time.Minute, conf.StrictJwtVcJsonTemporalClockSkew())

	conf.EnableStrictJwtVcJsonVerification()
	require.True(t, conf.StrictJwtVcJsonVerificationEnabled())

	// Idempotent enable should keep strict mode on.
	conf.EnableStrictJwtVcJsonVerification()
	require.True(t, conf.StrictJwtVcJsonVerificationEnabled())

	conf.DisableStrictJwtVcJsonVerification()
	require.False(t, conf.StrictJwtVcJsonVerificationEnabled())

	// Idempotent disable should keep strict mode off.
	conf.DisableStrictJwtVcJsonVerification()
	require.False(t, conf.StrictJwtVcJsonVerificationEnabled())

	err = conf.SetStrictJwtVcJsonTemporalClockSkew(2 * time.Minute)
	require.NoError(t, err)
	require.Equal(t, 2*time.Minute, conf.StrictJwtVcJsonTemporalClockSkew())

	err = conf.SetStrictJwtVcJsonTemporalClockSkew(0)
	require.NoError(t, err)
	require.Equal(t, time.Duration(0), conf.StrictJwtVcJsonTemporalClockSkew())

	err = conf.SetStrictJwtVcJsonTemporalClockSkew(-1 * time.Second)
	require.EqualError(t, err, "strict jwt_vc_json temporal clock skew must be non-negative")
	require.Equal(t, time.Duration(0), conf.StrictJwtVcJsonTemporalClockSkew())
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
	s, err := storage.NewStorage(aesKey, ":memory:", eudiAppDataPath)
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
	eudiAppDataPath := filepath.Join(storageFolder, "eudi")

	err := common.EnsureDirectoryExists(eudiAppDataPath)
	require.NoError(t, err)

	aesKey := [32]byte{}
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")
	s, err := storage.NewStorage(aesKey, ":memory:", eudiAppDataPath)
	require.NoError(t, err)

	// Act
	conf, err := NewConfiguration(s)

	require.NoError(t, err)
	require.NoError(t, conf.Reload())
	require.NotEmpty(t, conf.Issuers)
	require.NotEmpty(t, conf.Verifiers)
	require.NotNil(t, conf.Issuers.trustedRootCertificates)
	require.NotEmpty(t, conf.Issuers.trustedRootCertificates)
	require.NotNil(t, conf.Issuers.trustedIntermediateCertificates)
	require.NotEmpty(t, conf.Issuers.trustedIntermediateCertificates)
}
