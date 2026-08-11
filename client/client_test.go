package client

import (
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testhelpers"
	"github.com/stretchr/testify/require"
)

func TestInstantiateNewEmptyClient(t *testing.T) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	client, err := New(storagePath, irmaConfigurationPath, eudiAppDataPath, &testhelpers.TestClientHandler{}, nil, test.NewSigner(t), aesKey, "en")
	require.NoError(t, err)
	defer client.Close()

	credentials, err := client.GetCredentials()
	require.NoError(t, err)
	require.Empty(t, credentials)

	client.GetIrmaConfiguration()
}

func TestInstantiateClientWithExistingIrmaStorage(t *testing.T) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.SetupTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	client, err := New(storagePath, irmaConfigurationPath, eudiAppDataPath, &testhelpers.TestClientHandler{}, nil, test.NewSigner(t), aesKey, "en")
	require.NoError(t, err)
	defer client.Close()

	credentials, err := client.GetCredentials()
	require.NoError(t, err)
	require.NotEmpty(t, credentials)

	client.GetIrmaConfiguration()
}

// TestDeveloperModeSurvivesRestart covers the case where the preference is
// already enabled when the client starts: New then never passes through
// SetPreferences, so before the fix the wallet came back up production-strict.
func TestDeveloperModeSurvivesRestart(t *testing.T) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	newClient := func() *Client {
		c, err := New(storagePath, irmaConfigurationPath, eudiAppDataPath, &testhelpers.TestClientHandler{}, nil, test.NewSigner(t), aesKey, "en")
		require.NoError(t, err)
		return c
	}

	// First run: production-strict until developer mode is switched on.
	first := newClient()
	requireDeveloperModeApplied(t, first, false)
	first.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	requireDeveloperModeApplied(t, first, true)
	require.NoError(t, first.Close())

	// Restart on the same storage. The preference is persisted, so the
	// relaxations have to be back without anyone toggling the switch again.
	second := newClient()
	defer second.Close()
	require.True(t, second.GetPreferences().DeveloperMode)
	requireDeveloperModeApplied(t, second, true)
}

// requireDeveloperModeApplied asserts each of the relaxations developer mode
// makes, as observed from outside the client.
func requireDeveloperModeApplied(t *testing.T, client *Client, applied bool) {
	t.Helper()

	expectedMode := eudi.StrictCertificateVerification
	if applied {
		expectedMode = eudi.DeveloperModeCertificateVerification
	}
	conf := client.openid4vpClient.Configuration
	require.Equal(t, expectedMode, conf.Issuers.GetCertificateVerificationMode())
	require.Equal(t, expectedMode, conf.Verifiers.GetCertificateVerificationMode())
	require.Equal(t, applied, conf.UsesStagingTrustAnchors())

	require.Equal(t, applied, client.didValidator.AllowsInsecureDidWeb())

	// A plain-HTTP credential issuer is only accepted once the OpenID4VCI
	// client has been told to allow insecure HTTP.
	_, err := client.openid4vciClient.ParseAndValidateCredentialOffer(
		`{"credential_issuer":"http://localhost:8080","credential_configuration_ids":["test-credential"]}`,
	)
	if applied {
		require.NoError(t, err)
	} else {
		require.ErrorContains(t, err, "is not HTTPS")
	}
}
