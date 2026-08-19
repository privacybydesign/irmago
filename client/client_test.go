package client

import (
	"crypto/x509"
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
	newClient := newClientOnFreshStorage(t)

	// First run: production-strict until developer mode is switched on.
	first := newClient()
	requireDeveloperModeApplied(t, first, false)
	productionRoots := issuerRoots(first)
	first.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	requireDeveloperModeApplied(t, first, true)
	developerRoots := issuerRoots(first)
	require.False(t, productionRoots.Equal(developerRoots),
		"switching developer mode on should add the staging trust anchors")
	require.NoError(t, first.Close())

	// Restart on the same storage. The preference is persisted, so the
	// relaxations have to be back without anyone toggling the switch again.
	second := newClient()
	defer second.Close()
	require.True(t, second.GetPreferences().DeveloperMode)
	requireDeveloperModeApplied(t, second, true)
	require.True(t, developerRoots.Equal(issuerRoots(second)),
		"the restarted client should come back up with the staging trust anchors loaded, not just the flag set")
}

// TestDeveloperModeSwitchedOffRevertsRelaxations covers the other direction:
// every relaxation has to be undone the moment the preference is switched off,
// instead of staying active until the process restarts.
func TestDeveloperModeSwitchedOffRevertsRelaxations(t *testing.T) {
	client := newClientOnFreshStorage(t)()
	defer client.Close()

	productionRoots := issuerRoots(client)

	client.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	requireDeveloperModeApplied(t, client, true)
	require.False(t, productionRoots.Equal(issuerRoots(client)),
		"switching developer mode on should add the staging trust anchors")

	client.SetPreferences(clientsettings.Preferences{DeveloperMode: false})
	requireDeveloperModeApplied(t, client, false)
	require.True(t, productionRoots.Equal(issuerRoots(client)),
		"switching developer mode off should drop the staging trust anchors")
}

// newClientOnFreshStorage returns a factory that opens a client on one empty
// storage folder, so calling it twice models a restart of the same wallet.
func newClientOnFreshStorage(t *testing.T) func() *Client {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	return func() *Client {
		c, err := New(storagePath, irmaConfigurationPath, eudiAppDataPath, &testhelpers.TestClientHandler{}, nil, test.NewSigner(t), aesKey, "en")
		require.NoError(t, err)
		return c
	}
}

// issuerRoots returns the issuer trust anchors the client validates against.
// Configuration.Reload builds this pool, and reads the staging preference while
// doing so, so unlike the developer mode flags it can only hold the staging
// anchors if the preference was applied before that Reload ran.
func issuerRoots(client *Client) *x509.CertPool {
	return client.openid4vpClient.Configuration.Issuers.GetVerificationOptionsTemplate().Roots
}

// requireDeveloperModeApplied asserts each of the relaxations developer mode
// makes, as observed from outside the client. Every one of them is set by a
// plain setter on both sides of the Reload in New, so these assertions cannot
// witness that ordering on their own; compare issuerRoots for that.
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
