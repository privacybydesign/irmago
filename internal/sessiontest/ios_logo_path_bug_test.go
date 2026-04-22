package sessiontest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// iOS moves all data to a different directory after every new app version.
// Logs used to have a static file path that became invalid after every update.
// These tests proof that this is no longer a problem.
func Test_iOSLogoPathBug(t *testing.T) {
	t.Run("irma_issuance_log_logo_path", test_iOSLogoPathBug)
	t.Run("openid4vp_disclosure_log_logo_path", test_iOSLogoPathBugEudiLogs)
}

func test_iOSLogoPathBugEudiLogs(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()
	signer := test.NewSigner(t)
	storagePath, irmaConfigurationPath := createClientStorage(t)
	eudiAppDataPath := filepath.Join(storagePath, "eudi")
	c, handler, sessionHandler := createClientWithStorageAndSigner(t, storagePath, irmaConfigurationPath, eudiAppDataPath, signer)
	keyshareEnrollClient(t, c, handler)

	issueWithPinToClient(t, c, sessionHandler, irmaServer)
	discloseOverOpenID4VP(t, c, sessionHandler, testdata.OpenID4VP_DirectPost_Host)

	logs, err := c.LoadNewestLogs(1)
	require.NoError(t, err)

	log := logs[0].DisclosureLog

	// make sure we have the correct OpenID4VP log
	require.Contains(t, log.Credentials[0].CredentialId, "test.test.email")
	require.Contains(t, log.Protocol, clientmodels.Protocol_OpenID4VP)

	// require the logo of the requestor to be an existing file
	require.FileExists(t, *log.Verifier.ImagePath)

	c.Close()

	// move the storage to a new path
	newStoragePath := t.TempDir()
	require.NoError(t, common.CopyDirectory(storagePath, newStoragePath))
	// delete the old one
	require.NoError(t, os.RemoveAll(storagePath))
	require.NoDirExists(t, storagePath)

	newClient, _, newClientSessionHandler := createClientWithStorageAndSigner(t, newStoragePath, irmaConfigurationPath, eudiAppDataPath, signer)

	// make sure it can still do sessions
	issueSdJwtAndIdemixToClientExpectPin(t, newClient, newClientSessionHandler, irmaServer)

	logs, err = newClient.LoadNewestLogs(2)
	require.NoError(t, err)
	require.Len(t, logs, 2)
	// need the second to last one, because that log used the previous storage
	log = logs[1].DisclosureLog

	// make sure we have the correct OpenID4VP log
	require.Contains(t, log.Credentials[0].CredentialId, "test.test.email")
	require.Contains(t, log.Protocol, clientmodels.Protocol_OpenID4VP)

	// require the logo of the requestor to be an existing file
	require.FileExists(t, *log.Verifier.ImagePath)

	newClient.Close()
}

func test_iOSLogoPathBug(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()
	signer := test.NewSigner(t)
	storagePath, irmaConfigurationPath := createClientStorage(t)
	eudiAppDataPath := filepath.Join(storagePath, "eudi")
	c, handler, sessionHandler := createClientWithStorageAndSigner(t, storagePath, irmaConfigurationPath, eudiAppDataPath, signer)
	keyshareEnrollClient(t, c, handler)

	issueWithPinToClient(t, c, sessionHandler, irmaServer)

	logs, err := c.LoadNewestLogs(1)
	require.NoError(t, err)

	log := logs[0].IssuanceLog

	// make sure we have the correct log
	require.Contains(t, log.Credentials[0].CredentialId, "test.test.email")
	require.Contains(t, log.Credentials[0].Formats, clientmodels.Format_Idemix)
	require.Contains(t, log.Credentials[0].Formats, clientmodels.Format_SdJwtVc)

	// require the logo of the requestor to be an existing file
	require.FileExists(t, *log.Issuer.ImagePath)

	c.Close()

	// move the storage to a new path
	newStoragePath := t.TempDir()
	require.NoError(t, common.CopyDirectory(storagePath, newStoragePath))
	// delete the old one
	require.NoError(t, os.RemoveAll(storagePath))
	require.NoDirExists(t, storagePath)

	newClient, _, newClientSessionHandler := createClientWithStorageAndSigner(t, newStoragePath, irmaConfigurationPath, eudiAppDataPath, signer)

	// make sure it can still do sessions
	issueSdJwtAndIdemixToClientExpectPin(t, newClient, newClientSessionHandler, irmaServer)

	logs, err = newClient.LoadNewestLogs(2)
	require.NoError(t, err)
	require.Len(t, logs, 2)
	// need the second to last one, because that log used the previous storage
	log = logs[1].IssuanceLog

	require.Contains(t, log.Credentials[0].CredentialId, "test.test.email")
	require.Contains(t, log.Credentials[0].Formats, clientmodels.Format_Idemix)
	require.Contains(t, log.Credentials[0].Formats, clientmodels.Format_SdJwtVc)

	// require the logo of the requestor to be an existing file
	require.FileExists(t, *log.Issuer.ImagePath)

	newClient.Close()
}

// issueWithPinToClient issues a test.test.email credential via IRMA,
// handling the full session flow including pin entry.
func issueWithPinToClient(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	t.Helper()
	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email")))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	// Depending on the keyshare server state, the session may ask for a pin or succeed directly.
	if session.Status == clientmodels.Status_RequestPin {
		userInteraction(t, c, clientmodels.SessionUserInteraction{
			SessionId: session.Id,
			Type:      clientmodels.UI_EnteredPin,
			Payload:   clientmodels.PinInteractionPayload{Pin: "12345", Proceed: true},
		})
		session = awaitSessionState(t, sessionHandler)
	}
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

func issueSdJwtAndIdemixToClientExpectPin(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email")))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPin, session.Status)

	userInteraction(t, c, clientmodels.SessionUserInteraction{
		SessionId: session.Id,
		Type:      clientmodels.UI_EnteredPin,
		Payload:   clientmodels.PinInteractionPayload{Pin: "12345", Proceed: true},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

func createClientStorage(t *testing.T) (storagePath string, irmaConfigurationPath string) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath = filepath.Join(storageFolder, "client")

	// Copy files to storage folder
	require.NoError(t, common.CopyDirectory(filepath.Join(path, "irma_configuration"), filepath.Join(storagePath, "irma_configuration")))
	require.NoError(t, common.CopyDirectory(filepath.Join(path, "eudi_configuration"), filepath.Join(storagePath, "eudi")))

	// Add test issuer certificates as trusted chain (encrypted, since the
	// EUDI filesystem storage decrypts files on read).
	encMiddleware := encryption.NewAESEncryptionMiddleware(aesKey)

	issuerCertsPath := filepath.Join(storagePath, "eudi", "issuers", "certificates")
	require.NoError(t, common.EnsureDirectoryExists(issuerCertsPath))
	encIssuer, err := encMiddleware.Encrypt(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	require.NoError(t, err)
	require.NoError(t, common.SaveFile(filepath.Join(issuerCertsPath, "issuer_cert_openid4vc_staging_yivi_app.pem"), encIssuer))

	// Add test verifier CA certificate as trusted chain.
	verifierCertsPath := filepath.Join(storagePath, "eudi", "verifiers", "certificates")
	require.NoError(t, common.EnsureDirectoryExists(verifierCertsPath))
	encVerifierCA, err := encMiddleware.Encrypt(testdata.VerifierCACertBytes)
	require.NoError(t, err)
	require.NoError(t, common.SaveFile(filepath.Join(verifierCertsPath, "ca.pem"), encVerifierCA))

	return storagePath, filepath.Join(path, "irma_configuration")
}

func keyshareEnrollClient(t *testing.T, c *client.Client, handler *irmaclient.MockClientHandler) {
	c.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	c.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")

	require.NoError(t, handler.AwaitEnrollmentResult())
}

func createClientWithStorageAndSigner(
	t *testing.T,
	storagePath,
	irmaConfigurationPath string,
	eudiAppDataPath string,
	signer irmaclient.Signer,
) (*client.Client, *irmaclient.MockClientHandler, *MockSessionHandler) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	clientHandler := irmaclient.NewMockClientHandler()
	sessionHandler := &MockSessionHandler{
		SessionChan: make(chan clientmodels.SessionState, 10),
	}
	c, err := client.New(storagePath, irmaConfigurationPath, eudiAppDataPath, clientHandler, sessionHandler, signer, aesKey)
	require.NoError(t, err)

	return c, clientHandler, sessionHandler
}
