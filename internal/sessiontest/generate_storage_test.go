package sessiontest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// TestGenerateClientStorageForRegressionTests generates a client storage database that can be used
// as a fixture for regression tests. It performs several issuance and disclosure sessions (both
// IRMA and OpenID4VP) so the resulting database contains credentials, logs, and signatures.
//
// The database is written to testdata/storage_regression/.
// Set the GENERATE_STORAGE environment variable to any value to run this test.
//
// Usage:
//
//	GENERATE_STORAGE=1 go test -run TestGenerateClientStorageForRegressionTests -count=1 ./internal/sessiontest/
func TestGenerateClientStorageForRegressionTests(t *testing.T) {
	if os.Getenv("GENERATE_STORAGE") == "" {
		t.Skip("GENERATE_STORAGE not set, skipping storage generation")
	}
	outputDir := filepath.Join(test.FindTestdataFolder(t), storageRegressionFixtureDir)

	// Start infrastructure
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServerWithDB(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client, storagePath := createClientWithStoragePath(t)

	// 1. Issue idemix-only credential (MijnOverheid.fullName)
	performIrmaIssuanceSession(t, client, irmaServer, createMijnOverheidIssuanceRequest())

	// 2. Issue combined idemix + sd-jwt credential (test.test.email)
	performIrmaIssuanceSession(t, client, irmaServer, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	// 3. Issue singleton credential
	performIrmaIssuanceSession(t, client, irmaServer, &irma.IssuanceRequest{
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{LDContext: irma.LDContextIssuanceRequest},
		},
		Credentials: []*irma.CredentialRequest{
			{
				CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.singleton"),
				Attributes: map[string]string{
					"BSN": "12345",
				},
			},
		},
	})

	// Verify credentials are present
	credentialInfoList := client.CredentialInfoList()
	t.Logf("Credentials after issuance: %d", len(credentialInfoList))
	for _, cred := range credentialInfoList {
		t.Logf("  - %s (format: %s, hash: %s)", cred.Identifier(), cred.CredentialFormat, cred.Hash)
	}

	// 4. Perform IRMA disclosure session
	performIrmaDisclosureSession(t, client, irmaServer)

	// 5. Perform IRMA signature session
	performIrmaSignatureSession(t, client, irmaServer)

	// 6. Perform OpenID4VP disclosure sessions (direct_post and direct_post.jwt)
	discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPost_Host)
	discloseOverOpenID4VP(t, client, testdata.OpenID4VP_DirectPostJwt_Host)

	// Log final state
	logs, err := client.LoadNewestLogs(100)
	require.NoError(t, err)
	t.Logf("Total log entries: %d", len(logs))
	for _, log := range logs {
		t.Logf("  - type=%s", log.Type)
	}

	credentialInfoList = client.CredentialInfoList()
	t.Logf("Final credentials: %d", len(credentialInfoList))
	for _, cred := range credentialInfoList {
		t.Logf("  - %s (format: %s, hash: %s)", cred.Identifier(), cred.CredentialFormat, cred.Hash)
	}

	// Close client to flush database
	require.NoError(t, client.Close())

	// Copy the storage to a versioned subdirectory
	versionDir := filepath.Join(outputDir, "v"+irma.Version)
	require.NoError(t, common.EnsureDirectoryExists(versionDir))

	copyFile(t, filepath.Join(storagePath, "db2"), filepath.Join(versionDir, "bbolt_client_db"))
	copyFile(t, filepath.Join(storagePath, "ecdsa_sk.pem"), filepath.Join(versionDir, "ecdsa_sk.pem"))

	// Save the keyshare server's user database so the regression test can
	// start a keyshare server that recognizes the enrolled user.
	keyshareUsers := keyshareServer.DB.DumpUsers()
	keyshareUsersBts, err := json.Marshal(keyshareUsers)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "keyshare_users.json"), keyshareUsersBts, 0644))

	metadata := map[string]any{
		"description": "Client storage generated for regression testing",
		"credentials": credentialInfoList,
		"logs":        logs,
		"aes_key":     "asdfasdfasdfasdfasdfasdfasdfasdf",
	}
	metadataBts, err := json.MarshalIndent(metadata, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "metadata.json"), metadataBts, 0644))

	fmt.Printf("Storage written to %s\n", versionDir)
}

func createClientWithStoragePath(t *testing.T) (*irmaclient.Client, string) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(storagePath, "irma_configuration")

	require.NoError(t, common.CopyDirectory(filepath.Join(path, "irma_configuration"), filepath.Join(storagePath, "irma_configuration")))
	require.NoError(t, common.CopyDirectory(filepath.Join(path, "eudi_configuration"), filepath.Join(storagePath, "eudi_configuration")))

	certsPath := filepath.Join(storagePath, "eudi_configuration", "issuers", "certs")
	require.NoError(t, common.EnsureDirectoryExists(certsPath))
	require.NoError(t, common.SaveFile(filepath.Join(certsPath, "issuer_cert_openid4vc_staging_yivi_app.pem"), testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes))

	// Generate signer key and persist it so the regression test can reload it
	privateKey, err := signed.GenerateKey()
	require.NoError(t, err)
	pemBts, err := signed.MarshalPemPrivateKey(privateKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(storagePath, "ecdsa_sk.pem"), pemBts, 0644))
	signer := test.LoadSigner(t, privateKey)

	clientHandler := irmaclient.NewMockClientHandler()
	client, err := irmaclient.New(storagePath, irmaConfigurationPath, clientHandler, signer, aesKey)
	require.NoError(t, err)

	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, clientHandler.AwaitEnrollmentResult())

	return client, storagePath
}

func copyFile(t *testing.T, src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		t.Logf("Warning: could not read %s: %v", src, err)
		return
	}
	require.NoError(t, os.WriteFile(dst, data, 0644))
	t.Logf("Copied %s -> %s (%d bytes)", src, dst, len(data))
}
