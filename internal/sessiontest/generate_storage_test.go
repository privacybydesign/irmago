package sessiontest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/gabi/signed"
	rootpkg "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// TestGenerateClientStorageForRegressionTests regenerates the storage regression
// fixture for the current version (testdata/storage_regression/v<Version>/), used
// by TestClientStorageRegression. Run with GENERATE_STORAGE set:
//
//	GENERATE_STORAGE=1 go test -run TestGenerateClientStorageForRegressionTests -count=1 ./internal/sessiontest/
//
// Sessions performed:
//   - IRMA issuance: irma-demo.MijnOverheid.fullName (idemix), test.test.email
//     (idemix + 10 SD-JWTs), irma-demo.MijnOverheid.singleton, irma-demo.RU.studentCard.
//   - OpenID4VCI issuance: 3x TestCredentialSdJwt (vct https://localhost:8443/vct/test) and
//     1x OrganizationCredentialSdJwt (vct https://localhost:8443/vct/organization, deeply nested).
//   - IRMA disclosures: test.test.email; irma-demo.MijnOverheid.fullName (x2); and one spanning
//     irma-demo.MijnOverheid.fullName + irma-demo.MijnOverheid.singleton + irma-demo.RU.studentCard.
//   - IRMA signature.
//   - OpenID4VP disclosures: test.test.email (x2, served from bbolt) plus
//     https://localhost:8443/vct/test and https://localhost:8443/vct/organization
//     (served from the EUDI DB, via the veramo verifier).
//   - Removals, as the final actions: irma-demo.RU.studentCard + 2 spare https://localhost:8443/vct/test.
//
// Resulting database state:
//   - bbolt (bbolt_client_db): irma-demo.MijnOverheid.fullName, irma-demo.MijnOverheid.singleton
//     and test.test.email; the test.test.email SD-JWT retains 8 of 10 instances (2 consumed by
//     OpenID4VP disclosure); irma-demo.RU.studentCard removed.
//   - EUDI sqlcipher (eudi_client_db): one https://localhost:8443/vct/test and one
//     https://localhost:8443/vct/organization batch remaining.
//   - Activity logs (merged from both stores): all four types — issuance, disclosure, signature,
//     removal — returned newest-first, ending with the three removals.
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

	c, storagePath, sessionHandler := createClientWithStoragePath(t)

	// 1. Issue idemix-only credential (MijnOverheid.fullName)
	issue(t, irmaServer, c, sessionHandler, 1, createMijnOverheidIssuanceRequest())
	awaitSessionState(t, sessionHandler)

	// 2. Issue combined idemix + sd-jwt credential (test.test.email)
	issue(t, irmaServer, c, sessionHandler, 2, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	awaitSessionState(t, sessionHandler)

	// 3. Issue singleton credential
	issue(t, irmaServer, c, sessionHandler, 3, &irma.IssuanceRequest{
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
	awaitSessionState(t, sessionHandler)

	// 3b. Issue an OpenID4VCI SD-JWT credential so the EUDI (sqlcipher) DB is
	// populated. IRMA-issued SD-JWTs go to bbolt; only OpenID4VCI issuance
	// writes the EUDI credential store.
	issueCredentialViaOpenID4VCI(t, c, 8, sessionHandler, "TestCredentialSdJwt",
		`{"given_name": "Test", "family_name": "User", "email": "test@example.com"}`)

	// 3c. Issue an idemix-only student card (another credential type).
	issue(t, irmaServer, c, sessionHandler, 9, createStudentCardIssuanceRequest())
	awaitSessionState(t, sessionHandler)

	// 3d. Issue two more OpenID4VCI credentials (more EUDI data, and spare
	// credentials to remove later for the removal-ordering assertion).
	issueCredentialViaOpenID4VCI(t, c, 10, sessionHandler, "TestCredentialSdJwt",
		`{"given_name": "Alice", "family_name": "Example", "email": "alice@example.com"}`)
	issueCredentialViaOpenID4VCI(t, c, 12, sessionHandler, "TestCredentialSdJwt",
		`{"given_name": "Bob", "family_name": "Example", "email": "bob@example.com"}`)

	// 3e. Issue an OpenID4VCI credential with deeply nested attributes
	// (organizational credential: university -> faculties -> departments -> courses).
	issueCredentialViaOpenID4VCI(t, c, 16, sessionHandler, "OrganizationCredentialSdJwt", organizationClaimsJSON)

	// Verify credentials are present
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	t.Logf("Credentials after issuance: %d", len(creds))
	for _, cred := range creds {
		t.Logf("  - %s", cred.CredentialId)
	}

	// 4. Perform IRMA disclosure session
	performIrmaDisclosureSession(t, c, 4, sessionHandler, irmaServer)

	// 5. Perform IRMA signature session
	performIrmaSignatureSession(t, c, 5, sessionHandler, irmaServer)

	// 6. Perform OpenID4VP disclosure sessions (direct_post and direct_post.jwt)
	discloseOverOpenID4VP(t, c, 6, sessionHandler, testdata.OpenID4VP_DirectPost_Host)
	discloseOverOpenID4VP(t, c, 7, sessionHandler, testdata.OpenID4VP_DirectPostJwt_Host)

	// 7b-7c. A few more IRMA disclosures (idemix, non-keyshare) so the log has
	// several disclosure entries to assert ordering against.
	performDisclosureSessionForAttribute(t, c, 11, sessionHandler, irmaServer, "irma-demo.MijnOverheid.fullName.familyname")
	performDisclosureSessionForAttribute(t, c, 13, sessionHandler, irmaServer, "irma-demo.MijnOverheid.fullName.firstnames")

	// 7d. A single disclosure session spanning multiple credential types
	// (fullName + singleton + studentCard) so the fixture exercises a
	// multi-credential disclosure. Each credential is its own conjunction
	// (IRMA disallows multiple non-singletons in one inner conjunction).
	multiReq := irma.NewDisclosureRequest()
	multiReq.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{irma.AttributeCon{irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname")}},
		irma.AttributeDisCon{irma.AttributeCon{irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN")}},
		irma.AttributeDisCon{irma.AttributeCon{irma.NewAttributeRequest("irma-demo.RU.studentCard.university")}},
	}
	c.NewSession(14, startSameDeviceIrmaSessionAtServer(t, irmaServer, multiReq))
	multiSession := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, multiSession.Status)
	var multiChoices []clientmodels.DisclosureDisconSelection
	for _, slot := range multiSession.DisclosurePlan.DisclosureChoicesOverview {
		multiChoices = append(multiChoices, makeDisclosureChoice(slot.OwnedOptions[0]))
	}
	grantPermission(t, c, multiSession.Id, multiChoices...)
	multiSession = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, multiSession.Status)

	// 7e. Disclose the OpenID4VCI-issued credential over OpenID4VP (via the
	// veramo verifier). This is an OpenID4VP disclosure of an EUDI credential
	// stored in the sqlcipher DB, distinct from the email SD-JWT disclosures
	// above (which are served from bbolt).
	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, `{
		"dcql": {
			"credentials": [
				{
					"id": "test-cred",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": ["https://localhost:8443/vct/test"] },
					"claims": [ { "path": ["given_name"] }, { "path": ["email"] } ]
				}
			]
		}
	}`)
	startOpenID4VPDisclosureSession(t, c, 15, veramoSession.RequestUri)
	eudiVpSession := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, eudiVpSession.Status)
	grantPermission(t, c, eudiVpSession.Id, makeDisclosureChoice(eudiVpSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]))
	eudiVpSession = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, eudiVpSession.Status)

	// 7f. Disclose the deeply nested organization credential over OpenID4VP,
	// selecting only a few specific nested claims rather than the whole tree.
	orgVeramoSession := createVeramoVerifierDcqlSessionWithQuery(t, `{
		"dcql": {
			"credentials": [
				{
					"id": "org-cred",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": ["https://localhost:8443/vct/organization"] },
					"claims": [
						{ "path": ["university", "name"] },
						{ "path": ["university", "founded"] }
					]
				}
			]
		}
	}`)
	startOpenID4VPDisclosureSession(t, c, 17, orgVeramoSession.RequestUri)
	orgVpSession := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, orgVpSession.Status)
	grantPermission(t, c, orgVpSession.Id, makeDisclosureChoice(orgVpSession.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]))
	orgVpSession = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, orgVpSession.Status)

	// 8. Remove several credentials as the final actions, so the newest activity
	// logs are an ordered run of removals. Keep the credentials the regression
	// test asserts on: fullName, singleton, email, and one OpenID4VCI credential.
	keep := map[string]bool{
		"irma-demo.MijnOverheid.fullName":         true,
		"irma-demo.MijnOverheid.singleton":        true,
		"test.test.email":                         true,
		"https://localhost:8443/vct/organization": true, // keep the deeply nested credential
	}
	creds, err = c.GetCredentials()
	require.NoError(t, err)
	removals := 0
	for _, cred := range creds {
		if keep[cred.CredentialId] {
			continue
		}
		// Keep the canonical OpenID4VCI test credential (given_name "Test") so
		// the fixture is deterministic; remove the Alice/Bob spares and the
		// student card (3 removals in total).
		if cred.CredentialId == "https://localhost:8443/vct/test" && credentialAttrValue(cred, "given_name") == "Test" {
			continue
		}
		require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))
		removals++
	}
	require.Equal(t, 3, removals, "expected exactly 3 credential removals")

	// Log final state
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	t.Logf("Total log entries: %d", len(logs))
	for _, log := range logs {
		t.Logf("  - type=%s", log.Type)
	}

	creds, err = c.GetCredentials()
	require.NoError(t, err)
	t.Logf("Final credentials: %d", len(creds))
	for _, cred := range creds {
		t.Logf("  - %s", cred.CredentialId)
	}

	// Close client to flush database
	require.NoError(t, c.Close())

	// Copy the storage to a versioned subdirectory
	versionDir := filepath.Join(outputDir, "v"+rootpkg.Version)
	require.NoError(t, common.EnsureDirectoryExists(versionDir))

	copyFile(t, filepath.Join(storagePath, "db2"), filepath.Join(versionDir, "bbolt_client_db"))
	copyFile(t, filepath.Join(storagePath, "eudi", storage.DbFilename), filepath.Join(versionDir, "eudi_client_db"))
	copyFile(t, filepath.Join(storagePath, "ecdsa_sk.pem"), filepath.Join(versionDir, "ecdsa_sk.pem"))

	// Save the keyshare server's user database so the regression test can
	// start a keyshare server that recognizes the enrolled user.
	keyshareUsers := keyshareServer.DB.DumpUsers()
	keyshareUsersBts, err := json.Marshal(keyshareUsers)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "keyshare_users.json"), keyshareUsersBts, 0644))

	metadata := map[string]any{
		"description": "Client storage generated for regression testing",
		"credentials": creds,
		"logs":        logs,
		"aes_key":     "asdfasdfasdfasdfasdfasdfasdfasdf",
	}
	metadataBts, err := json.MarshalIndent(metadata, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(versionDir, "metadata.json"), metadataBts, 0644))

	fmt.Printf("Storage written to %s\n", versionDir)
}

func createClientWithStoragePath(t *testing.T) (*client.Client, string, *MockSessionHandler) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(storagePath, "irma_configuration")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	require.NoError(t, common.CopyDirectory(filepath.Join(path, "irma_configuration"), filepath.Join(storagePath, "irma_configuration")))
	require.NoError(t, common.EnsureDirectoryExists(eudiAppDataPath))

	// Install issuer + verifier trust anchors (encrypted, matching how the
	// regression reader loads them) so OpenID4VCI issuance and OpenID4VP
	// disclosure can verify the issuer/relying-party certificate chains.
	encMiddleware := encryption.NewAESEncryptionMiddleware(aesKey)

	issuerCertsPath := filepath.Join(storagePath, "eudi", "issuers", "certificates")
	require.NoError(t, common.EnsureDirectoryExists(issuerCertsPath))
	encIssuer, err := encMiddleware.Encrypt(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
	require.NoError(t, err)
	require.NoError(t, common.SaveFile(filepath.Join(issuerCertsPath, "issuer_cert_openid4vc_staging_yivi_app.pem"), encIssuer))

	verifierCertsPath := filepath.Join(storagePath, "eudi", "verifiers", "certificates")
	require.NoError(t, common.EnsureDirectoryExists(verifierCertsPath))
	encVerifierCA, err := encMiddleware.Encrypt(testdata.VerifierCACertBytes)
	require.NoError(t, err)
	require.NoError(t, common.SaveFile(filepath.Join(verifierCertsPath, "ca.pem"), encVerifierCA))

	// Generate signer key and persist it so the regression test can reload it
	privateKey, err := signed.GenerateKey()
	require.NoError(t, err)
	pemBts, err := signed.MarshalPemPrivateKey(privateKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(storagePath, "ecdsa_sk.pem"), pemBts, 0644))
	signer := test.LoadSigner(t, privateKey)

	clientHandler := irmaclient.NewMockClientHandler()
	sessionHandler := &MockSessionHandler{
		SessionChan: make(chan clientmodels.SessionState, 10),
	}
	c, err := client.New(storagePath, irmaConfigurationPath, eudiAppDataPath, clientHandler, sessionHandler, signer, aesKey, "en")
	require.NoError(t, err)

	c.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	c.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")
	require.NoError(t, clientHandler.AwaitEnrollmentResult())

	return c, storagePath, sessionHandler
}

// credentialAttrValue returns the string value of a top-level attribute, or ""
// if absent. Used to pick a specific credential among same-typed ones.
func credentialAttrValue(cred *clientmodels.Credential, key string) string {
	for _, a := range cred.Attributes {
		if len(a.ClaimPath) == 1 && a.ClaimPath[0] == key && a.Value != nil && a.Value.String != nil {
			return *a.Value.String
		}
	}
	return ""
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
