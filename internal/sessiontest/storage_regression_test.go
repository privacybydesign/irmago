package sessiontest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"image"
	_ "image/png" // register PNG decoder for requireValidImage
	"os"
	"path/filepath"
	"testing"

	"github.com/privacybydesign/gabi/signed"
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
	"github.com/privacybydesign/irmago/irma/server/keyshare/keyshareserver" // for MemoryDB
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// TestClientStorageRegressionV1_0_0 validates the first snapshot with the EUDI
// SQLCipher store: OpenID4VCI credentials (including a deeply nested organizational
// one), a multi-credential disclosure, OpenID4VP disclosures of EUDI credentials,
// and a trailing run of credential removals.
func TestClientStorageRegressionV1_0_0(t *testing.T) {
	c, sessionHandler, irmaServer := setupStorageRegressionClient(t, "v1.0.0")

	creds, err := c.GetCredentials()
	require.NoError(t, err)
	requireCredentialPresent(t, creds, "irma-demo.MijnOverheid.fullName")
	requireCredentialPresent(t, creds, "irma-demo.MijnOverheid.singleton")
	requireCredentialPresent(t, creds, "test.test.email")
	requireSdJwtInstancesRemaining(t, creds, "test.test.email", 8)

	// IRMA credentials: logos present + valid, attribute names and values correct.
	fullName := findCredentialById(creds, "irma-demo.MijnOverheid.fullName")
	require.NotNil(t, fullName)
	requireValidImage(t, fullName.Image, "fullName credential")
	requireValidImage(t, fullName.Issuer.Image, "fullName issuer")
	requireAttrsInOrder(t, fullName.Attributes,
		expectedAttr{Path: []any{"firstnames"}, DisplayName: &clientmodels.TranslatedString{"en": "First names"}, Value: strVal("Barry")},
		expectedAttr{Path: []any{"firstname"}, DisplayName: &clientmodels.TranslatedString{"en": "First name"}, Value: strVal("Bar")},
		expectedAttr{Path: []any{"familyname"}, DisplayName: &clientmodels.TranslatedString{"en": "Family name"}, Value: strVal("Batsbak")},
		expectedAttr{Path: []any{"prefix"}, DisplayName: &clientmodels.TranslatedString{"en": "Prefix"}, Value: strVal("Sir")},
	)

	singleton := findCredentialById(creds, "irma-demo.MijnOverheid.singleton")
	require.NotNil(t, singleton)
	requireAttrsInOrder(t, singleton.Attributes,
		expectedAttr{Path: []any{"BSN"}, DisplayName: &clientmodels.TranslatedString{"en": "BSN"}, Value: strVal("12345")},
	)

	email := findCredentialById(creds, "test.test.email")
	require.NotNil(t, email)
	requireValidImage(t, email.Image, "email credential")
	requireValidImage(t, email.Issuer.Image, "email issuer")
	requireAttrsInOrder(t, email.Attributes,
		expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address"}, Value: strVal("test@gmail.com")},
	)

	// OpenID4VCI credential from the EUDI DB: attribute names and values correct.
	// (EUDI issuer logos live in the eudi filesystem, which isn't part of the DB
	// snapshot, so no image is expected here.)
	testCred := findCredentialByName(t, creds, "en", "Test Credential (SD-JWT)")
	require.NotNil(t, testCred, "expected OpenID4VCI credential from the EUDI DB")
	requireEudiCredentialMeta(t, testCred)
	requireAttrsInOrder(t, testCred.Attributes,
		expectedAttr{Path: []any{"given_name"}, DisplayName: &clientmodels.TranslatedString{"en": "Given Name"}, Value: strVal("Test")},
		expectedAttr{Path: []any{"family_name"}, DisplayName: &clientmodels.TranslatedString{"en": "Family Name"}, Value: strVal("User")},
		expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email"}, Value: strVal("test@example.com")},
	)

	// The deeply nested organization credential loads with every nested attribute
	// name and value intact.
	org := findCredentialById(creds, "https://localhost:8443/vct/organization")
	require.NotNil(t, org, "expected deeply nested organization credential")
	requireEudiCredentialMeta(t, org)
	requireAttrsInOrder(t, org.Attributes, expectedOrganizationAttrs()...)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 21)
	requireLogTypePresent(t, logs, clientmodels.LogType_Issuance)
	requireLogTypePresent(t, logs, clientmodels.LogType_Disclosure)
	requireLogTypePresent(t, logs, clientmodels.LogType_Signature)
	requireLogTypePresent(t, logs, clientmodels.LogType_CredentialRemoval)
	assertLogsNewestFirst(t, logs)
	require.Equal(t, 4, countDisclosures(logs, clientmodels.Protocol_OpenID4VP))
	require.Equal(t, 4, countDisclosures(logs, clientmodels.Protocol_Irma))

	// The three credential removals were the final generator actions, so they are
	// the newest log entries.
	for i := 0; i < 3; i++ {
		require.Equal(t, clientmodels.LogType_CredentialRemoval, logs[i].Type,
			"expected the 3 newest logs to be credential removals")
	}

	// Log content: the multi-credential disclosure discloses the expected
	// credentials and attribute values.
	var multiDisc *clientmodels.DisclosureLog
	for _, log := range logs {
		if log.Type == clientmodels.LogType_Disclosure && log.DisclosureLog != nil && len(log.DisclosureLog.Credentials) > 1 {
			multiDisc = log.DisclosureLog
			break
		}
	}
	require.NotNil(t, multiDisc, "expected a disclosure log spanning multiple credentials")
	require.Equal(t, clientmodels.Protocol_Irma, multiDisc.Protocol)
	require.Len(t, multiDisc.Credentials, 3)
	discByID := map[string]clientmodels.LogCredential{}
	for _, lc := range multiDisc.Credentials {
		discByID[lc.CredentialId] = lc
	}
	requireValidImage(t, discByID["irma-demo.MijnOverheid.fullName"].Image, "disclosure log fullName")
	requireAttrsInOrder(t, discByID["irma-demo.MijnOverheid.fullName"].Attributes,
		expectedAttr{Path: []any{"familyname"}, DisplayName: &clientmodels.TranslatedString{"en": "Family name"}, Value: strVal("Batsbak")})
	requireValidImage(t, discByID["irma-demo.MijnOverheid.singleton"].Image, "disclosure log singleton")
	requireAttrsInOrder(t, discByID["irma-demo.MijnOverheid.singleton"].Attributes,
		expectedAttr{Path: []any{"BSN"}, DisplayName: &clientmodels.TranslatedString{"en": "BSN"}, Value: strVal("12345")})
	requireValidImage(t, discByID["irma-demo.RU.studentCard"].Image, "disclosure log studentCard")
	requireAttrsInOrder(t, discByID["irma-demo.RU.studentCard"].Attributes,
		expectedAttr{Path: []any{"university"}, DisplayName: &clientmodels.TranslatedString{"en": "University"}, Value: strVal("University of the Arts")})

	// The signature log records the signed message, the disclosed attribute, and
	// a valid credential image.
	sig := findLog(logs, clientmodels.LogType_Signature)
	require.NotNil(t, sig)
	require.NotNil(t, sig.SignedMessageLog)
	require.Equal(t, "Hello, World!", sig.SignedMessageLog.Message)
	require.Len(t, sig.SignedMessageLog.Credentials, 1)
	require.Equal(t, "test.test.email", sig.SignedMessageLog.Credentials[0].CredentialId)
	requireValidImage(t, sig.SignedMessageLog.Credentials[0].Image, "signature log email")
	requireAttrsInOrder(t, sig.SignedMessageLog.Credentials[0].Attributes,
		expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address"}, Value: strVal("test@gmail.com")})

	// The removal logs reference exactly the removed credentials.
	removed := map[string]int{}
	for _, log := range logs {
		if log.Type == clientmodels.LogType_CredentialRemoval {
			require.NotNil(t, log.RemovalLog)
			require.Len(t, log.RemovalLog.Credentials, 1)
			removed[log.RemovalLog.Credentials[0].CredentialId]++
		}
	}
	require.Equal(t, map[string]int{
		"https://localhost:8443/vct/test": 2,
		"irma-demo.RU.studentCard":        1,
	}, removed)

	assertLoadedClientUsable(t, c, sessionHandler, irmaServer)
}

// TestClientStorageRegressionV0_19_2 validates a snapshot from before the EUDI
// SQLCipher store existed: bbolt only, no OpenID4VCI credentials, no removals.
func TestClientStorageRegressionV0_19_2(t *testing.T) {
	c, sessionHandler, irmaServer := setupStorageRegressionClient(t, "v0.19.2")

	creds, err := c.GetCredentials()
	require.NoError(t, err)
	requireCredentialPresent(t, creds, "irma-demo.MijnOverheid.fullName")
	requireCredentialPresent(t, creds, "irma-demo.MijnOverheid.singleton")
	requireCredentialPresent(t, creds, "test.test.email")
	requireSdJwtInstancesRemaining(t, creds, "test.test.email", 8)

	// Credential + issuer logos are present and valid, and attribute names and
	// values are correct.
	fullName := findCredentialById(creds, "irma-demo.MijnOverheid.fullName")
	require.NotNil(t, fullName)
	requireValidImage(t, fullName.Image, "fullName credential")
	requireValidImage(t, fullName.Issuer.Image, "fullName issuer")
	requireAttrsInOrder(t, fullName.Attributes,
		expectedAttr{Path: []any{"firstnames"}, DisplayName: &clientmodels.TranslatedString{"en": "First names"}, Value: strVal("Barry")},
		expectedAttr{Path: []any{"firstname"}, DisplayName: &clientmodels.TranslatedString{"en": "First name"}, Value: strVal("")},
		expectedAttr{Path: []any{"familyname"}, DisplayName: &clientmodels.TranslatedString{"en": "Family name"}, Value: strVal("Batsbak")},
		expectedAttr{Path: []any{"prefix"}, DisplayName: &clientmodels.TranslatedString{"en": "Prefix"}, Value: strVal("Sir")},
	)

	singleton := findCredentialById(creds, "irma-demo.MijnOverheid.singleton")
	require.NotNil(t, singleton)
	requireAttrsInOrder(t, singleton.Attributes,
		expectedAttr{Path: []any{"BSN"}, DisplayName: &clientmodels.TranslatedString{"en": "BSN"}, Value: strVal("12345")},
	)

	email := findCredentialById(creds, "test.test.email")
	require.NotNil(t, email)
	requireValidImage(t, email.Image, "email credential")
	requireValidImage(t, email.Issuer.Image, "email issuer")
	requireAttrsInOrder(t, email.Attributes,
		expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address"}, Value: strVal("test@gmail.com")},
	)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 8)
	requireLogTypePresent(t, logs, clientmodels.LogType_Issuance)
	requireLogTypePresent(t, logs, clientmodels.LogType_Disclosure)
	requireLogTypePresent(t, logs, clientmodels.LogType_Signature)
	assertLogsNewestFirst(t, logs)
	require.Equal(t, 2, countDisclosures(logs, clientmodels.Protocol_OpenID4VP))
	require.Equal(t, 1, countDisclosures(logs, clientmodels.Protocol_Irma))

	// Log content: the signature log records the signed message and the
	// disclosed email attribute.
	sig := findLog(logs, clientmodels.LogType_Signature)
	require.NotNil(t, sig)
	require.NotNil(t, sig.SignedMessageLog)
	require.Equal(t, "Hello, World!", sig.SignedMessageLog.Message)
	require.Len(t, sig.SignedMessageLog.Credentials, 1)
	require.Equal(t, "test.test.email", sig.SignedMessageLog.Credentials[0].CredentialId)
	requireValidImage(t, sig.SignedMessageLog.Credentials[0].Image, "signature log email")
	requireAttrsInOrder(t, sig.SignedMessageLog.Credentials[0].Attributes,
		expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address"}, Value: strVal("test@gmail.com")})

	// Every disclosure log discloses the email credential's email attribute, with
	// a valid credential image.
	discCount := 0
	for _, log := range logs {
		if log.Type != clientmodels.LogType_Disclosure {
			continue
		}
		require.NotNil(t, log.DisclosureLog)
		require.Len(t, log.DisclosureLog.Credentials, 1)
		require.Equal(t, "test.test.email", log.DisclosureLog.Credentials[0].CredentialId)
		requireValidImage(t, log.DisclosureLog.Credentials[0].Image, "disclosure log email")
		requireAttrsInOrder(t, log.DisclosureLog.Credentials[0].Attributes,
			expectedAttr{Path: []any{"email"}, DisplayName: &clientmodels.TranslatedString{"en": "Email address"}, Value: strVal("test@gmail.com")})
		discCount++
	}
	require.Equal(t, 3, discCount)

	assertLoadedClientUsable(t, c, sessionHandler, irmaServer)
}

const storageRegressionFixtureDir = "storage_regression"

// The storage regression tests load client storage databases generated by older
// versions (fixtures under testdata/storage_regression/v<version>/, produced by
// TestGenerateClientStorageForRegressionTests) and verify that current code can
// still read and use them.
//
// There is one test per fixture version, because each version's snapshot contains
// a different set of credentials and logs (e.g. v0.19.2 predates the EUDI store).
// Shared setup, the version-agnostic "can the client still run sessions" check,
// and small assertion helpers live below.

// setupStorageRegressionClient starts the test infrastructure and loads the client
// from the given version's fixture. Skips when the fixture directory is absent.
func setupStorageRegressionClient(t *testing.T, version string) (*client.Client, *MockSessionHandler, *IrmaServer) {
	t.Helper()
	versionPath := filepath.Join(test.FindTestdataFolder(t), storageRegressionFixtureDir, version)
	if _, err := os.Stat(versionPath); os.IsNotExist(err) {
		t.Skipf("fixture %s not found; run TestGenerateClientStorageForRegressionTests first", versionPath)
	}

	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	t.Cleanup(func() { irmaServer.Stop() })

	keyshareServer := testkeyshare.StartKeyshareServerWithDB(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	t.Cleanup(func() { keyshareServer.Stop() })
	loadKeyshareUsersFromFixture(t, keyshareServer.DB, versionPath)

	c, sessionHandler := loadClientFromFixture(t, filepath.Join(versionPath, "bbolt_client_db"))
	t.Cleanup(func() { _ = c.Close() })
	return c, sessionHandler, irmaServer
}

// assertLoadedClientUsable checks that a client loaded from an old fixture can
// still perform fresh sessions of every kind. This backward-compatibility check
// is version-agnostic and shared by every per-version test.
func assertLoadedClientUsable(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	t.Helper()

	// A fresh IRMA issuance into the loaded client.
	issue(t, irmaServer, c, sessionHandler, 1, createMijnOverheidIssuanceRequest())
	issued := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, issued.Status)

	// IRMA disclosures (non-keyshare + keyshare) and an OpenID4VP disclosure of an
	// IRMA-issued SD-JWT (served from bbolt).
	performDisclosureSessionForAttribute(t, c, 2, sessionHandler, irmaServer, "irma-demo.MijnOverheid.fullName.familyname")
	performKeyshareDisclosureSession(t, c, 3, sessionHandler, irmaServer, "test.test.email.email")
	discloseOverOpenID4VP(t, c, 4, sessionHandler, testdata.OpenID4VP_DirectPost_Host)

	// A fresh OpenID4VCI issuance into the loaded client (veramo issuer), then an
	// OpenID4VP disclosure of that EUDI credential (veramo verifier).
	issueCredentialViaOpenID4VCI(t, c, 5, sessionHandler, "TestCredentialSdJwt",
		`{"given_name": "Reload", "family_name": "Check", "email": "reload@example.com"}`)

	veramoSession := createVeramoVerifierDcqlSessionWithQuery(t, `{
		"dcql": {
			"credentials": [
				{
					"id": "test-cred",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": ["https://localhost:8443/vct/test"] },
					"claims": [ { "path": ["email"] } ]
				}
			]
		}
	}`)
	startOpenID4VPDisclosureSession(t, c, 6, veramoSession.RequestUri)
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	grantPermission(t, c, session.Id, makeDisclosureChoice(session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]))
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

// assertLogsNewestFirst is a universal invariant across all fixtures: LoadNewestLogs
// returns entries in non-increasing time order.
func assertLogsNewestFirst(t *testing.T, logs []clientmodels.LogInfo) {
	t.Helper()
	for i := 1; i < len(logs); i++ {
		require.False(t, logs[i-1].Time.Before(logs[i].Time),
			"logs must be ordered newest-first (entry %d is older than %d)", i-1, i)
	}
}

// countDisclosures counts disclosure logs for the given protocol.
func countDisclosures(logs []clientmodels.LogInfo, protocol clientmodels.Protocol) int {
	n := 0
	for _, log := range logs {
		if log.Type == clientmodels.LogType_Disclosure && log.DisclosureLog != nil && log.DisclosureLog.Protocol == protocol {
			n++
		}
	}
	return n
}

// requireSdJwtInstancesRemaining asserts the remaining SD-JWT batch instance count
// for a credential.
func requireSdJwtInstancesRemaining(t *testing.T, creds []*clientmodels.Credential, credID string, want uint) {
	t.Helper()
	cred := findCredentialById(creds, credID)
	require.NotNil(t, cred, "credential %s", credID)
	n := cred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc)]
	require.NotNil(t, n, "credential %s has no SD-JWT instance count", credID)
	require.Equal(t, want, *n)
}

// requireEudiCredentialMeta asserts the public metadata common to the OpenID4VCI
// (EUDI) credentials in the fixture, as surfaced by Client.GetCredentials.
func requireEudiCredentialMeta(t *testing.T, cred *clientmodels.Credential) {
	t.Helper()
	require.Equal(t, "did:web:localhost%3A8443:test-issuer:.well-known", cred.Issuer.Id)
	require.Equal(t, "Test Issuer", cred.Issuer.Name["en"])
	require.Contains(t, cred.CredentialInstanceIds, clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc),
		"EUDI credential should have an SD-JWT instance")
	require.NotNil(t, cred.IssuanceDate, "EUDI credential should have an issuance date")
	require.False(t, cred.Revoked)
}

// findLog returns the first log entry of the given type, or nil.
func findLog(logs []clientmodels.LogInfo, logType clientmodels.LogType) *clientmodels.LogInfo {
	for i := range logs {
		if logs[i].Type == logType {
			return &logs[i]
		}
	}
	return nil
}

// requireValidImage asserts the image is present and its base64 payload decodes
// as a non-empty raster image.
func requireValidImage(t *testing.T, img *clientmodels.Image, desc string) {
	t.Helper()
	require.NotNil(t, img, "%s image should be present", desc)
	require.NotEmpty(t, img.Base64, "%s image should carry base64 data", desc)
	raw, err := base64.StdEncoding.DecodeString(img.Base64)
	require.NoError(t, err, "%s image base64 should decode", desc)
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	require.NoError(t, err, "%s image should be a decodable image", desc)
	require.Greater(t, cfg.Width, 0, "%s image should have positive width", desc)
	require.Greater(t, cfg.Height, 0, "%s image should have positive height", desc)
}

// loadClientFromFixture creates a client.Client from a saved db2 file.
func loadClientFromFixture(t *testing.T, db2Path string) (*client.Client, *MockSessionHandler) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	testdataPath := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")

	require.NoError(t, common.CopyDirectory(filepath.Join(testdataPath, "irma_configuration"), filepath.Join(storagePath, "irma_configuration")))
	require.NoError(t, common.EnsureDirectoryExists(filepath.Join(storagePath, "eudi")))

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

	// Copy the saved db2 into the storage path (always as "db2", which is what the client expects)
	copyFile(t, db2Path, filepath.Join(storagePath, "db2"))

	// Copy the saved EUDI (sqlcipher) DB in when the fixture has one (v1.0.0+).
	// Older fixtures (pre-sqlcipher) don't, and load with an empty EUDI DB.
	eudiDBSrc := filepath.Join(filepath.Dir(db2Path), "eudi_client_db")
	if _, err := os.Stat(eudiDBSrc); err == nil {
		copyFile(t, eudiDBSrc, filepath.Join(storagePath, "eudi", storage.DbFilename))
	}

	// Load the signer key from the fixture
	signer := loadSignerFromFixture(t, filepath.Dir(db2Path))

	irmaConfigurationPath := filepath.Join(storagePath, "irma_configuration")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")
	clientHandler := irmaclient.NewMockClientHandler()
	sessionHandler := &MockSessionHandler{
		SessionChan: make(chan clientmodels.SessionState, 10),
	}
	c, err := client.New(storagePath, irmaConfigurationPath, eudiAppDataPath, clientHandler, sessionHandler, signer, aesKey)
	require.NoError(t, err)

	c.SetPreferences(clientsettings.Preferences{DeveloperMode: true})

	return c, sessionHandler
}

func loadSignerFromFixture(t *testing.T, fixtureDir string) irmaclient.Signer {
	pemPath := filepath.Join(fixtureDir, "ecdsa_sk.pem")
	bts, err := os.ReadFile(pemPath)
	if os.IsNotExist(err) {
		t.Log("No ecdsa_sk.pem in fixture, generating fresh signer")
		return test.NewSigner(t)
	}
	require.NoError(t, err)
	sk, err := signed.UnmarshalPemPrivateKey(bts)
	require.NoError(t, err)
	return test.LoadSigner(t, sk)
}

// performDisclosureSessionForAttribute performs an IRMA disclosure of a non-keyshare attribute.
func performDisclosureSessionForAttribute(t *testing.T, c *client.Client, sessionId int, sessionHandler *MockSessionHandler, irmaServer *IrmaServer, attribute string) {
	req := irma.NewDisclosureRequest()
	req.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest(attribute),
			},
		},
	}
	c.NewSession(sessionId, startSameDeviceIrmaSessionAtServer(t, irmaServer, req))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

// performKeyshareDisclosureSession performs an IRMA disclosure of a keyshare-protected attribute.
// The reloaded client doesn't have the keyshare auth token cached, so a PIN is requested.
func performKeyshareDisclosureSession(t *testing.T, c *client.Client, sessionId int, sessionHandler *MockSessionHandler, irmaServer *IrmaServer, attribute string) {
	req := irma.NewDisclosureRequest()
	req.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest(attribute),
			},
		},
	}
	c.NewSession(sessionId, startSameDeviceIrmaSessionAtServer(t, irmaServer, req))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	cred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(cred))

	// The reloaded client needs to authenticate with the keyshare server.
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

func requireCredentialPresent(t *testing.T, creds []*clientmodels.Credential, credType string) {
	t.Helper()
	cred := findCredentialById(creds, credType)
	require.NotNilf(t, cred, "expected credential %s", credType)
}

func loadKeyshareUsersFromFixture(t *testing.T, db *keyshareserver.MemoryDB, fixtureDir string) {
	bts, err := os.ReadFile(filepath.Join(fixtureDir, "keyshare_users.json"))
	if os.IsNotExist(err) {
		t.Log("No keyshare_users.json in fixture, skipping keyshare user preload")
		return
	}
	require.NoError(t, err)

	var users []keyshareserver.User
	require.NoError(t, json.Unmarshal(bts, &users))

	for i := range users {
		_ = db.AddUser(context.Background(), &users[i])
	}
	t.Logf("Loaded %d keyshare users from fixture", len(users))
}

func requireLogTypePresent(t *testing.T, logs []clientmodels.LogInfo, logType clientmodels.LogType) {
	t.Helper()
	for _, log := range logs {
		if log.Type == logType {
			return
		}
	}
	require.Failf(t, "log type not found", "expected log type %s", logType)
}
