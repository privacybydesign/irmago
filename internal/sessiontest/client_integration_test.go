package sessiontest

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	mathBig "math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/client/clientsettings"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/crypto/encryption"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
	"github.com/privacybydesign/irmago/irma/server"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestEudiClient(t *testing.T) {
	t.Run("double sdjwt issuance replaces instances", testDoubleSdJwtIssuanceReplacesInstances)
	t.Run("double sdjwt issuance fails after revocation list update", testDoubleSdJwtIssuanceFailsAfterRevocationListUpdate)
	t.Run("credential instance count", testCredentialInstanceCount)
	t.Run("test logs for combined issuance and disclosure", testLogsForCombinedIssuanceAndDisclosure)

	t.Run("test logs for completely optional disclosure", testLogsForCompletelyOptionalDisclosure)
	t.Run("remove storage empty client", testRemoveStorageEmptyClient)
	t.Run("remove storage with only idemix credentials", testRemoveStorageWithOnlyIdemixCredentials)
	t.Run("remove storage clears eudi database and filesystem", testRemoveStorageClearsEudiDatabaseAndFilesystem)
	t.Run("credential store items have images", testCredentialStoreItemsHaveImages)

	t.Run("irma disclosure session logs", testIrmaDisclosureSessionLogs)
	t.Run("signature session logs", testIrmaSignatureSessionLogs)
	t.Run("eudi session logs", testEudiSessionLogs)

	t.Run("idemix only credential removal log", testIdemixOnlyCredentialRemovalLog)
	t.Run("idemix and sdjwt combined credential removal log", testIdemixAndSdJwtCombinedRemovalLog)

	t.Run("idemix and sdjwtvc combined issuance over irma", testIdemixAndSdJwtCombinedIssuance)
	t.Run("disclose single sdjwtvc over openid4vp", testDiscloseOverOpenID4VP)
	t.Run("idemix and sdjwtvc show up as single credential info", testIdemixAndSdJwtShowUpAsSeparateCredentialInfos)
	t.Run("deleting combined credential deletes both formats", testDeletingCombinedCredentialDeletesBothFormats)
	t.Run("optional empty attributes excluded from GetCredentials", testOptionalEmptyAttributesExcludedFromGetCredentials)
}

func testDoubleSdJwtIssuanceReplacesInstances(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	awaitSessionState(t, sessionHandler)

	creds, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)

	emailCred := findCredentialById(creds, "test.test.email")
	require.NotNil(t, emailCred)
	require.Equal(t, 10, int(*emailCred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc)]))

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	awaitSessionState(t, sessionHandler)

	creds, err = c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)

	emailCred = findCredentialById(creds, "test.test.email")
	require.NotNil(t, emailCred)
	require.Equal(t, 10, int(*emailCred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc)]))
}

func testCredentialInstanceCount(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	c, sessionHandler := createClient(t)

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	awaitSessionState(t, sessionHandler)

	creds, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)

	emailCred := findCredentialById(creds, "test.test.email")
	require.NotNil(t, emailCred)

	numInstances := uint(10)

	require.Equal(t, numInstances, *emailCred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc)])

	for i := range numInstances {
		discloseOverOpenID4VP(t, c, sessionHandler, testdata.OpenID4VP_DirectPost_Host)

		creds, err = c.GetCredentials()
		require.NoError(t, err)
		require.Len(t, creds, 1)

		emailCred = findCredentialById(creds, "test.test.email")
		require.NotNil(t, emailCred)
		require.Equal(t, numInstances-1-i, *emailCred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc)])
	}

	c.Close()
	keyshareServer.Stop()
	irmaServer.Stop()
}

func testLogsForCombinedIssuanceAndDisclosure(t *testing.T) {
	conf := IrmaServerConfigurationWithTempStorage(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	performCombinedIssuanceAndDisclosureSession(t, c, sessionHandler, irmaServer)

	logs, err := c.LoadNewestLogs(20)
	require.NoError(t, err)

	latestLog := logs[0]

	require.Equal(t, latestLog.Type, clientmodels.LogType_Issuance)
	require.Equal(t, latestLog.IssuanceLog.Protocol, clientmodels.Protocol_Irma)
	require.Len(t, latestLog.IssuanceLog.DisclosedCredentials, 2)
	require.Len(t, latestLog.IssuanceLog.Credentials, 1)
}

func createEmailIssuanceRequest() *irma.IssuanceRequest {
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.email"),
			Attributes: map[string]string{
				"email": "test@gmail.com",
			},
		},
	})
}

func createStudentCardIssuanceRequestWithSdJwt() *irma.IssuanceRequest {
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "University of the Arts",
				"studentCardNumber": "12345",
				"studentID":         "67890",
				"level":             "high",
			},
			SdJwtBatchSize: 10,
		},
	})
}

func createStudentCardIssuanceRequest() *irma.IssuanceRequest {
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
			Attributes: map[string]string{
				"university":        "University of the Arts",
				"studentCardNumber": "12345",
				"studentID":         "67890",
				"level":             "high",
			},
		},
	})
}

func createMijnOverheidIssuanceRequestWithSdJwt() *irma.IssuanceRequest {
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Barry",
				"firstname":  "Bar",
				"familyname": "Batsbak",
				"prefix":     "Sir",
			},
			SdJwtBatchSize: 10,
		},
	})
}

func createMijnOverheidIssuanceRequest() *irma.IssuanceRequest {
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Barry",
				"firstname":  "Bar",
				"familyname": "Batsbak",
				"prefix":     "Sir",
			},
		},
	})
}

func performCombinedIssuanceAndDisclosureSession(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	regularIssuanceRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Barry",
				"firstname":  "",
				"familyname": "Batsbak",
			},
		},
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.singleton"),
			Attributes: map[string]string{
				"BSN": "1234",
			},
		},
	})

	issue(t, irmaServer, c, sessionHandler, regularIssuanceRequest)

	awaitSessionState(t, sessionHandler)

	combinedIssuanceRequest := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test2.email"),
			Attributes: map[string]string{
				"email": "two@gmail.com",
			},
		},
	})
	combinedIssuanceRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN"),
			},
		},
	}

	sessionRequestJson := startSameDeviceIrmaSessionAtServer(t, irmaServer, combinedIssuanceRequest)
	c.NewSession(sessionRequestJson)
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	// Both fullName.familyname and singleton.BSN belong to one discon, so they
	// appear as two OwnedOptions within a single DisclosurePickOne.
	overview := session.DisclosurePlan.DisclosureChoicesOverview[0]
	var fullNameCred, singletonCred *clientmodels.SelectableCredentialInstance
	for _, opt := range overview.OwnedOptions {
		switch opt.CredentialId {
		case "irma-demo.MijnOverheid.fullName":
			fullNameCred = opt
		case "irma-demo.MijnOverheid.singleton":
			singletonCred = opt
		}
	}
	require.NotNil(t, fullNameCred)
	require.NotNil(t, singletonCred)

	grantPermission(t, c, session.Id, clientmodels.DisclosureDisconSelection{
		Credentials: []clientmodels.SelectedCredential{
			{CredentialId: fullNameCred.CredentialId, CredentialHash: fullNameCred.Hash, AttributePaths: [][]any{{"familyname"}}},
			{CredentialId: singletonCred.CredentialId, CredentialHash: singletonCred.Hash, AttributePaths: [][]any{{"BSN"}}},
		},
	})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

func testLogsForCompletelyOptionalDisclosure(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	performCompletelyOptionalDisclosure(t, c, sessionHandler, irmaServer)

	logs, err := c.LoadNewestLogs(10)
	require.NoError(t, err)

	latestLog := logs[0]

	require.Equal(t, latestLog.Type, clientmodels.LogType_Disclosure)
	require.Empty(t, latestLog.DisclosureLog.Credentials)
	require.Equal(t, latestLog.DisclosureLog.Protocol, clientmodels.Protocol_Irma)
	require.Equal(t, latestLog.DisclosureLog.Verifier.Id, "test-requestors.test-requestor")
}

func performCompletelyOptionalDisclosure(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	req := irma.NewDisclosureRequest()
	req.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
			irma.AttributeCon{},
		},
	}
	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, req))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	// Grant permission with an empty selection for the one optional discon.
	grantPermission(t, c, session.Id, clientmodels.DisclosureDisconSelection{})

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

func testRemoveStorageWithOnlyIdemixCredentials(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, createIdemixOnlyIssuanceRequest())

	awaitSessionState(t, sessionHandler)

	require.NoError(t, c.RemoveStorage())
}

func testRemoveStorageEmptyClient(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, _ := createClient(t)
	defer c.Close()

	require.NoError(t, c.RemoveStorage())
}

func testCredentialStoreItemsHaveImages(t *testing.T) {
	c, _ := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Mark test.test.email as a credential store item so GetCredentialStore() includes it.
	emailCredId := irma.NewCredentialTypeIdentifier("test.test.email")
	credType := c.GetIrmaConfiguration().CredentialTypes[emailCredId]
	require.NotNil(t, credType, "test.test.email should exist in the configuration")

	issueURL := irma.TranslatedString{"en": "https://example.com/issue/email"}
	credType.IsInCredentialStore = true
	credType.IssueURL = &issueURL

	// Verify this credential type has a logo file on disk (the test scheme includes logo.png).
	logoPath := credType.Logo(c.GetIrmaConfiguration())
	require.NotEmpty(t, logoPath, "test.test.email should have a logo.png in the scheme")

	store, err := c.GetCredentialStore()
	require.NoError(t, err)
	require.NotEmpty(t, store, "credential store should contain at least one item")

	var emailItem *clientmodels.CredentialStoreItem
	for _, item := range store {
		if item.Credential.CredentialId == emailCredId.String() {
			emailItem = item
			break
		}
	}
	require.NotNil(t, emailItem, "credential store should contain test.test.email")

	// The credential store item should have a valid image from the scheme's logo.png.
	require.NotNil(t, emailItem.Credential.Image,
		"credential store item should have an image (logo.png exists at %s)", logoPath)
	require.NotEmpty(t, emailItem.Credential.Image.Base64,
		"credential store item image should have base64 data")

	// The issuer should also have an image.
	require.NotNil(t, emailItem.Credential.Issuer.Image,
		"credential store item issuer should have an image")
	require.NotEmpty(t, emailItem.Credential.Issuer.Image.Base64,
		"credential store item issuer image should have base64 data")
}

func testRemoveStorageClearsEudiDatabaseAndFilesystem(t *testing.T) {
	c, sessionHandler := createClientWithoutKeyshareEnrollment(t, nil)
	defer c.Close()

	// Issue a credential so that the EUDI database and filesystem are populated.
	issueCredentialViaOpenID4VCI(t, c, sessionHandler, "TestCredentialSdJwt", `{
		"given_name": "Storage",
		"family_name": "Cleanup",
		"email": "cleanup@example.com"
	}`)

	// Verify credentials exist before removal.
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	require.NotEmpty(t, creds, "should have at least one credential after issuance")

	// Verify logs exist before removal.
	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.NotEmpty(t, logs, "should have at least one log after issuance")

	// Derive the EUDI storage path from the client's temp directory.
	// instantiateClient creates: storageFolder/client/eudi/
	eudiPath := filepath.Join(c.GetIrmaConfiguration().Path, "..", "eudi")

	// Verify the EUDI database file exists.
	dbPath := filepath.Join(eudiPath, "yivi.db")
	_, err = os.Stat(dbPath)
	require.NoError(t, err, "EUDI database should exist before RemoveStorage")

	// Verify the EUDI filesystem directories have content (certificates at minimum).
	requireDirHasFiles(t, eudiPath, "EUDI storage directory should have content before RemoveStorage")

	// Act: remove all storage.
	require.NoError(t, c.RemoveStorage())

	// Assert: EUDI credentials are gone.
	creds, err = c.GetCredentials()
	require.NoError(t, err)
	require.Empty(t, creds, "credentials should be empty after RemoveStorage")

	// Assert: EUDI logs are gone.
	logs, err = c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Empty(t, logs, "logs should be empty after RemoveStorage")

	// Assert: EUDI filesystem directories are cleaned up.
	for _, subdir := range []string{
		"credentials/logos",
		"issuers/logos",
		"verifiers/logos",
		"issuers/certificates",
		"verifiers/certificates",
	} {
		dir := filepath.Join(eudiPath, subdir)
		if _, err := os.Stat(dir); err == nil {
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Empty(t, entries,
				"directory %s should be empty after RemoveStorage, but has %d files", subdir, len(entries))
		}
	}
}

// requireDirHasFiles asserts that a directory tree contains at least one regular file.
func requireDirHasFiles(t *testing.T, dir string, msg string) {
	t.Helper()
	found := false
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	require.True(t, found, msg)
}

func testIdemixOnlyCredentialRemovalLog(t *testing.T) {
	// This test makes sure the attributes in the log are not in incorrect order.
	// It solves a bug we had where the list of attributes had an incorrect order due to a (unordered) map being converted to a list.
	tester := func(t *testing.T) {
		conf := IrmaServerConfigurationWithTempStorage(t)
		irmaServer := StartIrmaServer(t, conf)
		keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
		c, sessionHandler := createClient(t)

		issue(t, irmaServer, c, sessionHandler, createMijnOverheidIssuanceRequest())

		awaitSessionState(t, sessionHandler)

		credentials, err := c.GetCredentials()
		require.NoError(t, err)
		fullNameCred := findCredentialById(credentials, "irma-demo.MijnOverheid.fullName")
		require.NotNil(t, fullNameCred)

		require.NoError(t, c.RemoveCredentialsByHash(credentialHashByFormat(fullNameCred)))

		logs, err := c.LoadNewestLogs(100)
		require.NoError(t, err)

		require.Equal(t, logs[0].Type, clientmodels.LogType_CredentialRemoval)
		removalLog := logs[0].RemovalLog

		// one credential was removed
		require.Len(t, removalLog.Credentials, 1)

		credential := removalLog.Credentials[0]

		require.Contains(t, credential.Formats, clientmodels.Format_Idemix)
		require.Equal(t, "irma-demo.MijnOverheid.fullName", credential.CredentialId)
		require.Equal(t, "Demo Name", credential.Name["en"])
		require.Equal(t, "Demo MijnOverheid.nl", credential.Issuer.Name["en"])

		requireAttrsInOrder(t, credential.Attributes,
			expectedAttr{
				Path:        []any{"firstnames"},
				DisplayName: &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
				Description: &clientmodels.TranslatedString{"en": "All of your first names", "nl": "Al uw voornamen"},
				Value:       strVal("Barry"),
			},
			expectedAttr{
				Path:        []any{"firstname"},
				DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"},
				Description: &clientmodels.TranslatedString{"en": "Your first name", "nl": "Uw voornaam"},
				Value:       strVal("Bar"),
			},
			expectedAttr{
				Path:        []any{"familyname"},
				DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
				Description: &clientmodels.TranslatedString{"en": "Your family name", "nl": "Uw achternaam"},
				Value:       strVal("Batsbak"),
			},
			expectedAttr{
				Path:        []any{"prefix"},
				DisplayName: &clientmodels.TranslatedString{"en": "Prefix", "nl": "Tussenvoegsel"},
				Description: &clientmodels.TranslatedString{"en": "Family name prefix", "nl": "Tussenvoegsel van uw achternaam"},
				Value:       strVal("Sir"),
			},
		)

		c.Close()
		keyshareServer.Stop()
		irmaServer.Stop()
	}

	for range 10 {
		tester(t)
	}
}

func testIdemixAndSdJwtCombinedRemovalLog(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, createIdemixOnlyIssuanceRequest())

	awaitSessionState(t, sessionHandler)

	credentials, err := c.GetCredentials()
	require.NoError(t, err)
	emailCred := findCredentialById(credentials, "test.test.email")
	require.NotNil(t, emailCred)

	require.NoError(t, c.RemoveCredentialsByHash(credentialHashByFormat(emailCred)))

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)

	requireIdemixOnlyCredentialRemovalLog(t, logs[0])
}

func testDoubleSdJwtIssuanceFailsAfterRevocationListUpdate(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabledWithoutCerts(t)

	var crl *x509.RevocationList

	// Setup a mocked server to get the CRL from
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
	}))
	defer ts.Close()

	// Setup a PKI to test with
	// The revocation list is already in need of an update at creation time, so that the client will try to download it
	_, rootCert, caKeys, caCerts, _ := testdata.CreateTestPkiHierarchy(t, testdata.CreateDistinguishedName("ROOT 1"), 1, testdata.PkiOption_None, &ts.URL)

	// The caCrls are the CRLs issued by the root for the intermediate CAs, so we need to create a new one for the intermediate CA itself
	crlTemplate := testdata.GetDefaultCrlTemplate(caCerts[0])
	crlTemplate.AuthorityKeyId = caCerts[0].SubjectKeyId // Set the correct AuthorityKeyId
	crlTemplate.Issuer = caCerts[0].Subject              // Set the correct Issuer
	crlTemplate.ThisUpdate = time.Now().Add(-2 * time.Hour)
	crlTemplate.NextUpdate = time.Now().Add(-1 * time.Hour)

	crlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCerts[0], caKeys[0])
	require.NoError(t, err)
	crl, err = x509.ParseRevocationList(crlBytes)
	require.NoError(t, err)

	// Create an issuer certificate for the IRMA server
	issuerSchemeData := `{
		"registration": "https://portal.yivi.app/organizations/yivi",
		"organization": {
			"legalName": {
				"en": "Yivi B.V.",
				"nl": "Yivi B.V."
			}
		},
		"ap": {
			"authorized": [
				{
					"credential": "test.test.email",
					"attributes": ["email"]
				}
			]
		}
	}`

	uri, err := url.Parse(ts.URL)
	require.NoError(t, err)

	issuerKey, issuerCert, _ := testdata.CreateEndEntityCertificate(t, testdata.CreateDistinguishedName("END ENTITY CERT"), uri.Host, caCerts[0], caKeys[0], issuerSchemeData, testdata.PkiOption_None)
	testdata.WritePrivateKeyToFile(t, path.Join(conf.SdJwtIssuanceSettings.SdJwtIssuerPrivKeysDir, "test.test.pem"), issuerKey)
	testdata.WriteCertAsPemFile(t, path.Join(conf.SdJwtIssuanceSettings.SdJwtIssuerCertificatesDir, "test.test.pem"), issuerCert)

	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClientWithCustomIssuerTrustChain(t, rootCert, caCerts[0])
	defer c.Close()

	revocationListUpdateInterval := 3 * time.Second
	c.InitJobs(revocationListUpdateInterval)

	// Give the client some time to init and download the current CRL
	time.Sleep(4 * time.Second)

	// Execute first issuance
	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	awaitSessionState(t, sessionHandler)

	creds, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)

	cred := findCredentialById(creds, "test.test.email")
	require.NotNil(t, cred)

	require.Equal(t, 10, int(*cred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc)]))

	// Revoke the issuer certificate, wait for the client to pick up the new CRL and try to issue again
	crlTemplate.Number = crlTemplate.Number.Add(crl.Number, mathBig.NewInt(1))
	crlTemplate.NextUpdate = time.Now().Add(24 * time.Hour)
	crlTemplate.RevokedCertificateEntries = []x509.RevocationListEntry{
		{
			SerialNumber:   issuerCert.SerialNumber,
			RevocationTime: time.Now(),
			ReasonCode:     0,
		},
	}
	updatedCrlBytes, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCerts[0], caKeys[0])
	require.NoError(t, err)
	crl, err = x509.ParseRevocationList(updatedCrlBytes)
	require.NoError(t, err)

	// Sleep shortly to let the client update the CRL
	time.Sleep(6 * time.Second)

	// Execute second issuance, which should now fail
	// TODO: how to check that it failed?
	failIssueSdJwtAndIdemixToClient(t, c, sessionHandler, irmaServer)

	creds, err = c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)

	cred = findCredentialById(creds, "test.test.email")
	require.NotNil(t, cred)

	require.Equal(t, 10, int(*cred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc)]))
}

func requireIdemixOnlyCredentialRemovalLog(t *testing.T, log clientmodels.LogInfo) {
	require.Equal(t, log.Type, clientmodels.LogType_CredentialRemoval)
	require.Len(t, log.RemovalLog.Credentials, 1)
	cred := log.RemovalLog.Credentials[0]
	require.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_Idemix}, cred.Formats)
	require.Equal(t, "test.test.email", cred.CredentialId)
	require.Equal(t, "Demo Email address", cred.Name["en"])
	require.Equal(t, "Demo test issuer", cred.Issuer.Name["en"])

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
			Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
			Value:       strVal("test@gmail.com"),
		},
	)
}

func testIrmaDisclosureSessionLogs(t *testing.T) {
	conf := IrmaServerConfigurationWithTempStorage(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, createIdemixOnlyIssuanceRequest())

	awaitSessionState(t, sessionHandler)
	performIrmaDisclosureSession(t, c, sessionHandler, irmaServer)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 3)

	requireIrmaDisclosureLog(t, logs[0])
}

func testIrmaSignatureSessionLogs(t *testing.T) {
	conf := IrmaServerConfigurationWithTempStorage(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, createIdemixOnlyIssuanceRequest())

	awaitSessionState(t, sessionHandler)
	performIrmaSignatureSession(t, c, sessionHandler, irmaServer)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 3)

	requireSignatureLog(t, logs[0])
}

func requireIrmaDisclosureLog(t *testing.T, log clientmodels.LogInfo) {
	require.Equal(t, log.Type, clientmodels.LogType_Disclosure)
	require.Equal(t, clientmodels.Protocol_Irma, log.DisclosureLog.Protocol)
	require.Len(t, log.DisclosureLog.Credentials, 1)
	cred := log.DisclosureLog.Credentials[0]
	require.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_Idemix}, cred.Formats)
	require.Equal(t, "test.test.email", cred.CredentialId)
	require.Equal(t, "Demo Email address", cred.Name["en"])
	require.Equal(t, "Demo test issuer", cred.Issuer.Name["en"])

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
			Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
			Value:       strVal("test@gmail.com"),
		},
	)
}

func requireSignatureLog(t *testing.T, log clientmodels.LogInfo) {
	require.Equal(t, log.Type, clientmodels.LogType_Signature)
	require.Equal(t, clientmodels.Protocol_Irma, log.SignedMessageLog.Protocol)
	require.Equal(t, "Hello, World!", log.SignedMessageLog.Message)
	require.Len(t, log.SignedMessageLog.Credentials, 1)
	cred := log.SignedMessageLog.Credentials[0]
	require.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_Idemix}, cred.Formats)
	require.Equal(t, "test.test.email", cred.CredentialId)
	require.Equal(t, "Demo Email address", cred.Name["en"])
	require.Equal(t, "Demo test issuer", cred.Issuer.Name["en"])

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
			Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
			Value:       strVal("test@gmail.com"),
		},
	)
}

func testEudiSessionLogs(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	logs, err := c.LoadNewestLogs(100)

	require.NoError(t, err)

	// only keyshare enrollment log should be there
	require.Len(t, logs, 1)

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	awaitSessionState(t, sessionHandler)

	logs, err = c.LoadNewestLogs(100)
	require.NoError(t, err)
	require.Len(t, logs, 2)

	// credential with sdjwt included
	requireIrmaSdJwtIssuanceLog(t, logs[0])

	// keyshare attribute (no sdjwt included)
	requireRegularIrmaIssuanceLog(t, logs[1])

	discloseOverOpenID4VP(t, c, sessionHandler, testdata.OpenID4VP_DirectPostJwt_Host)
	logs, err = c.LoadNewestLogs(100)
	require.NoError(t, err)

	require.Len(t, logs, 3)
	requireOpenID4VPLog(t, logs[0])
}

func requireOpenID4VPLog(t *testing.T, log clientmodels.LogInfo) {
	require.Equal(t, log.Type, clientmodels.LogType_Disclosure)
	require.NotNil(t, log.DisclosureLog)
	require.Len(t, log.DisclosureLog.Credentials, 1)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, log.DisclosureLog.Protocol)

	cred := log.DisclosureLog.Credentials[0]
	require.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_SdJwtVc}, cred.Formats)
	require.Equal(t, "test.test.email", cred.CredentialId)
	require.Equal(t, "Demo Email address", cred.Name["en"])
	require.Equal(t, "Demo test issuer", cred.Issuer.Name["en"])

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
			Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
			Value:       strVal("test@gmail.com"),
		},
	)
}

func requireRegularIrmaIssuanceLog(t *testing.T, log clientmodels.LogInfo) {
	require.Equal(t, log.Type, clientmodels.LogType_Issuance)
	require.Equal(t, clientmodels.Protocol_Irma, log.IssuanceLog.Protocol)

	cred := log.IssuanceLog.Credentials[0]
	require.Equal(t, []clientmodels.CredentialFormat{clientmodels.Format_Idemix}, cred.Formats)
}

func requireIrmaSdJwtIssuanceLog(t *testing.T, log clientmodels.LogInfo) {
	require.Equal(t, log.Type, clientmodels.LogType_Issuance)
	require.Equal(t, clientmodels.Protocol_Irma, log.IssuanceLog.Protocol)

	require.Len(t, log.IssuanceLog.Credentials, 1)

	cred := log.IssuanceLog.Credentials[0]

	require.Contains(t, cred.Formats, clientmodels.Format_SdJwtVc)
	require.Contains(t, cred.Formats, clientmodels.Format_Idemix)

	require.Equal(t, "test.test.email", cred.CredentialId)
	require.Equal(t, "Demo Email address", cred.Name["en"])
	require.Equal(t, "Demo test issuer", cred.Issuer.Name["en"])

	requireAttrsInOrder(t, cred.Attributes,
		expectedAttr{
			Path:        []any{"email"},
			DisplayName: &clientmodels.TranslatedString{"en": "Email address", "nl": "E-mailadres"},
			Description: &clientmodels.TranslatedString{"en": "Your verified email address", "nl": "Uw geverifiëerde e-mailadres"},
			Value:       strVal("test@gmail.com"),
		},
	)
}

func testDeletingCombinedCredentialDeletesBothFormats(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	awaitSessionState(t, sessionHandler)

	creds, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)

	emailCred := findCredentialById(creds, "test.test.email")
	require.NotNil(t, emailCred)

	require.NoError(t, c.RemoveCredentialsByHash(credentialHashByFormat(emailCred)))

	creds, err = c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 0)
}

func testIdemixAndSdJwtShowUpAsSeparateCredentialInfos(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	awaitSessionState(t, sessionHandler)

	creds, err := c.GetCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)

	emailCred := findCredentialById(creds, "test.test.email")
	require.NotNil(t, emailCred)
	require.Len(t, emailCred.CredentialInstanceIds, 2)
}

func testIdemixAndSdJwtCombinedIssuance(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	awaitSessionState(t, sessionHandler)
}

func testDiscloseOverOpenID4VP(t *testing.T) {
	conf := irmaServerConfWithSdJwtEnabled(t)
	irmaServer := StartIrmaServer(t, conf)
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	issue(t, irmaServer, c, sessionHandler, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))

	awaitSessionState(t, sessionHandler)
	discloseOverOpenID4VP(t, c, sessionHandler, testdata.OpenID4VP_DirectPost_Host)
	discloseOverOpenID4VP(t, c, sessionHandler, testdata.OpenID4VP_DirectPostJwt_Host)
}

func discloseOverOpenID4VP(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, openid4vpHost string) {
	verifierSession, err := irmaclient.StartTestSessionAtEudiVerifier(openid4vpHost, createEmailAuthRequestRequest())
	require.NoError(t, err)
	sessionReq := client.SessionRequestData{
		Qr: irma.Qr{
			Type: irma.ActionDisclosing,
			URL:  verifierSession.SessionLink,
		},
		Protocol: clientmodels.Protocol_OpenID4VP,
	}
	sessionJson, err := json.Marshal(sessionReq)
	require.NoError(t, err)

	c.NewSession(string(sessionJson))
	sessionState := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, sessionState.Status)

	emailCred := sessionState.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, sessionState.Id, makeDisclosureChoice(emailCred))

	sessionState = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, sessionState.Status)
}

func createIdemixOnlyIssuanceRequest() *irma.IssuanceRequest {
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.email"),
			Attributes: map[string]string{
				"email": "test@gmail.com",
			},
		},
	})
}

func failIssueSdJwtAndIdemixToClient(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email")))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	grantPermission(t, c, session.Id)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Error, session.Status)
}

func performIrmaDisclosureSession(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	req := irma.NewDisclosureRequest()
	req.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
	}
	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, req))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	emailCred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(emailCred))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

func performIrmaSignatureSession(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	req := irma.NewSignatureRequest("Hello, World!")
	req.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("test.test.email.email"),
			},
		},
	}

	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, req))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	emailCred := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(emailCred))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

func startCrossDeviceIrmaSessionAtServer(t *testing.T, server *IrmaServer, req irma.SessionRequest) string {
	qr, _, _, err := server.irma.StartSession(req, nil, "")
	require.NoError(t, err)
	session := client.SessionRequestData{
		Qr:                     *qr,
		Protocol:               clientmodels.Protocol_Irma,
		ContinueOnSecondDevice: true,
	}
	sessionJson, err := json.Marshal(session)
	require.NoError(t, err)
	return string(sessionJson)
}

func startSameDeviceIrmaSessionAtServer(t *testing.T, server *IrmaServer, req any) string {
	sessionJson, _ := startSameDeviceIrmaSessionAtServerWithToken(t, server, req)
	return sessionJson
}

func startSameDeviceIrmaSessionAtServerWithToken(t *testing.T, server *IrmaServer, req any) (string, irma.RequestorToken) {
	qr, token, _, err := server.irma.StartSession(req, nil, "")
	require.NoError(t, err)
	session := client.SessionRequestData{
		Qr:                     *qr,
		Protocol:               clientmodels.Protocol_Irma,
		ContinueOnSecondDevice: false,
	}
	sessionJson, err := json.Marshal(session)
	require.NoError(t, err)
	return string(sessionJson), token
}

func createIrmaIssuanceRequestWithSdJwts(credentialId string, attributeId string) *irma.IssuanceRequest {
	var sdJwtBatchSize uint = 10
	req := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier(credentialId),
			Attributes: map[string]string{
				attributeId: "test@gmail.com",
			},
			SdJwtBatchSize: sdJwtBatchSize,
		},
	})
	return req
}

func createClient(t *testing.T) (*client.Client, *MockSessionHandler) {
	return createClientWithIssuerChain(t, nil)
}

type MockSessionHandler struct {
	SessionChan chan clientmodels.SessionState
}

func (mh *MockSessionHandler) UpdateSession(s clientmodels.SessionState) {
	mh.SessionChan <- s
}

func createClientWithoutKeyshareEnrollment(t *testing.T, issuerChain []byte) (*client.Client, *MockSessionHandler) {
	client, _, sessionHandler := instantiateClient(t, issuerChain)
	return client, sessionHandler
}

func createClientWithIssuerChain(t *testing.T, issuerChain []byte) (*client.Client, *MockSessionHandler) {
	client, clientHandler, sessionHandler := instantiateClient(t, issuerChain)
	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")

	require.NoError(t, clientHandler.AwaitEnrollmentResult())

	return client, sessionHandler
}

func createClientWithCustomIssuerTrustChain(
	t *testing.T,
	issuerRoot *x509.Certificate,
	issuerCert *x509.Certificate,
) (*client.Client, *MockSessionHandler) {
	issuerChainBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerRoot.Raw})
	issuerChainBytes = append(issuerChainBytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuerCert.Raw})...)

	return createClientWithIssuerChain(t, issuerChainBytes)
}

func instantiateClient(t *testing.T, issuerChain []byte) (*client.Client, *irmaclient.MockClientHandler, *MockSessionHandler) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(storagePath, "irma_configuration")
	eudiAppDataPath := filepath.Join(storagePath, "eudi")

	// Copy files to storage folder
	require.NoError(t, common.CopyDirectory(filepath.Join(path, "irma_configuration"), filepath.Join(storagePath, "irma_configuration")))
	require.NoError(t, common.EnsureDirectoryExists(eudiAppDataPath))

	// Add test issuer certificates as trusted chain (encrypted, since the
	// EUDI filesystem storage decrypts files on read).
	encMiddleware := encryption.NewAESEncryptionMiddleware(aesKey)

	issuerCertsPath := filepath.Join(storagePath, "eudi", "issuers", "certificates")
	require.NoError(t, common.EnsureDirectoryExists(issuerCertsPath))

	if issuerChain != nil {
		encIssuer, err := encMiddleware.Encrypt(issuerChain)
		require.NoError(t, err)
		require.NoError(t, common.SaveFile(filepath.Join(issuerCertsPath, "integrationtest-chain.pem"), encIssuer))
	} else {
		encIssuer, err := encMiddleware.Encrypt(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes)
		require.NoError(t, err)
		require.NoError(t, common.SaveFile(filepath.Join(issuerCertsPath, "issuer_cert_openid4vc_staging_yivi_app.pem"), encIssuer))
	}

	// Add test verifier CA certificate as trusted chain.
	verifierCertsPath := filepath.Join(storagePath, "eudi", "verifiers", "certificates")
	require.NoError(t, common.EnsureDirectoryExists(verifierCertsPath))
	encVerifierCA, err := encMiddleware.Encrypt(testdata.VerifierCACertBytes)
	require.NoError(t, err)
	require.NoError(t, common.SaveFile(filepath.Join(verifierCertsPath, "ca.pem"), encVerifierCA))

	clientHandler := irmaclient.NewMockClientHandler()
	sessionHandler := &MockSessionHandler{
		SessionChan: make(chan clientmodels.SessionState, 10),
	}
	client, err := client.New(storagePath, irmaConfigurationPath, eudiAppDataPath, clientHandler, sessionHandler, test.NewSigner(t), aesKey)
	require.NoError(t, err)

	client.SetPreferences(clientsettings.Preferences{DeveloperMode: true})
	return client, clientHandler, sessionHandler
}

func createAuthRequestRequestWithDcql(dcql string) string {
	return fmt.Sprintf(`
		{
		  "type": "vp_token",
		  "dcql_query": %s,
		  "nonce": "nonce",
		  "jar_mode": "by_reference",
		  "request_uri_method": "post",
		  "issuer_chain": "%s"
		}
		`,
		dcql,
		string(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
	)
}

func createEmailAuthRequestRequest() string {
	return createAuthRequestRequestWithDcql(`
		  {
			"credentials": [
			  {
				"id": "32f54163-7166-48f1-93d8-ff217bdb0653",
				"format": "dc+sd-jwt",
				"meta": {
					"vct_values": ["test.test.email"]
				},
				"claims": [
				  {
					"path": ["email"]
				  }
				]
			  }
			]
		  }
		`,
	)
}

func irmaServerConfWithSdJwtEnabled(t *testing.T) *server.Configuration {
	certDir := t.TempDir()
	require.NoError(t, os.WriteFile(path.Join(certDir, "test.test.pem"), testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes, 0644))
	require.NoError(t, os.WriteFile(path.Join(certDir, "irma-demo.RU.pem"), testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes, 0644))
	require.NoError(t, os.WriteFile(path.Join(certDir, "irma-demo.MijnOverheid.pem"), testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes, 0644))

	privKeyDir := t.TempDir()
	require.NoError(t, os.WriteFile(path.Join(privKeyDir, "test.test.pem"), testdata.IssuerPrivKeyBytes, 0644))
	require.NoError(t, os.WriteFile(path.Join(privKeyDir, "irma-demo.RU.pem"), testdata.IssuerPrivKeyBytes, 0644))
	require.NoError(t, os.WriteFile(path.Join(privKeyDir, "irma-demo.MijnOverheid.pem"), testdata.IssuerPrivKeyBytes, 0644))

	conf := IrmaServerConfigurationWithTempStorage(t)
	conf.SdJwtIssuanceSettings = &server.SdJwtIssuanceSettings{
		SdJwtIssuerPrivKeysDir:     privKeyDir,
		SdJwtIssuerCertificatesDir: certDir,
	}
	return conf
}

func irmaServerConfWithSdJwtEnabledWithoutCerts(t *testing.T) *server.Configuration {
	certDir := t.TempDir()
	privKeyDir := t.TempDir()
	conf := IrmaServerConfigurationWithTempStorage(t)
	conf.SdJwtIssuanceSettings = &server.SdJwtIssuanceSettings{
		SdJwtIssuerPrivKeysDir:     privKeyDir,
		SdJwtIssuerCertificatesDir: certDir,
	}
	return conf
}

func findCredentialById(credentials []*clientmodels.Credential, id string) *clientmodels.Credential {
	for _, cred := range credentials {
		if cred.CredentialId == id {
			return cred
		}
	}
	return nil
}

func credentialHashByFormat(cred *clientmodels.Credential) map[clientmodels.CredentialFormat]string {
	result := map[clientmodels.CredentialFormat]string{}
	for format, hash := range cred.CredentialInstanceIds {
		result[clientmodels.CredentialFormat(format)] = hash
	}
	return result
}

func IrmaServerConfigurationWithTempStorage(t *testing.T) *server.Configuration {
	storageFolder := test.SetupTestStorage(t)
	testdataFolder := test.FindTestdataFolder(t)

	// Copy files to storage folder
	_ = common.CopyDirectory(filepath.Join(testdataFolder, "irma_configuration"), filepath.Join(storageFolder, "irma_configuration"))
	_ = common.CopyDirectory(filepath.Join(testdataFolder, "privatekeys"), filepath.Join(storageFolder, "privatekeys"))

	conf := IrmaServerConfiguration()
	conf.SchemesPath = filepath.Join(storageFolder, "irma_configuration")
	conf.IssuerPrivateKeysPath = filepath.Join(storageFolder, "privatekeys")

	return conf
}

func testOptionalEmptyAttributesExcludedFromGetCredentials(t *testing.T) {
	irmaServer := StartIrmaServer(t, irmaServerConfWithSdJwtEnabled(t))
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	c, sessionHandler := createClient(t)
	defer c.Close()

	// Issue two fullName credentials: one without and one with the optional "prefix" attribute
	reqWithoutPrefix := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Barry",
				"firstname":  "Bar",
				"familyname": "Batsbak",
			},
			SdJwtBatchSize: 10,
		},
	})
	reqWithPrefix := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Barry",
				"firstname":  "Bar",
				"familyname": "Batsbak",
				"prefix":     "Sir",
			},
			SdJwtBatchSize: 10,
		},
	})

	issue(t, irmaServer, c, sessionHandler, reqWithoutPrefix)
	awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, reqWithPrefix)
	awaitSessionState(t, sessionHandler)

	creds, err := c.GetCredentials()
	require.NoError(t, err)

	// Find both credentials and distinguish them by attribute count
	var credWithoutPrefix, credWithPrefix *clientmodels.Credential
	for _, cred := range creds {
		if cred.CredentialId != "irma-demo.MijnOverheid.fullName" {
			continue
		}
		_, hasPrefix := attributeMap(cred.Attributes)[pk("prefix")]
		if hasPrefix {
			credWithPrefix = cred
		} else {
			credWithoutPrefix = cred
		}
	}

	// Credential without prefix: optional empty attribute should be excluded
	require.NotNil(t, credWithoutPrefix)
	requireAttrsInOrder(t, credWithoutPrefix.Attributes,
		expectedAttr{
			Path:        []any{"firstnames"},
			DisplayName: &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
			Value:       strVal("Barry"),
		},
		expectedAttr{
			Path:        []any{"firstname"},
			DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"},
			Value:       strVal("Bar"),
		},
		expectedAttr{
			Path:        []any{"familyname"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
			Value:       strVal("Batsbak"),
		},
	)

	// Credential with prefix: optional non-empty attribute should be included
	require.NotNil(t, credWithPrefix)
	requireAttrsInOrder(t, credWithPrefix.Attributes,
		expectedAttr{
			Path:        []any{"firstnames"},
			DisplayName: &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
			Value:       strVal("Barry"),
		},
		expectedAttr{
			Path:        []any{"firstname"},
			DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"},
			Value:       strVal("Bar"),
		},
		expectedAttr{
			Path:        []any{"familyname"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
			Value:       strVal("Batsbak"),
		},
		expectedAttr{
			Path:        []any{"prefix"},
			DisplayName: &clientmodels.TranslatedString{"en": "Prefix", "nl": "Tussenvoegsel"},
			Value:       strVal("Sir"),
		},
	)

	// Issue a credential with an empty non-optional attribute ("firstname" = "")
	// Non-optional attributes should always be included, even when empty.
	reqEmptyNonOptional := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
			Attributes: map[string]string{
				"firstnames": "Barry",
				"firstname":  "",
				"familyname": "Batsbak",
			},
			SdJwtBatchSize: 10,
		},
	})

	issue(t, irmaServer, c, sessionHandler, reqEmptyNonOptional)
	awaitSessionState(t, sessionHandler)

	creds, err = c.GetCredentials()
	require.NoError(t, err)

	// Find the credential with empty firstname (distinct from the others by its attribute values)
	var credEmptyFirstname *clientmodels.Credential
	for _, cred := range creds {
		if cred.CredentialId != "irma-demo.MijnOverheid.fullName" {
			continue
		}
		am := attributeMap(cred.Attributes)
		if attr, ok := am[pk("firstname")]; ok && attr.Value != nil &&
			attr.Value.String != nil && *attr.Value.String == "" {
			credEmptyFirstname = cred
		}
	}

	require.NotNil(t, credEmptyFirstname, "credential with empty firstname should exist")
	requireAttrsInOrder(t, credEmptyFirstname.Attributes,
		expectedAttr{
			Path:        []any{"firstnames"},
			DisplayName: &clientmodels.TranslatedString{"en": "First names", "nl": "Voornamen"},
			Value:       strVal("Barry"),
		},
		expectedAttr{
			Path:        []any{"firstname"},
			DisplayName: &clientmodels.TranslatedString{"en": "First name", "nl": "Voornaam"},
			Value:       strVal(""),
		},
		expectedAttr{
			Path:        []any{"familyname"},
			DisplayName: &clientmodels.TranslatedString{"en": "Family name", "nl": "Achternaam"},
			Value:       strVal("Batsbak"),
		},
	)
}
