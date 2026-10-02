package sessiontest

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"image"
	_ "image/png" // register PNG decoder for requireValidImage
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	stdmdoc "github.com/privacybydesign/irmago/eudi/credentials/mdoc"
	"github.com/privacybydesign/irmago/eudi/services"
	"github.com/privacybydesign/irmago/eudi/storage"
	"github.com/privacybydesign/irmago/eudi/storage/db"
	"github.com/privacybydesign/irmago/eudi/storage/db/models"
	"github.com/privacybydesign/irmago/eudi/storage/sqlcipherstorage"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// Every snapshot since v0.19.2 comes from the same generator script, extended
// over time, so most of what one snapshot holds the next one holds too. The
// checks for those shared parts live here; each version's test calls the ones
// for what its snapshot holds, then checks what is new in it.

// The ids the snapshots stored the veramo test issuer under.
const (
	veramoIssuerDidWeb = "did:web:localhost%3A8443:test-issuer:.well-known" // up to v1.3.0
	veramoIssuerURL    = "https://localhost:8443/test-issuer"               // from v1.4.0
)

// ----------------------------------------------------------------------------
// Credentials
// ----------------------------------------------------------------------------

// requireIrmaCredentials checks the three IRMA credentials every snapshot
// keeps: fullName, singleton, and email with 8 of its 10 SD-JWT instances left
// (two were spent by OpenID4VP disclosures). firstname is fullName's firstname
// attribute, which v0.19.2 issued empty.
func requireIrmaCredentials(t *testing.T, creds []*clientmodels.Credential, firstname string) {
	t.Helper()

	fullName := findCredentialById(creds, "irma-demo.MijnOverheid.fullName")
	require.NotNil(t, fullName, "expected irma-demo.MijnOverheid.fullName")
	requireValidImage(t, fullName.Image, "fullName credential")
	requireValidImage(t, fullName.Issuer.Image, "fullName issuer")
	requireAttrsInOrder(t, fullName.Attributes,
		expectedAttr{Path: []any{"firstnames"}, DisplayName: new("First names"), Value: strVal("Barry")},
		expectedAttr{Path: []any{"firstname"}, DisplayName: new("First name"), Value: strVal(firstname)},
		expectedAttr{Path: []any{"familyname"}, DisplayName: new("Family name"), Value: strVal("Batsbak")},
		expectedAttr{Path: []any{"prefix"}, DisplayName: new("Prefix"), Value: strVal("Sir")},
	)

	singleton := findCredentialById(creds, "irma-demo.MijnOverheid.singleton")
	require.NotNil(t, singleton, "expected irma-demo.MijnOverheid.singleton")
	requireAttrsInOrder(t, singleton.Attributes,
		expectedAttr{Path: []any{"BSN"}, DisplayName: new("BSN"), Value: strVal("12345")},
	)

	email := findCredentialById(creds, "test.test.email")
	require.NotNil(t, email, "expected test.test.email")
	requireValidImage(t, email.Image, "email credential")
	requireValidImage(t, email.Issuer.Image, "email issuer")
	requireAttrsInOrder(t, email.Attributes,
		expectedAttr{Path: []any{"email"}, DisplayName: new("Email address"), Value: strVal("test@gmail.com")},
	)
	requireSdJwtInstancesRemaining(t, creds, "test.test.email", 8)
}

// requireTestCredential checks the OpenID4VCI "Test Credential (SD-JWT)" that
// every snapshot from v1.0.0 keeps, and returns it. issuerId is the id the
// snapshot stored the veramo issuer under.
func requireTestCredential(t *testing.T, creds []*clientmodels.Credential, issuerId string) *clientmodels.Credential {
	t.Helper()
	testCred := findCredentialByName(t, creds, "Test Credential (SD-JWT)")
	require.NotNil(t, testCred, "expected OpenID4VCI credential from the EUDI DB")
	requireEudiCredentialMeta(t, testCred, issuerId)
	requireAttrsInOrder(t, testCred.Attributes,
		expectedAttr{Path: []any{"given_name"}, DisplayName: new("Given Name"), Value: strVal("Test")},
		expectedAttr{Path: []any{"family_name"}, DisplayName: new("Family Name"), Value: strVal("User")},
		expectedAttr{Path: []any{"email"}, DisplayName: new("Email"), Value: strVal("test@example.com")},
	)
	return testCred
}

// requireOrganizationCredential checks the deeply nested organization
// credential that every snapshot from v1.0.0 keeps, with every nested
// attribute name and value intact.
func requireOrganizationCredential(t *testing.T, creds []*clientmodels.Credential, issuerId string) {
	t.Helper()
	org := findCredentialById(creds, "https://localhost:8443/vct/organization")
	require.NotNil(t, org, "expected deeply nested organization credential")
	requireEudiCredentialMeta(t, org, issuerId)
	requireAttrsInOrder(t, org.Attributes, expectedOrganizationAttrs()...)
}

// requireRevokedStatusListCredential checks the status-list credential that
// every snapshot from v1.3.0 keeps, and returns it. The generator revoked it
// and refreshed, so the wallet stored an INVALID status against the instances'
// status.status_list reference. Both flags are read from storage, without
// network access, so this does not depend on the status-list agent still
// serving that list and index.
func requireRevokedStatusListCredential(t *testing.T, creds []*clientmodels.Credential) *clientmodels.Credential {
	t.Helper()
	statusList := findCredentialById(creds, "https://localhost:8443/vct/statuslist")
	require.NotNil(t, statusList, "expected the revoked status-list credential")
	require.True(t, statusList.RevocationSupported,
		"a stored status.status_list reference must read back as revocation-supporting")
	require.True(t, statusList.Revoked, "the stored INVALID status must read back as revoked")
	requireAttrsInOrder(t, statusList.Attributes,
		expectedAttr{Path: []any{"given_name"}, DisplayName: new("Given Name"), Value: strVal("Test")},
		expectedAttr{Path: []any{"family_name"}, DisplayName: new("Family Name"), Value: strVal("StatusList")},
		expectedAttr{Path: []any{"email"}, DisplayName: new("Email"), Value: strVal(statusListCredentialEmail)},
	)
	return statusList
}

// requireStoredMdocDeviceKeysSign checks that every instance of the stored
// age-verification mdoc can still sign with its stored device key, and that the
// signature verifies against the device key its MSO was issued for. This is
// what a disclosure of the stored mdoc would depend on, checked without one:
// the MSO expires 90 days after the snapshot was made, and a verifier would
// then refuse it before looking at the device signature. Here the verifier's
// clock is pinned inside the MSO's validity instead.
//
// It opens a copy of the snapshot's EUDI database directly, with the same
// storage and key lookup the wallet uses when it presents an mdoc (the
// PrepareDisclosure path in mdoc_dcql), so the wallet under test is not
// touched. want is the number of instances the snapshot stored and spent is
// how many of them a disclosure used.
func requireStoredMdocDeviceKeysSign(t *testing.T, version string, want, spent int) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, storage.DbFilename)
	copyIfExists(t, filepath.Join(snapshotDir(t, version), "eudi_client_db"), dbPath)
	eudiStorage, err := sqlcipherstorage.New(testAESKey(), dbPath, dir)
	require.NoError(t, err)
	t.Cleanup(func() { _ = eudiStorage.Close() })

	batches, err := db.NewMdocStore(eudiStorage.Db()).GetBatchesByDocType(avDocType)
	require.NoError(t, err)
	require.Len(t, batches, 1)
	batch := batches[0]

	var instances []models.MdocBatchInstance
	require.NoError(t, eudiStorage.Db().Where("mdoc_batch_id = ?", batch.ID).Find(&instances).Error)
	require.Len(t, instances, want)

	binder := services.NewMdocDeviceKeyBinder(db.NewMdocDeviceKeyStore(eudiStorage.Db()))
	verifier := stdmdoc.NewVerifierWithClock([]*x509.Certificate{eudiPidIssuerPyCACert(t)},
		batch.ValidFrom.Add(batch.ValidUntil.Sub(batch.ValidFrom)/2))
	transcript := stdmdoc.SessionTranscript{Handover: []any{"storage regression", version}}

	used := 0
	for _, instance := range instances {
		if instance.Used {
			used++
		}
		var doc stdmdoc.MDoc
		require.NoError(t, stdmdoc.Unmarshal(instance.IssuerSigned, &doc))
		deviceKey, err := stdmdoc.DeviceKeyFromIssuerAuth(doc.IssuerSigned.IssuerAuth)
		require.NoError(t, err)
		signer, err := binder.SignerForDeviceKey(deviceKey)
		require.NoError(t, err, "instance %s: no stored device key for its MSO", instance.ID)
		deviceAuth, err := signer.SignDeviceAuth(batch.DocType, transcript)
		require.NoError(t, err)
		presented, err := stdmdoc.AttachDeviceSigned(&doc, deviceAuth)
		require.NoError(t, err)

		result := verifier.VerifyWithDeviceAuth(presented, avDocType, batch.DocType, transcript, deviceAuth)
		require.True(t, result.Valid, "instance %s: %s", instance.ID, result.Error)
		require.True(t, result.DeviceAuthValid, "instance %s: device signature did not verify", instance.ID)
	}
	require.Equal(t, spent, used)
}

// requireEudiCredentialMeta checks the metadata common to the snapshots'
// veramo-issued OpenID4VCI credentials.
func requireEudiCredentialMeta(t *testing.T, cred *clientmodels.Credential, issuerId string) {
	t.Helper()
	require.Equal(t, issuerId, cred.Issuer.Id)
	require.Equal(t, "Test Issuer", cred.Issuer.Name)
	require.Contains(t, cred.CredentialInstanceIds, clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc),
		"EUDI credential should have an SD-JWT instance")
	require.NotNil(t, cred.IssuanceDate, "EUDI credential should have an issuance date")
	require.False(t, cred.Revoked)
}

// requireSdJwtInstancesRemaining checks how many SD-JWT instances of a
// credential are left.
func requireSdJwtInstancesRemaining(t *testing.T, creds []*clientmodels.Credential, credID string, want uint) {
	t.Helper()
	cred := findCredentialById(creds, credID)
	require.NotNil(t, cred, "credential %s", credID)
	n := cred.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_SdJwtVc)]
	require.NotNil(t, n, "credential %s has no SD-JWT instance count", credID)
	require.Equal(t, want, *n)
}

// requireValidImage checks that the image is there and decodes as a
// non-empty raster image.
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

// ----------------------------------------------------------------------------
// Activity logs
// ----------------------------------------------------------------------------

// logSummary is the shape of a snapshot's activity log.
type logSummary struct {
	total                int
	openID4VPDisclosures int
	irmaDisclosures      int
	// newestRemovals is the number of removals at the top of the log. The
	// generator removes credentials as its last actions.
	newestRemovals int
}

// requireLogSummary checks the log's size, its newest-first order, and its mix
// of entries.
func requireLogSummary(t *testing.T, logs []clientmodels.LogInfo, want logSummary) {
	t.Helper()
	require.Len(t, logs, want.total)
	for i := 1; i < len(logs); i++ {
		require.False(t, logs[i-1].Time.Before(logs[i].Time),
			"logs must be ordered newest-first (entry %d is older than %d)", i-1, i)
	}
	requireLogTypePresent(t, logs, clientmodels.LogType_Issuance)
	requireLogTypePresent(t, logs, clientmodels.LogType_Disclosure)
	requireLogTypePresent(t, logs, clientmodels.LogType_Signature)
	require.Equal(t, want.openID4VPDisclosures, countDisclosures(logs, clientmodels.Protocol_OpenID4VP))
	require.Equal(t, want.irmaDisclosures, countDisclosures(logs, clientmodels.Protocol_Irma))
	for i := range want.newestRemovals {
		require.Equal(t, clientmodels.LogType_CredentialRemoval, logs[i].Type,
			"expected the %d newest logs to be credential removals", want.newestRemovals)
	}
}

// requireSnapshotSignatureLog checks the snapshots' one signature session: the signed
// message and the disclosed email attribute.
func requireSnapshotSignatureLog(t *testing.T, logs []clientmodels.LogInfo) {
	t.Helper()
	sig := findLog(logs, clientmodels.LogType_Signature)
	require.NotNil(t, sig)
	require.NotNil(t, sig.SignedMessageLog)
	require.Equal(t, "Hello, World!", sig.SignedMessageLog.Message)
	require.Len(t, sig.SignedMessageLog.Credentials, 1)
	require.Equal(t, "test.test.email", sig.SignedMessageLog.Credentials[0].CredentialId)
	requireValidImage(t, sig.SignedMessageLog.Credentials[0].Image, "signature log email")
	requireAttrsInOrder(t, sig.SignedMessageLog.Credentials[0].Attributes,
		expectedAttr{Path: []any{"email"}, DisplayName: new("Email address"), Value: strVal("test@gmail.com")})
}

// requireMultiCredentialDisclosureLog checks the IRMA disclosure that spans
// fullName, singleton and studentCard (from v1.0.0).
func requireMultiCredentialDisclosureLog(t *testing.T, logs []clientmodels.LogInfo) {
	t.Helper()
	var disclosure *clientmodels.DisclosureLog
	for _, log := range logs {
		if log.Type == clientmodels.LogType_Disclosure && log.DisclosureLog != nil && len(log.DisclosureLog.Credentials) > 1 {
			disclosure = log.DisclosureLog
			break
		}
	}
	require.NotNil(t, disclosure, "expected a disclosure log spanning multiple credentials")
	require.Equal(t, clientmodels.Protocol_Irma, disclosure.Protocol)
	require.Len(t, disclosure.Credentials, 3)

	fullName := findLogCredential(t, disclosure.Credentials, "irma-demo.MijnOverheid.fullName")
	requireValidImage(t, fullName.Image, "disclosure log fullName")
	requireAttrsInOrder(t, fullName.Attributes,
		expectedAttr{Path: []any{"familyname"}, DisplayName: new("Family name"), Value: strVal("Batsbak")})

	singleton := findLogCredential(t, disclosure.Credentials, "irma-demo.MijnOverheid.singleton")
	requireValidImage(t, singleton.Image, "disclosure log singleton")
	requireAttrsInOrder(t, singleton.Attributes,
		expectedAttr{Path: []any{"BSN"}, DisplayName: new("BSN"), Value: strVal("12345")})

	studentCard := findLogCredential(t, disclosure.Credentials, "irma-demo.RU.studentCard")
	requireValidImage(t, studentCard.Image, "disclosure log studentCard")
	requireAttrsInOrder(t, studentCard.Attributes,
		expectedAttr{Path: []any{"university"}, DisplayName: new("University"), Value: strVal("University of the Arts")})
}

// requireEudiDisclosureLog checks the OpenID4VP disclosure of the "Test
// Credential (SD-JWT)" given_name and email claims (from v1.0.0): its
// credential name, issuer name, attribute names and values.
func requireEudiDisclosureLog(t *testing.T, logs []clientmodels.LogInfo) {
	t.Helper()
	var disclosure *clientmodels.DisclosureLog
	for _, log := range logs {
		if log.Type == clientmodels.LogType_Disclosure && log.DisclosureLog != nil &&
			len(log.DisclosureLog.Credentials) == 1 &&
			log.DisclosureLog.Credentials[0].CredentialId == "https://localhost:8443/vct/test" {
			disclosure = log.DisclosureLog
			break
		}
	}
	require.NotNil(t, disclosure, "expected an OpenID4VP disclosure log of the EUDI credential")
	require.Equal(t, "Test Credential (SD-JWT)", disclosure.Credentials[0].Name)
	require.Equal(t, "Test Issuer", disclosure.Credentials[0].Issuer.Name)
	requireAttrsInOrder(t, disclosure.Credentials[0].Attributes,
		expectedAttr{Path: []any{"given_name"}, DisplayName: new("Given Name"), Value: strVal("Test")},
		expectedAttr{Path: []any{"email"}, DisplayName: new("Email"), Value: strVal("test@example.com")},
	)
}

// requireRemovals checks that the removal logs name exactly the removed
// credentials, counted by id. A removed EUDI credential's removal log keeps
// its name, although the credential itself is gone.
func requireRemovals(t *testing.T, logs []clientmodels.LogInfo, want map[string]int) {
	t.Helper()
	removed := map[string]int{}
	for _, log := range logs {
		if log.Type != clientmodels.LogType_CredentialRemoval {
			continue
		}
		require.NotNil(t, log.RemovalLog)
		require.Len(t, log.RemovalLog.Credentials, 1)
		cred := log.RemovalLog.Credentials[0]
		removed[cred.CredentialId]++
		if cred.CredentialId == "https://localhost:8443/vct/test" {
			require.Equal(t, "Test Credential (SD-JWT)", cred.Name,
				"a removed EUDI credential's name must survive in its removal log")
		}
	}
	require.Equal(t, want, removed)
}

// requireOpenID4VCIIssuances checks which credentials the OpenID4VCI issuance
// logs name, counted by id. From v1.3.0 an issuance log names the vct (or
// docType) it issued; older snapshots stored a placeholder there.
func requireOpenID4VCIIssuances(t *testing.T, logs []clientmodels.LogInfo, want map[string]int) {
	t.Helper()
	issued := map[string]int{}
	for _, log := range logs {
		if log.Type != clientmodels.LogType_Issuance || log.IssuanceLog == nil ||
			log.IssuanceLog.Protocol != clientmodels.Protocol_OpenID4VCI {
			continue
		}
		for _, cred := range log.IssuanceLog.Credentials {
			issued[cred.CredentialId]++
		}
	}
	require.Equal(t, want, issued, "OpenID4VCI issuance logs must record the issued credential's id")
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

func requireLogTypePresent(t *testing.T, logs []clientmodels.LogInfo, logType clientmodels.LogType) {
	t.Helper()
	for _, log := range logs {
		if log.Type == logType {
			return
		}
	}
	require.Failf(t, "log type not found", "expected log type %s", logType)
}

// ----------------------------------------------------------------------------
// Fresh sessions after loading
// ----------------------------------------------------------------------------

// assertLoadedClientUsable checks that a wallet loaded from a snapshot can
// still run fresh sessions of every kind. It is the same for every version.
func assertLoadedClientUsable(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	t.Helper()
	assertFreshIrmaSessionsWork(t, c, sessionHandler, irmaServer)
	assertFreshOpenID4VCISessionsWork(t, c, sessionHandler)
	assertStatusListSessionsWork(t, c, sessionHandler)
	assertFreshMdocSessionsWork(t, c, sessionHandler)
}

// assertFreshIrmaSessionsWork runs non-keyshare and keyshare disclosures and an
// OpenID4VP disclosure of an IRMA-issued SD-JWT (served from bbolt), then a
// fresh IRMA issuance. The disclosures come first, while the stored
// credentials are the only candidates, so they prove the stored signatures and
// keys still work.
func assertFreshIrmaSessionsWork(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	t.Helper()

	performStoredDisclosureSession(t, c, 1, sessionHandler, irmaServer, "irma-demo.MijnOverheid.fullName.familyname", false)
	performStoredDisclosureSession(t, c, 2, sessionHandler, irmaServer, "test.test.email.email", true)
	replaceExpiredEmailSdJwts(t, c, sessionHandler, irmaServer)
	discloseOverOpenID4VP(t, c, 3, sessionHandler, testdata.OpenID4VP_DirectPost_Host)

	issue(t, irmaServer, c, sessionHandler, 4, createMijnOverheidIssuanceRequest())
	issued := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, issued.Status)
}

// replaceExpiredEmailSdJwts swaps the stored test.test.email credential for a
// fresh one when its SD-JWTs have expired or are about to. An IRMA-issued
// SD-JWT carries the IRMA credential's expiry as exp, and the OpenID4VP
// verifier rejects it after that, with no way to skip the check. Snapshots up
// to v1.4.0 were made with IRMA's default validity of 6 months, so theirs run
// out; later ones are issued with a long validity (see withSnapshotValidity).
// Once a snapshot falls back, its stored SD-JWT keys are no longer disclosed.
func replaceExpiredEmailSdJwts(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler, irmaServer *IrmaServer) {
	t.Helper()
	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	email := findCredentialById(creds, "test.test.email")
	require.NotNil(t, email, "expected test.test.email")
	require.NotNil(t, email.ExpiryDate, "test.test.email should have an expiry date")

	// A day of margin, so a run close to the expiry does not fail on it.
	expiry := time.Unix(*email.ExpiryDate, 0)
	if expiry.After(time.Now().AddDate(0, 0, 1)) {
		return
	}
	t.Logf("stored test.test.email SD-JWTs expire %s; disclosing fresh ones over OpenID4VP", expiry.Format(time.DateOnly))
	require.NoError(t, c.RemoveCredentialsByHash(email.CredentialInstanceIds))
	issue(t, irmaServer, c, sessionHandler, 21, createIrmaIssuanceRequestWithSdJwts("test.test.email", "email"))
	issued := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, issued.Status, "session error: %+v", issued.Error)
}

// assertStoredTestCredentialDisclosable discloses the stored "Test Credential
// (SD-JWT)" over OpenID4VP (veramo verifier), which signs with its stored
// holder-binding key. Call it before assertLoadedClientUsable: that issues a
// second credential of the same vct, and then either could be disclosed.
func assertStoredTestCredentialDisclosable(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler) {
	t.Helper()
	session := awaitDisclosurePermission(t, c, 20, sessionHandler, `{
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
	options := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.Len(t, options, 1, "the stored credential should be the only candidate")
	require.Len(t, options[0].Credentials, 1)
	requireAttrsInOrder(t, options[0].Credentials[0].Attributes,
		expectedAttr{Path: []any{"email"}, DisplayName: new("Email"), Value: strVal("test@example.com")})

	grantPermission(t, c, session.Id, makeDisclosureChoice(options[0]))
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

// assertFreshOpenID4VCISessionsWork runs a fresh OpenID4VCI issuance (veramo
// issuer) and an OpenID4VP disclosure of that credential (veramo verifier).
func assertFreshOpenID4VCISessionsWork(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler) {
	t.Helper()

	issueCredentialViaOpenID4VCI(t, c, 5, sessionHandler, "TestCredentialSdJwt",
		`{"given_name": "Reload", "family_name": "Check", "email": "reload@example.com"}`)

	session := discloseViaVeramoOpenID4VP(t, c, 6, sessionHandler, `{
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
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

// assertStatusListSessionsWork issues a status-list SD-JWT and discloses it
// twice over OpenID4VP: once while valid, which succeeds, and once after
// revocation. The wallet does not refuse a revoked credential at disclosure
// (matching IRMA); it marks it on the disclosure plan, so the revoked run
// checks the plan's Revoked flag rather than the session outcome.
func assertStatusListSessionsWork(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler) {
	t.Helper()

	issueStatusListCredential(t, c, sessionHandler, 7)

	statusListDcql := `{
		"dcql": {
			"credentials": [
				{
					"id": "statuslist-cred",
					"format": "dc+sd-jwt",
					"meta": { "vct_values": ["https://localhost:8443/vct/statuslist"] },
					"claims": [ { "path": ["email"] } ]
				}
			]
		}
	}`

	valid := discloseViaVeramoOpenID4VP(t, c, 8, sessionHandler, statusListDcql)
	require.Equal(t, clientmodels.Status_Success, valid.Status)

	revokeStatusListCredentialViaVeramo(t, statusListCredentialEmail)
	require.NoError(t, c.RefreshStatuses(context.Background()))

	revoked := awaitDisclosurePermission(t, c, 9, sessionHandler, statusListDcql)
	revokedCred := revoked.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0].Credentials[0]
	require.True(t, revokedCred.Revoked,
		"a revoked status-list credential must be surfaced as Revoked on the disclosure plan")
}

// assertFreshMdocSessionsWork issues an age-verification mdoc from the Python
// PID issuer and discloses it to the EUDI reference verifier, which checks the
// issuer and device signatures.
func assertFreshMdocSessionsWork(t *testing.T, c *client.Client, sessionHandler *MockSessionHandler) {
	t.Helper()
	issueAvMdocViaPythonIssuer(t, c, 10, sessionHandler)
	discloseAvMdocOnce(t, c, sessionHandler, 11)
}

// discloseViaVeramoOpenID4VP runs a full OpenID4VP disclosure against the
// veramo verifier for the given DCQL query, granting the first owned option,
// and returns the final session state.
func discloseViaVeramoOpenID4VP(t *testing.T, c *client.Client, sessionId int, sessionHandler *MockSessionHandler, dcql string) clientmodels.SessionState {
	t.Helper()
	session := awaitDisclosurePermission(t, c, sessionId, sessionHandler, dcql)
	grantPermission(t, c, session.Id, makeDisclosureChoice(session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions[0]))
	return awaitSessionState(t, sessionHandler)
}

// awaitDisclosurePermission starts an OpenID4VP disclosure against the veramo
// verifier and returns the session once it asks for permission, without
// granting it, so the caller can inspect the disclosure plan.
func awaitDisclosurePermission(t *testing.T, c *client.Client, sessionId int, sessionHandler *MockSessionHandler, dcql string) clientmodels.SessionState {
	t.Helper()
	verifierSession := createVeramoVerifierDcqlSessionWithQuery(t, dcql)
	startOpenID4VPDisclosureSession(t, c, sessionId, verifierSession.RequestUri)
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	return session
}

// performDisclosureSessionForAttribute performs an IRMA disclosure of a non-keyshare attribute.
func performDisclosureSessionForAttribute(t *testing.T, c *client.Client, sessionId int, sessionHandler *MockSessionHandler, irmaServer *IrmaServer, attribute string) {
	t.Helper()
	performIrmaDisclosure(t, c, sessionId, sessionHandler, irmaServer, attributeDisclosureRequest(attribute), false)
}

// performStoredDisclosureSession performs an IRMA disclosure of an attribute
// from a credential stored in a snapshot. A snapshot's IRMA credentials expire
// some months after it was made, so the request skips the expiry check: what
// is tested is that the stored signature and keys still produce a valid proof.
// keyshare says whether the attribute is keyshare-protected.
func performStoredDisclosureSession(t *testing.T, c *client.Client, sessionId int, sessionHandler *MockSessionHandler, irmaServer *IrmaServer, attribute string, keyshare bool) {
	t.Helper()
	req := attributeDisclosureRequest(attribute)
	req.SkipExpiryCheck = []irma.CredentialTypeIdentifier{irma.NewAttributeTypeIdentifier(attribute).CredentialTypeIdentifier()}
	performIrmaDisclosure(t, c, sessionId, sessionHandler, irmaServer, req, keyshare)
}

func attributeDisclosureRequest(attribute string) *irma.DisclosureRequest {
	req := irma.NewDisclosureRequest()
	req.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest(attribute),
			},
		},
	}
	return req
}

// performIrmaDisclosure runs an IRMA disclosure of a single attribute that one
// credential holds. For a keyshare-protected attribute it enters the PIN: a
// reloaded client has no keyshare auth token cached, so a PIN is requested.
func performIrmaDisclosure(t *testing.T, c *client.Client, sessionId int, sessionHandler *MockSessionHandler, irmaServer *IrmaServer, req *irma.DisclosureRequest, keyshare bool) {
	t.Helper()
	c.NewSession(sessionId, startSameDeviceIrmaSessionAtServer(t, irmaServer, req))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	options := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.Len(t, options, 1, "expected exactly one candidate credential")
	grantPermission(t, c, session.Id, makeDisclosureChoice(options[0]))

	if keyshare {
		session = awaitSessionState(t, sessionHandler)
		require.Equal(t, clientmodels.Status_RequestPin, session.Status)
		userInteraction(t, c, clientmodels.SessionUserInteraction{
			SessionId: session.Id,
			Type:      clientmodels.UI_EnteredPin,
			Payload:   clientmodels.PinInteractionPayload{Pin: "12345", Proceed: true},
		})
	}

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status, "session error: %+v", session.Error)
}
