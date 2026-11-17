package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/credentials/statuslist"
	"github.com/privacybydesign/irmago/eudi/credentials/vcdm"
	"github.com/stretchr/testify/require"
)

// The storage regression tests load a wallet from the storage snapshot of an
// older version (see storage_snapshot_test.go) and check that current code
// still reads everything in it and can still run sessions. There is one test
// per snapshot version. The checks shared between versions are in
// storage_regression_helpers_test.go, so each test here shows what its
// snapshot holds and what is new in it.

// TestClientStorageRegressionV0_19_2 checks a snapshot from before the EUDI
// database existed: bbolt only, no OpenID4VCI credentials, no removals.
func TestClientStorageRegressionV0_19_2(t *testing.T) {
	c, sessionHandler, irmaServer := setupStorageRegressionClient(t, "v0.19.2")

	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	requireIrmaCredentials(t, creds, "")

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	requireLogSummary(t, logs, logSummary{total: 8, openID4VPDisclosures: 2, irmaDisclosures: 1})
	requireSnapshotSignatureLog(t, logs)

	// Every disclosure in this snapshot disclosed the email attribute.
	disclosures := 0
	for _, log := range logs {
		if log.Type != clientmodels.LogType_Disclosure {
			continue
		}
		require.NotNil(t, log.DisclosureLog)
		require.Len(t, log.DisclosureLog.Credentials, 1)
		require.Equal(t, "test.test.email", log.DisclosureLog.Credentials[0].CredentialId)
		requireValidImage(t, log.DisclosureLog.Credentials[0].Image, "disclosure log email")
		requireAttrsInOrder(t, log.DisclosureLog.Credentials[0].Attributes,
			expectedAttr{Path: []any{"email"}, DisplayName: new("Email address"), Value: strVal("test@gmail.com")})
		disclosures++
	}
	require.Equal(t, 3, disclosures)

	assertLoadedClientUsable(t, c, sessionHandler, irmaServer)
}

// TestClientStorageRegressionV1_0_0 checks the first snapshot with the EUDI
// database: OpenID4VCI credentials (one deeply nested), a multi-credential
// disclosure, OpenID4VP disclosures of EUDI credentials, and removals.
//
// Its EUDI database is plaintext; loading it encrypts it in place. Its EUDI
// log rows store translation maps rather than resolved text, so this test
// covers the legacy decode path.
func TestClientStorageRegressionV1_0_0(t *testing.T) {
	c, sessionHandler, irmaServer := setupStorageRegressionClient(t, "v1.0.0")

	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	requireIrmaCredentials(t, creds, "Bar")
	requireTestCredential(t, creds, veramoIssuerDidWeb)
	requireOrganizationCredential(t, creds, veramoIssuerDidWeb)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	requireLogSummary(t, logs, logSummary{total: 21, openID4VPDisclosures: 4, irmaDisclosures: 4, newestRemovals: 3})
	requireMultiCredentialDisclosureLog(t, logs)
	requireSnapshotSignatureLog(t, logs)
	requireRemovals(t, logs, map[string]int{
		"https://localhost:8443/vct/test": 2,
		"irma-demo.RU.studentCard":        1,
	})
	requireEudiDisclosureLog(t, logs)

	assertStoredTestCredentialDisclosable(t, c, sessionHandler)
	assertLoadedClientUsable(t, c, sessionHandler, irmaServer)
}

// TestClientStorageRegressionV1_1_1 checks the first snapshot whose EUDI
// database was encrypted when it was created (the v1.1.1 fix), so loading it
// uses the normal encrypted read path. It comes from the same generator script
// as v1.0.0, so the log content checks are left to that test.
func TestClientStorageRegressionV1_1_1(t *testing.T) {
	c, sessionHandler, irmaServer := setupStorageRegressionClient(t, "v1.1.1")

	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	requireIrmaCredentials(t, creds, "Bar")
	requireTestCredential(t, creds, veramoIssuerDidWeb)
	requireOrganizationCredential(t, creds, veramoIssuerDidWeb)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	requireLogSummary(t, logs, logSummary{total: 21, openID4VPDisclosures: 4, irmaDisclosures: 4, newestRemovals: 3})

	assertStoredTestCredentialDisclosable(t, c, sessionHandler)
	assertLoadedClientUsable(t, c, sessionHandler, irmaServer)
}

// TestClientStorageRegressionV1_3_0 checks the first snapshot written by the
// locale-aware wallet. New in it:
//
//   - EUDI log rows store text already resolved to a locale, where older
//     snapshots stored translation maps.
//   - OpenID4VCI issuance logs name the vct they issued, where older snapshots
//     stored a placeholder.
//   - A status-list credential, stored as revoked.
func TestClientStorageRegressionV1_3_0(t *testing.T) {
	c, sessionHandler, irmaServer := setupStorageRegressionClient(t, "v1.3.0")

	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	requireIrmaCredentials(t, creds, "Bar")
	testCred := requireTestCredential(t, creds, veramoIssuerDidWeb)
	requireOrganizationCredential(t, creds, veramoIssuerDidWeb)
	statusList := requireRevokedStatusListCredential(t, creds)

	// The contrast that gives the status-list flags their meaning: a credential
	// with no status reference is not revocation-supporting.
	require.False(t, testCred.RevocationSupported,
		"a credential without a status reference must not read back as revocation-supporting")

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	requireLogSummary(t, logs, logSummary{total: 22, openID4VPDisclosures: 4, irmaDisclosures: 4, newestRemovals: 3})
	requireOpenID4VCIIssuances(t, logs, map[string]int{
		"https://localhost:8443/vct/test":         3,
		"https://localhost:8443/vct/organization": 1,
		"https://localhost:8443/vct/statuslist":   1,
	})
	requireMultiCredentialDisclosureLog(t, logs)
	requireSnapshotSignatureLog(t, logs)
	requireRemovals(t, logs, map[string]int{
		"https://localhost:8443/vct/test": 2,
		"irma-demo.RU.studentCard":        1,
	})
	requireEudiDisclosureLog(t, logs)

	// The fresh status-list session below expects to disclose a valid
	// credential; the stored revoked one would be a second candidate.
	require.NoError(t, c.RemoveCredentialsByHash(statusList.CredentialInstanceIds))

	assertStoredTestCredentialDisclosable(t, c, sessionHandler)
	assertLoadedClientUsable(t, c, sessionHandler, irmaServer)
}

// TestClientStorageRegressionV1_4_0 checks the first snapshot with an mdoc: an
// age-verification mdoc (docType eu.europa.ec.av.1) issued by the Python PID
// issuer, with one of its 30 instances spent by a disclosure. New in it:
//
//   - The mdoc, in its own tables, with its issuance and disclosure logs.
//   - The EUDI logo files, so logos stored by an older version are checked.
//   - The veramo issuer is stored under its URL rather than a did:web id.
//
// The stored mdoc is not disclosed again: it is valid for 90 days from when
// the snapshot was made, so that would start failing on its own. Instead its
// stored device keys sign, and are verified, with the verifier's clock inside
// that validity. The fresh mdoc session in assertLoadedClientUsable covers the
// rest of disclosure.
func TestClientStorageRegressionV1_4_0(t *testing.T) {
	c, sessionHandler, irmaServer := setupStorageRegressionClient(t, "v1.4.0")

	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	requireIrmaCredentials(t, creds, "Bar")
	requireTestCredential(t, creds, veramoIssuerURL)
	requireOrganizationCredential(t, creds, veramoIssuerURL)
	statusList := requireRevokedStatusListCredential(t, creds)

	mdoc := findMdocCredentialByDocType(t, creds, avDocType)
	require.Equal(t, avCredentialDisplayName, mdoc.Name)
	require.Equal(t, "https://localhost:8443/eudi-pid-issuer-py", mdoc.Issuer.Id)
	require.Equal(t, avIssuerDisplayName, mdoc.Issuer.Name)
	require.True(t, mdoc.Issuer.Verified, "the document signer chain verified at issuance")
	require.Contains(t, mdoc.CredentialInstanceIds, clientmodels.CredentialFormat(clientmodels.Format_MsoMdoc))
	require.NotNil(t, mdoc.IssuanceDate)
	require.Equal(t, avMdocIssuanceDate, *mdoc.IssuanceDate)
	require.NotNil(t, mdoc.ExpiryDate)
	require.Equal(t, avMdocExpiryDate, *mdoc.ExpiryDate)
	require.False(t, mdoc.Revoked)
	require.False(t, mdoc.RevocationSupported, "the mdoc path has no status mechanism")
	requireAttrsInOrder(t, mdoc.Attributes, avAttrAgeOver18())

	// 30 issued, one spent: a spent instance stays spent after a reload.
	remaining := mdoc.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_MsoMdoc)]
	require.NotNil(t, remaining, "a batched mdoc credential must carry a remaining count")
	require.Equal(t, uint(29), *remaining)
	requireStoredMdocDeviceKeysSign(t, "v1.4.0", avDocType, 30, 1)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	requireLogSummary(t, logs, logSummary{total: 24, openID4VPDisclosures: 5, irmaDisclosures: 4, newestRemovals: 3})
	requireOpenID4VCIIssuances(t, logs, map[string]int{
		"https://localhost:8443/vct/test":         3,
		"https://localhost:8443/vct/organization": 1,
		"https://localhost:8443/vct/statuslist":   1,
		avDocType:                                 1,
	})
	requireMultiCredentialDisclosureLog(t, logs)
	requireSnapshotSignatureLog(t, logs)
	requireRemovals(t, logs, map[string]int{
		"https://localhost:8443/vct/test": 2,
		"irma-demo.RU.studentCard":        1,
	})
	requireEudiDisclosureLog(t, logs)

	// The mdoc disclosure was the last session before the three removals.
	mdocDisclosure := logs[3].DisclosureLog
	require.NotNil(t, mdocDisclosure)
	require.Equal(t, clientmodels.Protocol_OpenID4VP, mdocDisclosure.Protocol)
	require.Len(t, mdocDisclosure.Credentials, 1)
	requireLogCredential(t, mdocDisclosure.Credentials[0], storedAvLogCredential(), "mdoc disclosure log")

	var mdocIssuance *clientmodels.LogCredential
	for _, log := range logs {
		if log.IssuanceLog != nil && len(log.IssuanceLog.Credentials) == 1 &&
			log.IssuanceLog.Credentials[0].CredentialId == avDocType {
			mdocIssuance = &log.IssuanceLog.Credentials[0]
		}
	}
	require.NotNil(t, mdocIssuance, "expected the mdoc issuance log")
	requireLogCredential(t, *mdocIssuance, storedAvLogCredential(), "mdoc issuance log")

	// EUDI logos stored by the generator still load. Log entries are checked
	// rather than credentials on purpose: a missing credential logo is
	// downloaded again at startup, which would hide a broken logo store, while
	// a log entry's logo cannot be fetched again.
	requireValidImage(t, mdocDisclosure.Credentials[0].Image, "mdoc disclosure log credential")
	require.NotNil(t, mdocDisclosure.Verifier)
	requireValidImage(t, mdocDisclosure.Verifier.Image, "mdoc disclosure log verifier")
	for i := range 2 {
		removed := logs[i].RemovalLog.Credentials[0]
		require.Equal(t, "https://localhost:8443/vct/test", removed.CredentialId)
		requireValidImage(t, removed.Issuer.Image, "removed EUDI credential's issuer")
	}

	// The fresh sessions below expect to disclose the credentials they issue
	// themselves. The stored revoked status-list credential and the stored
	// mdoc (which expires) would be second candidates.
	require.NoError(t, c.RemoveCredentialsByHash(statusList.CredentialInstanceIds))
	require.NoError(t, c.RemoveCredentialsByHash(mdoc.CredentialInstanceIds))

	assertStoredTestCredentialDisclosable(t, c, sessionHandler)
	assertLoadedClientUsable(t, c, sessionHandler, irmaServer)
}

// The validity dates in the v1.4.0 snapshot's mdoc: issued 2026-09-23, valid
// 90 days.
const (
	avMdocIssuanceDate int64 = 1790121600
	avMdocExpiryDate   int64 = 1797897600
)

// storedAvLogCredential is the age credential as a v1.4.0 snapshot log entry
// reads back. Its issuer publishes no logo.
func storedAvLogCredential() expectedLogCredential {
	expected := avLogCredential(avAttrAgeOver18())
	expected.HasIssuerImage = new(false)
	expected.IssuanceDate = new(avMdocIssuanceDate)
	expected.ExpiryDate = new(avMdocExpiryDate)
	return expected
}

// TestClientStorageRegressionV1_5_0 checks the first snapshot that holds
// SD-JWT-secured VCDM credentials. New in it:
//
//   - VCDM credentials in their own tables (vcdm_batches, vcdm_batch_instances),
//     with their holder binding keys in the table they share with SD-JWT VC.
//   - A VCDM credential stored as revoked through a W3C Bitstring Status List.
//   - An Open Badges credential whose claim images are stored next to the logos,
//     and whose type was expanded from a context the wallet can no longer fetch.
//   - VCDM issuance, disclosure and removal log entries.
//   - An mdoc with a Token Status List reference on every instance, stored as
//     revoked, and its Status List Token cached as a CWT.
//
// The database was written before 1.6.0 pinned the SQLCipher parameters, so
// loading it also covers that upgrade.
func TestClientStorageRegressionV1_5_0(t *testing.T) {
	c, sessionHandler, irmaServer := setupStorageRegressionClient(t, "v1.5.0")

	creds, _, err := c.GetCredentials()
	require.NoError(t, err)
	requireIrmaCredentials(t, creds, "Bar")
	requireTestCredential(t, creds, veramoIssuerURL)
	requireOrganizationCredential(t, creds, veramoIssuerURL)
	statusList := requireRevokedStatusListCredential(t, creds)

	mdoc := findMdocCredentialByDocType(t, creds, avDocType)
	require.False(t, mdoc.Revoked)
	remaining := mdoc.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_MsoMdoc)]
	require.NotNil(t, remaining)
	require.Equal(t, uint(29), *remaining)
	requireStoredMdocDeviceKeysSign(t, "v1.5.0", avDocType, 30, 1)

	// The PID mdoc: every instance names its own Token Status List entry, served
	// as a CWT. The generator revoked them all and refreshed. The status list
	// server is not running now, so both flags come from storage.
	pid := findMdocCredentialByDocType(t, creds, pidMdocDocType)
	require.True(t, pid.RevocationSupported, "a stored status reference must read back as revocation-supporting")
	require.True(t, pid.Revoked, "the stored revoked status must read back as revoked")
	pidRemaining := pid.BatchInstanceCountsRemaining[clientmodels.CredentialFormat(clientmodels.Format_MsoMdoc)]
	require.NotNil(t, pidRemaining)
	requireStoredMdocStatusReferences(t, "v1.5.0", pidMdocDocType, int(*pidRemaining), statuslist.StatusInvalid)
	requireStoredMdocDeviceKeysSign(t, "v1.5.0", pidMdocDocType, int(*pidRemaining), 0)

	// The VCDM credentials: Vera's, and the revoked status-list one. Both
	// share a type identity; their email tells them apart.
	vera := requireStoredVcdmCredential(t, creds, "vera@example.com")
	requireVcdmTestAttrs(t, vera.Attributes, "Vera", "Modell", "vera@example.com")
	require.False(t, vera.Revoked)
	require.False(t, vera.RevocationSupported, "Vera's credential names no status")

	vcdmStatusList := requireStoredVcdmCredential(t, creds, vcdmStatusListEmail)
	requireVcdmTestAttrs(t, vcdmStatusList.Attributes, "Vera", "StatusList", vcdmStatusListEmail)
	require.True(t, vcdmStatusList.RevocationSupported,
		"a stored Bitstring Status List entry must read back as revocation-supporting")
	require.True(t, vcdmStatusList.Revoked, "the stored revoked status must read back as revoked")

	// The Open Badge's claim images come from the image store: the server
	// that served them at issuance is not running.
	badge := findCredentialById(creds, openBadgeCredentialId)
	require.NotNil(t, badge, "expected the Open Badges credential")
	require.Equal(t, openBadgeCredentialName, badge.Name)
	requireOpenBadgeImages(t, badge.Attributes)

	logs, err := c.LoadNewestLogs(100)
	require.NoError(t, err)
	requireLogSummary(t, logs, logSummary{total: 32, openID4VPDisclosures: 7, irmaDisclosures: 4, newestRemovals: 4})
	requireOpenID4VCIIssuances(t, logs, map[string]int{
		"https://localhost:8443/vct/test":         3,
		"https://localhost:8443/vct/organization": 1,
		"https://localhost:8443/vct/statuslist":   1,
		avDocType:                                 1,
		pidMdocDocType:                            1,
		vcdmCredentialId:                          3,
		openBadgeCredentialId:                     1,
	})
	requireMultiCredentialDisclosureLog(t, logs)
	requireSnapshotSignatureLog(t, logs)
	requireRemovals(t, logs, map[string]int{
		"https://localhost:8443/vct/test": 2,
		"irma-demo.RU.studentCard":        1,
		vcdmCredentialId:                  1,
	})
	requireEudiDisclosureLog(t, logs)

	// The VCDM disclosure log. Its issuer logo is stored; it cannot be
	// fetched again.
	veraLogged := newestDisclosureLogCredential(t, c, vcdmCredentialId)
	requireAttrsInOrder(t, veraLogged.Attributes,
		vcdmTestExpectedAttrs("Vera", "Modell", "vera@example.com", vcdmHolderDid(t, vera.Attributes))...)
	requireValidImage(t, veraLogged.Issuer.Image, "VCDM disclosure log issuer")

	// The Open Badge disclosure log keeps its pictures. Its issuer image is
	// only checked to load: a log entry stores it under the issuer id, which
	// Vera's credential shares, so the later VCDM removal log replaced the
	// badge's own issuer image with the issuer metadata's logo.
	badgeLogged := newestDisclosureLogCredential(t, c, openBadgeCredentialId)
	requireOpenBadgeImages(t, badgeLogged.Attributes)
	require.NotNil(t, badgeLogged.Image)
	require.NotNil(t, badgeLogged.Image.MimeType)
	require.Equal(t, clientmodels.MimeTypeSVG, *badgeLogged.Image.MimeType, "the badge's own image")
	requireValidImage(t, badgeLogged.Issuer.Image, "Open Badge disclosure log issuer")

	// A DCQL type_values query still finds the Open Badge. Its types were
	// expanded at issuance from a context that cannot be fetched now, so this
	// reads the stored expanded types. The plan is all this needs; dismiss it.
	session := awaitDisclosurePermission(t, c, 30, sessionHandler, vcdmDcqlQuery(
		`"meta": {"type_values": [["`+vcdmVerifiableCredentialIri+`", "`+vcdm.OpenBadgeCredentialType+`"]]}`,
		[]any{"credentialSubject", "photo"},
	))
	options := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.Len(t, options, 1, "the stored Open Badge should be the only candidate")
	require.Equal(t, openBadgeCredentialId, options[0].Credentials[0].CredentialId)
	userInteraction(t, c, clientmodels.SessionUserInteraction{SessionId: session.Id, Type: clientmodels.UI_DismissSession})
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Dismissed, session.Status)

	// Vera's credential is still disclosable: the verifier checks the
	// presentation's signature, made with the stored holder binding key.
	discloseVcdmToVeramo(t, c, sessionHandler, 31, vcdmDcqlQuery(
		`"meta": {"type_values": [["`+vcdmVerifiableCredentialIri+`", "`+vcdmCredentialType+`"]]}`,
		[]any{"credentialSubject", "email"},
	), func(cred *clientmodels.SelectableCredentialInstance) bool {
		return vcdmSubjectValue(cred.Attributes, "email") == "vera@example.com"
	})

	// The fresh sessions below expect to disclose the credentials they issue
	// themselves; these stored ones would be second candidates.
	require.NoError(t, c.RemoveCredentialsByHash(statusList.CredentialInstanceIds))
	require.NoError(t, c.RemoveCredentialsByHash(mdoc.CredentialInstanceIds))

	assertStoredTestCredentialDisclosable(t, c, sessionHandler)
	assertLoadedClientUsable(t, c, sessionHandler, irmaServer)
}

// openBadgeCredentialId is the @context+type identity the Open Badges test
// credential is stored under.
const openBadgeCredentialId = "https://www.w3.org/ns/credentials/v2 " + claimImagesPublicURL +
	"/context.json VerifiableCredential OpenBadgeCredential"

// requireStoredVcdmCredential returns the one stored TestVcdmCredential whose
// credentialSubject.email is email, after checking what all of them share.
func requireStoredVcdmCredential(t *testing.T, creds []*clientmodels.Credential, email string) *clientmodels.Credential {
	t.Helper()
	var found *clientmodels.Credential
	for _, cred := range creds {
		if cred.CredentialId == vcdmCredentialId && vcdmSubjectValue(cred.Attributes, "email") == email {
			require.Nil(t, found, "more than one VCDM credential with email %s", email)
			found = cred
		}
	}
	require.NotNil(t, found, "expected the VCDM credential with email %s", email)
	require.Equal(t, vcdmCredentialName, found.Name)
	require.Equal(t, veramoIssuerURL, found.Issuer.Id)
	require.Equal(t, "Test Issuer", found.Issuer.Name)
	require.True(t, found.Issuer.Verified)
	require.Contains(t, found.CredentialInstanceIds, clientmodels.CredentialFormat(clientmodels.Format_SdJwtVcdm))
	require.NotNil(t, found.IssuanceDate)
	require.Nil(t, found.ExpiryDate, "veramo issues the VCDM test credential without validUntil")
	return found
}
