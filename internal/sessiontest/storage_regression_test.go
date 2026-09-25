package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/common/clientmodels"
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
// the snapshot was made, so that would start failing on its own. The fresh
// mdoc session in assertLoadedClientUsable covers disclosure.
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
