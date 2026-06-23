package sessiontest

import (
	"slices"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

// testDisclosureKeepsSelectionAfterDeletingAnotherCredential reproduces the
// scenario behind irmamobile#520 / irmamobile#579 ("disclosure discloses the
// wrong email after a credential is deleted") against irmago's own session
// logic.
//
// w-ensink asked whether this is reproducible in irmago, where all session
// logic lives, and noted (correctly) that the credential must be deleted
// BEFORE the disclosure session starts — that is the only path reachable from
// the irmamobile UI (the Data tab is unreachable while a session screen is
// shown) and it is exactly the order in irmamobile#520's repro (delete first,
// then disclose). This test follows that order, and the bug still reproduces:
// the root cause is in irmago, not the irmamobile UI, and it is independent of
// whether the deletion happens before or during the session because the stale
// state lives on the long-lived IrmaClient.
//
// The defect was in IrmaClient.remove: deleting a credential shifts every later
// instance of that type down one position, and their lookup counters are
// decremented to match, but the credentialsCache is keyed by positional counter
// and only the deleted index's entry was invalidated. The shifted instances
// kept STALE cache entries, so a subsequent credentialByHash lookup resolved
// hash -> decremented counter -> credentialsCache.Get -> the credential
// previously cached at that counter = the WRONG instance. The disclosure choice
// already round-trips by credential hash
// (clientmodels.SelectedCredential.CredentialHash), so the selection itself is
// stable; it is the hash->credential resolution underneath that returned the
// wrong instance.
//
// This test issues three email credentials, deletes the first one (which shifts
// the later instances' counters down), then starts a disclosure session and
// discloses the last email. On master it discloses the credential that slid
// into the freed counter slot; with the IrmaClient.remove cache-invalidation
// fix it discloses the selected email. The test therefore fails before the fix
// and passes after it.
//
// Version note (verification requested on irmamobile#579): the same
// IrmaClient.remove / credentialByHash code is byte-for-byte identical between
// irmago v0.19.1 (shipped by Yivi app v7.13.5) and irmago v1.0.0 (shipped by
// Yivi app v8.0.0), and v8.0.0's new client package still runs IRMA disclosure
// through this same irmaclient session engine
// (client.(*Client).NewSession -> client.irmaClient.NewSession). So the v8.0
// architecture rework did NOT fix this bug on its own — it is present in both
// app versions, which is why this regression test (run against the new
// client.Client) is needed alongside the IrmaClient.remove fix in this PR.
func testDisclosureKeepsSelectionAfterDeletingAnotherCredential(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Email is a non-singleton credential, so the wallet keeps all three
	// instances side by side.
	issue(t, irmaServer, c, sessionHandler, 1, createEmailIssuanceRequestWithValue("first@example.com"))
	_ = awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, 2, createEmailIssuanceRequestWithValue("second@example.com"))
	_ = awaitSessionState(t, sessionHandler)
	issue(t, irmaServer, c, sessionHandler, 3, createEmailIssuanceRequestWithValue("third@example.com"))
	_ = awaitSessionState(t, sessionHandler)

	// Mirror the irmamobile#520 steps: the user deletes a credential from the
	// Data tab BEFORE starting any disclosure session. Deleting the FIRST email
	// shifts "second@example.com" and "third@example.com" down one positional
	// counter; the credentialsCache is keyed by that counter, so without the
	// IrmaClient.remove fix the cache entries for the shifted instances stay
	// stale and the later hash lookup resolves to the wrong instance.
	deleteIrmaCredentialByEmail(t, c, "first@example.com")

	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
		},
	}

	sessionJson, disclosureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(4, sessionJson)
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_RequestPermission)

	owned := session.DisclosurePlan.DisclosureChoicesOverview[0].OwnedOptions
	require.Len(t, owned, 2, "the two remaining email instances should be offered for disclosure")

	// The user picks "third@example.com" — an instance whose positional counter
	// was shifted down by the earlier deletion.
	selectedBundle := bundleForEmail(t, owned, "third@example.com")
	choice := makeDisclosureChoice(selectedBundle)

	grantPermission(t, c, session.Id, choice)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// The selected email must be the one disclosed, not the credential that slid
	// into its old positional slot.
	requireIrmaServerResult(t, irmaServer, disclosureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "test.test.email.email", Value: "third@example.com"},
		},
	})
}

// createEmailIssuanceRequestWithValue builds an email issuance request with a
// caller-chosen address, so a test can stock the wallet with several
// distinguishable email instances.
func createEmailIssuanceRequestWithValue(email string) *irma.IssuanceRequest {
	return irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.email"),
			Attributes: map[string]string{
				"email": email,
			},
		},
	})
}

// bundleForEmail returns the single-credential owned bundle whose email
// attribute equals the given address.
func bundleForEmail(t *testing.T, bundles []*clientmodels.DisclosureBundle, email string) *clientmodels.DisclosureBundle {
	t.Helper()
	idx := slices.IndexFunc(bundles, func(b *clientmodels.DisclosureBundle) bool {
		for _, cred := range b.Credentials {
			for _, attr := range cred.Attributes {
				if attr.Value != nil && attr.Value.String != nil && *attr.Value.String == email {
					return true
				}
			}
		}
		return false
	})
	require.GreaterOrEqual(t, idx, 0, "no owned option discloses email %q", email)
	return bundles[idx]
}

// deleteIrmaCredentialByEmail removes the wallet credential whose email
// attribute equals the given address, mirroring a user deleting it from the
// Data tab. It looks the credential up via the same GetCredentials() listing
// the app uses, so it works outside an active session (the realistic
// irmamobile#520 order: delete first, then start the disclosure session).
func deleteIrmaCredentialByEmail(t *testing.T, c *client.Client, email string) {
	t.Helper()
	creds, err := c.GetCredentials()
	require.NoError(t, err)
	for _, cred := range creds {
		for _, attr := range cred.Attributes {
			if attr.Value != nil && attr.Value.String != nil && *attr.Value.String == email {
				// CredentialInstanceIds maps each format to the raw idemix
				// credential hash that RemoveCredentialsByHash matches on.
				require.NotEmpty(t, cred.CredentialInstanceIds,
					"credential disclosing %q has no instance ids", email)
				require.NoError(t, c.RemoveCredentialsByHash(cred.CredentialInstanceIds))
				return
			}
		}
	}
	t.Fatalf("no wallet credential found with email %q", email)
}
