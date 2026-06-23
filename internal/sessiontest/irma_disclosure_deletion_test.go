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
// logic lives. It is, and the root cause is in irmago — not (only) in the
// irmamobile UI. The disclosure choice already round-trips by credential hash
// (clientmodels.SelectedCredential.CredentialHash), so the selection itself is
// stable across a deletion. The defect was in IrmaClient.remove: deleting a
// credential shifts every later instance of that type down one position, and
// their lookup counters are decremented to match, but the credentialsCache is
// keyed by positional counter and only the deleted index's entry was
// invalidated. The shifted instances kept STALE cache entries, so a subsequent
// credentialByHash lookup resolved hash -> decremented counter ->
// credentialsCache.Get -> the credential previously cached at that counter =
// the WRONG instance.
//
// This test issues three email credentials, selects the last one, deletes an
// earlier one (which shifts the selected one's counter down), and then
// discloses. On master it discloses the credential that slid into the freed
// counter slot; with the IrmaClient.remove cache-invalidation fix it discloses
// the originally-selected email. The test therefore fails before the fix and
// passes after it.
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
	require.Len(t, owned, 3, "all three email instances should be offered for disclosure")

	// The user picks the email that sits LAST in the rendered list.
	selectedBundle := bundleForEmail(t, owned, "third@example.com")
	selectedIndex := slices.Index(owned, selectedBundle)
	require.Equal(t, 2, selectedIndex, "third@example.com is expected to be the last owned option")

	// The wallet captures the user's choice now, while the list still holds all
	// three entries. makeDisclosureChoice records the credential hash, not the
	// list position.
	choice := makeDisclosureChoice(selectedBundle)

	// Now delete a DIFFERENT credential that sits BEFORE the selected one. This
	// shifts "third@example.com" from positional counter 2 down to 1; with the
	// stale-cache bug the credentialsCache entry for counter 1 still holds
	// "second@example.com", so resolving the selected hash discloses the wrong
	// email — the irmamobile#520 failure mode.
	deleteBundle := bundleForEmail(t, owned, "first@example.com")
	require.Less(t, slices.Index(owned, deleteBundle), selectedIndex,
		"the deleted credential must sit before the selected one to trigger a shift")
	deleteIrmaCredential(t, c, deleteBundle)

	// Grant permission with the choice captured before the deletion.
	grantPermission(t, c, session.Id, choice)

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Protocol_Irma, session.Protocol)
	requireSessionState(t, session, 4, clientmodels.Type_Disclosure, clientmodels.Status_Success)

	// The originally-selected email must be the one disclosed, not the
	// credential that slid into its old slot.
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

// deleteIrmaCredential removes the (idemix) credential of the given
// single-credential bundle from the wallet, mirroring a user deleting it from
// the Data tab.
func deleteIrmaCredential(t *testing.T, c *client.Client, bundle *clientmodels.DisclosureBundle) {
	t.Helper()
	require.Len(t, bundle.Credentials, 1, "expected a single-credential bundle")
	cred := bundle.Credentials[0]
	require.NoError(t, c.RemoveCredentialsByHash(map[clientmodels.CredentialFormat]string{
		cred.Format: cred.Hash,
	}))
}
