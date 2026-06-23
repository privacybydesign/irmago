package sessiontest

import (
	"slices"
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

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
