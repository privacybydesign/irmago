package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

// testMultiSingletonInnerConProducesBundle issues two singleton credentials
// (MijnOverheid.singleton and stemmen.stempas) and discloses against a single
// inner con that requires an attribute from each. Under the bundle model this
// yields ONE OwnedOption holding both credential instances together — not two
// "alternative" options as pre-refactor code produced.
func testMultiSingletonInnerConProducesBundle(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Issue MijnOverheid.singleton with BSN.
	issue(t, irmaServer, c, sessionHandler, irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.singleton"),
			Attributes:       map[string]string{"BSN": "1234"},
		},
	}))
	_ = awaitSessionState(t, sessionHandler)

	// Issue stemmen.stempas with election.
	issue(t, irmaServer, c, sessionHandler, irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas"),
			Attributes:       map[string]string{"election": "plantsoen"},
		},
	}))
	_ = awaitSessionState(t, sessionHandler)

	// Disclosure request: single inner con requiring both singletons.
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.stemmen.stempas.election"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN"),
			},
		},
	}
	c.NewSession(startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	// The single inner con yields exactly one DisclosureBundle holding both
	// credentials together — the user can't "pick one" between them.
	require.NotNil(t, session.DisclosurePlan)
	require.Len(t, session.DisclosurePlan.DisclosureChoicesOverview, 1)
	pickOne := session.DisclosurePlan.DisclosureChoicesOverview[0]
	require.Len(t, pickOne.OwnedOptions, 1,
		"single inner con requiring two singletons should produce ONE bundle, not multiple options")
	bundle := pickOne.OwnedOptions[0]
	require.Len(t, bundle.Credentials, 2,
		"bundle should hold both singleton credentials together")

	// Both expected credentials are present in the bundle, each carrying only
	// the attribute requested by the inner con.
	credsByID := map[string]*clientmodels.SelectableCredentialInstance{}
	for _, cred := range bundle.Credentials {
		credsByID[cred.CredentialId] = cred
	}
	stempas, ok := credsByID["irma-demo.stemmen.stempas"]
	require.True(t, ok, "bundle should contain stempas")
	require.Len(t, stempas.Attributes, 1)
	require.Equal(t, []any{"election"}, stempas.Attributes[0].ClaimPath)

	singleton, ok := credsByID["irma-demo.MijnOverheid.singleton"]
	require.True(t, ok, "bundle should contain singleton")
	require.Len(t, singleton.Attributes, 1)
	require.Equal(t, []any{"BSN"}, singleton.Attributes[0].ClaimPath)

	// Grant permission for the entire bundle — disclosure should succeed.
	grantPermission(t, c, session.Id, makeDisclosureChoice(bundle))

	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}
