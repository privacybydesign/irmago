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
	issue(t, irmaServer, c, sessionHandler, 1, irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.singleton"),
			Attributes:       map[string]string{"BSN": "1234"},
		},
	}))
	_ = awaitSessionState(t, sessionHandler)

	// Issue stemmen.stempas with election.
	issue(t, irmaServer, c, sessionHandler, 2, irma.NewIssuanceRequest([]*irma.CredentialRequest{
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
	c.NewSession(3, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	// The single inner con yields exactly one DisclosureBundle holding both
	// credentials together — the user can't "pick one" between them.
	require.NotNil(t, session.DisclosurePlan)
	require.Len(t, pickOnes(session.DisclosurePlan), 1)
	pickOne := pickOnes(session.DisclosurePlan)[0]
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

// testIssuanceStepEmitsMultiCredBundle asserts that an empty-wallet disclosure
// with an inner con spanning two credential types emits a single IssuanceStep
// whose only option is a bundle holding both credential descriptors.
func testIssuanceStepEmitsMultiCredBundle(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN"),
				irma.NewAttributeRequest("irma-demo.stemmen.stempas.election"),
			},
		},
	}
	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	require.NotNil(t, session.DisclosurePlan)
	require.NotNil(t, issuance(session.DisclosurePlan))
	require.Len(t, issuance(session.DisclosurePlan).Steps, 1)

	step := issuance(session.DisclosurePlan).Steps[0]
	require.Len(t, step.Options, 1, "single inner con → single bundle option")

	bundle := step.Options[0]
	require.Len(t, bundle.Credentials, 2,
		"bundle should hold one descriptor per credential type in the con")

	credIds := map[string]bool{}
	for _, desc := range bundle.Credentials {
		credIds[desc.CredentialId] = true
	}
	require.True(t, credIds["irma-demo.MijnOverheid.singleton"],
		"bundle should contain singleton descriptor")
	require.True(t, credIds["irma-demo.stemmen.stempas"],
		"bundle should contain stempas descriptor")
}

// testMultiCredBundleIssuanceFlow drives the end-to-end issuance-during-
// disclosure flow for a multi-credential bundle: empty wallet → issue first
// singleton (step partially satisfied) → issue second singleton (step fully
// satisfied) → grant permission → success.
func testMultiCredBundleIssuanceFlow(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN"),
				irma.NewAttributeRequest("irma-demo.stemmen.stempas.election"),
			},
		},
	}
	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)
	require.NotNil(t, issuance(session.DisclosurePlan),
		"wallet is empty, so issuance is required")

	disclosureSessionId := session.Id

	// Issue the first credential of the bundle. The bundle is still not
	// satisfied — stempas for the inner con isn't owned yet.
	issue(t, irmaServer, c, sessionHandler, 2, irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.singleton"),
			Attributes:       map[string]string{"BSN": "1234"},
		},
	}))
	session = awaitSessionState(t, sessionHandler) // disclosure re-eval
	require.Equal(t, disclosureSessionId, session.Id)
	require.NotNil(t, issuance(session.DisclosurePlan),
		"single bundle member issued → bundle still incomplete → issuance still required")
	require.Equal(t,
		map[string]struct{}{
			"irma-demo.MijnOverheid.singleton": {},
		},
		issuance(session.DisclosurePlan).IssuedCredentialIds,
		"partial progress should be surfaced: singleton satisfies its descriptor, stempas does not",
	)
	// The choices are there while the bundle is incomplete, but the bundle is
	// not owned yet: there is nothing to pick, only something to obtain.
	require.Len(t, pickOnes(session.DisclosurePlan), 1)
	require.Empty(t, pickOnes(session.DisclosurePlan)[0].OwnedOptions,
		"an incomplete bundle must not be offered as a choice")
	require.NotEmpty(t, pickOnes(session.DisclosurePlan)[0].ObtainableOptions)
	_ = awaitSessionState(t, sessionHandler) // finished issuance session

	// Issue the second credential of the bundle.
	issue(t, irmaServer, c, sessionHandler, 3, irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas"),
			Attributes:       map[string]string{"election": "plantsoen"},
		},
	}))
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, disclosureSessionId, session.Id)
	// Both creds issued: IssueDuringDisclosure remains populated with the full
	// IssuedCredentialIds (so the UI can show "all required data added"), and
	// DisclosureChoicesOverview is now surfaced.
	require.NotNil(t, issuance(session.DisclosurePlan))
	require.Equal(t,
		map[string]struct{}{
			"irma-demo.MijnOverheid.singleton": {},
			"irma-demo.stemmen.stempas":        {},
		},
		issuance(session.DisclosurePlan).IssuedCredentialIds,
	)
	require.NotNil(t, pickOnes(session.DisclosurePlan))
	require.Len(t, pickOnes(session.DisclosurePlan), 1)

	pickOne := pickOnes(session.DisclosurePlan)[0]
	require.Len(t, pickOne.OwnedOptions, 1, "single con → single bundle in OwnedOptions")
	disclosureBundle := pickOne.OwnedOptions[0]
	require.Len(t, disclosureBundle.Credentials, 2,
		"DisclosureBundle should hold both just-issued credentials")

	_ = awaitSessionState(t, sessionHandler) // finished issuance session

	grantPermission(t, c, session.Id, makeDisclosureChoice(disclosureBundle))
	session = awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_Success, session.Status)
}

// testMultipleIssuanceBundleOptions covers the case that motivates the bundle
// model: a discon with two inner cons, each requiring two credentials. The
// IssuanceStep must surface both bundles as alternatives, each carrying its
// own credential descriptors — which couldn't be expressed under the pre-bundle
// model that collapsed each con to a single descriptor.
//
// This is a structural test only: end-to-end satisfaction of multi-cred bundles
// is covered by testMultiCredBundleIssuanceFlow.
func testMultipleIssuanceBundleOptions(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	// Both bundles respect "at most one non-singleton per inner con".
	// Bundle A: two singletons. Bundle B: one singleton + one non-singleton.
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN"),
				irma.NewAttributeRequest("irma-demo.stemmen.stempas.election"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstnames"),
			},
		},
	}
	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	require.NotNil(t, issuance(session.DisclosurePlan))
	require.Len(t, issuance(session.DisclosurePlan).Steps, 1)
	step := issuance(session.DisclosurePlan).Steps[0]
	require.Len(t, step.Options, 2,
		"two inner cons → two bundle options")
	for i, b := range step.Options {
		require.Len(t, b.Credentials, 2,
			"bundle %d should hold two credential descriptors", i)
	}

	// Bundle A: singleton + stempas
	bundleACredIds := map[string]bool{}
	for _, desc := range step.Options[0].Credentials {
		bundleACredIds[desc.CredentialId] = true
	}
	require.True(t, bundleACredIds["irma-demo.MijnOverheid.singleton"])
	require.True(t, bundleACredIds["irma-demo.stemmen.stempas"])

	// Bundle B: singleton + fullName
	bundleBCredIds := map[string]bool{}
	for _, desc := range step.Options[1].Credentials {
		bundleBCredIds[desc.CredentialId] = true
	}
	require.True(t, bundleBCredIds["irma-demo.MijnOverheid.singleton"])
	require.True(t, bundleBCredIds["irma-demo.MijnOverheid.fullName"])
}

// testOptionalPartlyOwnedConIsAnOptionWithAnEmptySlot asks, optionally, for a
// con of two singletons of which the wallet holds one, or for the other one on
// its own. Neither con can be disclosed yet, so no option is complete, and
// nothing has to be added first (the discon is optional); each con is an
// option with the owned type's slot holding its card and the missing type's
// slot offering it.
func testOptionalPartlyOwnedConIsAnOptionWithAnEmptySlot(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	issue(t, irmaServer, c, sessionHandler, 1, irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.stemmen.stempas"),
			Attributes:       map[string]string{"election": "plantsoen"},
		},
	}))
	_ = awaitSessionState(t, sessionHandler)

	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN"),
				irma.NewAttributeRequest("irma-demo.stemmen.stempas.election"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.singleton.BSN"),
			},
		},
	}
	c.NewSession(2, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)
	require.Equal(t, clientmodels.Status_RequestPermission, session.Status)

	require.NotNil(t, session.DisclosurePlan)
	require.Nil(t, issuance(session.DisclosurePlan))
	require.Len(t, pickOnes(session.DisclosurePlan), 1)
	pickOne := pickOnes(session.DisclosurePlan)[0]
	require.True(t, pickOne.Optional)
	require.Empty(t, pickOne.OwnedOptions)
	require.Len(t, pickOne.ObtainableOptions, 1)
	require.Equal(t, "irma-demo.MijnOverheid.singleton", pickOne.ObtainableOptions[0].CredentialId)

	// In slots: each con is an option, each type of it a slot. The owned part
	// is the slot with its card, the missing type a slot without a card.
	options := session.DisclosurePlan.Choices[0].Options
	require.Len(t, options, 2)
	both := options[0].Slots
	require.Len(t, both, 2)
	require.Equal(t, "0:irma-demo.MijnOverheid.singleton", both[0].Id)
	require.Empty(t, both[0].Candidates)
	require.Len(t, both[0].Obtainable, 1)
	require.Equal(t, "irma-demo.MijnOverheid.singleton", both[0].Obtainable[0].CredentialId)
	require.Equal(t, "0:irma-demo.stemmen.stempas", both[1].Id)
	require.Len(t, both[1].Candidates, 1)
	require.Equal(t, "irma-demo.stemmen.stempas", both[1].Candidates[0].CredentialId)
	require.NotEmpty(t, both[1].Candidates[0].Hash)
	require.Len(t, both[1].Candidates[0].Attributes, 1)
	require.Equal(t, []any{"election"}, both[1].Candidates[0].Attributes[0].ClaimPath)

	alone := options[1].Slots
	require.Len(t, alone, 1)
	require.Empty(t, alone[0].Candidates)
	require.Len(t, alone[0].Obtainable, 1)
	require.Equal(t, "irma-demo.MijnOverheid.singleton", alone[0].Obtainable[0].CredentialId)
}
