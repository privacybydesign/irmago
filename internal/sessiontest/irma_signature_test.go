package sessiontest

import (
	"testing"

	"github.com/privacybydesign/irmago/client"
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/irma"

	"github.com/stretchr/testify/require"
)

func testSessionHandlerForIrmaSignature(t *testing.T) {
	runSessionTest(t,
		"irma signature requestor info correct",
		testIrmaSignatureRequestorInfoCorrect,
	)

	runSessionTest(t,
		"signature request with unsatisfied disclosure",
		testSignatureRequest,
	)
}

func testIrmaSignatureRequestorInfoCorrect(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewSignatureRequest("Hello world")
	request.Disclose = studentCardDisclosure()

	c.NewSession(1, startSameDeviceIrmaSessionAtServer(t, irmaServer, request))
	session := awaitSessionState(t, sessionHandler)

	require.Equal(t, 1, session.Id)
	requireRequestorInfo(t, session)
}

func testSignatureRequest(
	t *testing.T,
	irmaServer *IrmaServer,
	c *client.Client,
	sessionHandler *MockSessionHandler,
) {
	request := irma.NewSignatureRequest("Hello, World!")
	request.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{irma.NewAttributeRequest("test.test.email.email")},
		},
	}

	sessionJson, signatureToken := startSameDeviceIrmaSessionAtServerWithToken(t, irmaServer, request)
	c.NewSession(1, sessionJson)
	session := awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Signature, clientmodels.Status_RequestPermission)
	require.Equal(t, "Hello, World!", session.MessageToSign)

	require.Empty(t, session.OfferedCredentials)
	plan := session.DisclosurePlan
	require.Len(t, plan.IssueDuringDisclosure.Steps, 1)
	require.Nil(t, plan.DisclosureChoicesOverview)

	issue(t, irmaServer, c, sessionHandler, 2, createEmailIssuanceRequest())

	// update disclosure candidates of signature session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Signature, clientmodels.Status_RequestPermission)
	require.Equal(t, "Hello, World!", session.MessageToSign)

	require.Empty(t, session.OfferedCredentials)
	plan = session.DisclosurePlan
	require.Len(t, plan.IssueDuringDisclosure.Steps, 1)
	require.NotNil(t, plan.DisclosureChoicesOverview)

	choice := plan.DisclosureChoicesOverview[0].OwnedOptions[0]
	grantPermission(t, c, session.Id, makeDisclosureChoice(choice))

	// finish email issuance session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 2, clientmodels.Type_Issuance, clientmodels.Status_Success)

	// finish signature session
	session = awaitSessionState(t, sessionHandler)
	requireSessionState(t, session, 1, clientmodels.Type_Signature, clientmodels.Status_Success)

	requireIrmaServerResult(t, irmaServer, signatureToken, [][]expectedDisclosedAttr{
		{
			{Identifier: "test.test.email.email", Value: "test@gmail.com"},
		},
	})
}
