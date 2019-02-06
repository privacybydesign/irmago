package sessiontest

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/require"
)

func requestorSessionHelper(t *testing.T, request irma.SessionRequest) *server.SessionResult {
	StartIrmaServer(t)
	defer StopIrmaServer()

	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	clientChan := make(chan *SessionResult)
	serverChan := make(chan *server.SessionResult)

	qr, token, err := irmaServer.StartSession(request, func(result *server.SessionResult) {
		serverChan <- result
	})
	require.NoError(t, err)

	h := TestHandler{t, clientChan, client}
	j, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(j), h)
	clientResult := <-clientChan
	if clientResult != nil {
		require.NoError(t, clientResult.Err)
	}

	serverResult := <-serverChan

	require.Equal(t, token, serverResult.Token)
	return serverResult
}

func TestRequestorSignatureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	serverResult := requestorSessionHelper(t, &irma.SignatureRequest{
		Message: "message",
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{Type: irma.ActionSigning},
			Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
				Label:      "foo",
				Attributes: []irma.AttributeTypeIdentifier{id},
			}}),
		},
	})

	require.Nil(t, serverResult.Err)
	require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
	require.NotEmpty(t, serverResult.Disclosed)
	require.Equal(t, id, serverResult.Disclosed[0].Identifier)
	require.Equal(t, "456", serverResult.Disclosed[0].Value["en"])
}

func TestRequestorDisclosureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	serverResult := requestorSessionHelper(t, &irma.DisclosureRequest{
		BaseRequest: irma.BaseRequest{Type: irma.ActionDisclosing},
		Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
			Label:      "foo",
			Attributes: []irma.AttributeTypeIdentifier{id},
		}}),
	})

	require.Nil(t, serverResult.Err)
	require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
	require.NotEmpty(t, serverResult.Disclosed)
	require.Equal(t, id, serverResult.Disclosed[0].Identifier)
	require.Equal(t, "456", serverResult.Disclosed[0].Value["en"])

}

func TestRequestorIssuanceSession(t *testing.T) {
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := &irma.IssuanceRequest{
		BaseRequest: irma.BaseRequest{Type: irma.ActionIssuing},
	}
	request.Credentials = []*irma.CredentialRequest{{
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
		Attributes: map[string]string{
			"university":        "Radboud",
			"studentCardNumber": "31415927",
			"studentID":         "s1234567",
			"level":             "42",
		},
	}, {
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"),
		Attributes: map[string]string{
			"BSN": "299792458",
		},
	}, {
		CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
		Attributes:       map[string]string{"email": "testusername"},
	}}
	request.Disclose = []*irma.AttributeDisjunction{{
		Label:      "foo",
		Attributes: []irma.AttributeTypeIdentifier{attrid},
	}}

	result := requestorSessionHelper(t, request)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)
	require.Equal(t, attrid, result.Disclosed[0].Identifier)
	require.Equal(t, "456", result.Disclosed[0].Value["en"])
}
