package sessiontest

import (
	"encoding/json"
	"testing"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/require"
)

func requestorSessionHelper(t *testing.T, request irma.SessionRequest, client *irmaclient.Client) *server.SessionResult {
	StartIrmaServer(t)
	defer StopIrmaServer()

	if client == nil {
		client = parseStorage(t)
		defer test.ClearTestStorage(t)
	}

	clientChan := make(chan *SessionResult)
	serverChan := make(chan *server.SessionResult)

	qr, token, err := irmaServer.StartSession(request, func(result *server.SessionResult) {
		serverChan <- result
	})
	require.NoError(t, err)

	h := TestHandler{t, clientChan, client, nil}
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
	serverResult := requestorSessionHelper(t, irma.NewSignatureRequest("message", id), nil)

	require.Nil(t, serverResult.Err)
	require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
	require.NotEmpty(t, serverResult.Disclosed)
	require.Equal(t, id, serverResult.Disclosed[0][0].Identifier)
	require.Equal(t, "456", serverResult.Disclosed[0][0].Value["en"])
}

func TestRequestorDisclosureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := irma.NewDisclosureRequest(id)
	serverResult := testRequestorDisclosure(t, request)
	require.Len(t, serverResult.Disclosed, 1)
	require.Equal(t, id, serverResult.Disclosed[0][0].Identifier)
	require.Equal(t, "456", serverResult.Disclosed[0][0].Value["en"])
}

func TestRequestorDisclosureMultipleAttrs(t *testing.T) {
	request := irma.NewDisclosureRequest(
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID"),
		irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"),
	)
	serverResult := testRequestorDisclosure(t, request)
	require.Len(t, serverResult.Disclosed, 2)
}

func testRequestorDisclosure(t *testing.T, request *irma.DisclosureRequest) *server.SessionResult {
	serverResult := requestorSessionHelper(t, request, nil)
	require.Nil(t, serverResult.Err)
	require.Equal(t, irma.ProofStatusValid, serverResult.ProofStatus)
	return serverResult
}

func TestRequestorIssuanceSession(t *testing.T) {
	testRequestorIssuance(t, false)
}

func testRequestorIssuance(t *testing.T, keyshare bool) {
	attrid := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	request := irma.NewIssuanceRequest([]*irma.CredentialRequest{{
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
	}}, attrid)
	if keyshare {
		request.Credentials = append(request.Credentials, &irma.CredentialRequest{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.mijnirma"),
			Attributes:       map[string]string{"email": "testusername"},
		})
	}

	result := requestorSessionHelper(t, request, nil)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)
	require.Equal(t, attrid, result.Disclosed[0][0].Identifier)
	require.Equal(t, "456", result.Disclosed[0][0].Value["en"])
}

func TestConDisCon(t *testing.T) {
	client := parseStorage(t)
	ir := getMultipleIssuanceRequest()
	ir.Credentials = append(ir.Credentials, &irma.CredentialRequest{
		Validity:         ir.Credentials[0].Validity,
		CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.fullName"),
		Attributes: map[string]string{
			"firstnames": "Jan Hendrik",
			"firstname":  "Jan",
			"familyname": "Klaassen",
			"prefix":     "van",
		},
	})
	requestorSessionHelper(t, ir, client)

	dr := irma.NewDisclosureRequest()
	dr.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.MijnOverheid.root.BSN"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
				irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
			},
			irma.AttributeCon{
				irma.NewAttributeRequest("irma-demo.RU.studentCard.studentID"),
				irma.NewAttributeRequest("irma-demo.RU.studentCard.university"),
			},
		},
		//irma.AttributeDisCon{
		//	irma.AttributeCon{
		//		irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.firstname"),
		//		irma.NewAttributeRequest("irma-demo.MijnOverheid.fullName.familyname"),
		//	},
		//},
	}

	requestorSessionHelper(t, dr, client)
}
