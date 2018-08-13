package sessiontest

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Sirupsen/logrus"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaserver"
	"github.com/privacybydesign/irmago/irmaserver/irmarequestor"
	"github.com/stretchr/testify/require"
)

var irmaServer *http.Server

func StartIrmaServer(t *testing.T) {
	testdata := test.FindTestdataFolder(t)
	skpath := filepath.Join(testdata, "irma_configuration", "irma-demo", "RU", "PrivateKeys", "2.xml")
	iss := irma.NewIssuerIdentifier("irma-demo.RU")
	sk, err := gabi.NewPrivateKeyFromFile(skpath)
	require.NoError(t, err)

	skpath = filepath.Join(testdata, "irma_configuration", "irma-demo", "MijnOverheid", "PrivateKeys", "1.xml")
	iss2 := irma.NewIssuerIdentifier("irma-demo.MijnOverheid")
	sk2, err := gabi.NewPrivateKeyFromFile(skpath)
	require.NoError(t, err)

	skpath = filepath.Join(testdata, "irma_configuration", "test", "test", "PrivateKeys", "3.xml")
	iss3 := irma.NewIssuerIdentifier("test.test")
	sk3, err := gabi.NewPrivateKeyFromFile(skpath)
	require.NoError(t, err)

	logger := logrus.New()
	logger.Level = logrus.WarnLevel
	logger.Formatter = &logrus.TextFormatter{}
	require.NoError(t, irmarequestor.Initialize(&irmaserver.Configuration{
		Logger:                logger,
		IrmaConfigurationPath: filepath.Join(testdata, "irma_configuration"),
		PrivateKeys: map[irma.IssuerIdentifier]*gabi.PrivateKey{
			iss:  sk,
			iss2: sk2,
			iss3: sk3,
		},
	}))

	mux := http.NewServeMux()
	mux.HandleFunc("/", irmarequestor.HttpHandlerFunc("/"))
	irmaServer = &http.Server{Addr: ":48680", Handler: mux}
	go func() {
		irmaServer.ListenAndServe()
	}()
}

func StopIrmaServer() {
	irmaServer.Close()
}

func newSessionHelper(t *testing.T, request irma.SessionRequest) *irmaserver.SessionResult {
	StartIrmaServer(t)
	client := parseStorage(t)
	clientChan := make(chan *SessionResult)
	serverChan := make(chan *irmaserver.SessionResult)

	qr, token, err := irmarequestor.StartSession(request, func(result *irmaserver.SessionResult) {
		serverChan <- result
	})
	require.NoError(t, err)
	qr.URL = "http://localhost:48680/" + qr.URL

	h := TestHandler{t, clientChan, client}
	j, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(j), h)
	clientResult := <-clientChan
	if clientResult != nil {
		require.NoError(t, clientResult.Err)
	}

	serverResult := <-serverChan
	StopIrmaServer()
	test.ClearTestStorage(t)
	require.Equal(t, token, serverResult.Token)
	return serverResult
}

func TestNewSignatureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	serverResult := newSessionHelper(t, &irma.SignatureRequest{
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

func TestNewDisclosureSession(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	serverResult := newSessionHelper(t, &irma.DisclosureRequest{
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

func TestNewIssuanceSession(t *testing.T) {
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

	result := newSessionHelper(t, request)
	require.Nil(t, result.Err)
	require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
	require.NotEmpty(t, result.Disclosed)
	require.Equal(t, attrid, result.Disclosed[0].Identifier)
	require.Equal(t, "456", result.Disclosed[0].Value["en"])
}
