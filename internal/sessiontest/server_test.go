package sessiontest

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/irmaserver"
	"github.com/privacybydesign/irmago/irmaserver/server"
	"github.com/stretchr/testify/require"
)

func StartRequestorServer() {
	testdata := test.FindTestdataFolder(nil)

	logger := logrus.New()
	logger.Level = logrus.WarnLevel
	logger.Formatter = &logrus.TextFormatter{}

	go func() {
		err := server.Start(&server.Configuration{
			Configuration: &irmaserver.Configuration{
				Logger:                logger,
				IrmaConfigurationPath: filepath.Join(testdata, "irma_configuration"),
				PrivateKeysPath:       filepath.Join(testdata, "privatekeys"),
			},
			Port: 48682,
		})
		if err != nil {
			panic("Starting server failed: " + err.Error())
		}
	}()
	time.Sleep(100 * time.Millisecond) // Give server time to start
}

func StopRequestorServer() {
	server.Stop()
}

func serverSessionHelper(t *testing.T, request irma.SessionRequest) *irmaserver.SessionResult {
	client := parseStorage(t)
	defer test.ClearTestStorage(t)

	clientChan := make(chan *SessionResult)

	transport := irma.NewHTTPTransport("http://localhost:48682")
	var qr irma.Qr
	err := transport.Post("create", &qr, request)
	require.NoError(t, err)

	token := qr.URL
	qr.URL = "http://localhost:48682/irma/" + qr.URL

	h := TestHandler{t, clientChan, client}
	j, err := json.Marshal(qr)
	require.NoError(t, err)
	client.NewSession(string(j), h)
	clientResult := <-clientChan
	if clientResult != nil {
		require.NoError(t, clientResult.Err)
	}

	var result irmaserver.SessionResult
	transport.Get("result/"+token, &result)
	return &result
}

func TestRequestorServer(t *testing.T) {
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")
	serverResult := serverSessionHelper(t, &irma.DisclosureRequest{
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
