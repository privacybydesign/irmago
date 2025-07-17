package sessiontest

import (
	"encoding/json"
	"path/filepath"
	"testing"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/internal/testkeyshare"
	"github.com/privacybydesign/irmago/irmaclient"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

func TestIdemixAndSdJwtCombinedIssuance(t *testing.T) {
	irmaServer := StartIrmaServer(t, IrmaServerConfWithSdJwtEnabled())
	defer irmaServer.Stop()

	keyshareServer := testkeyshare.StartKeyshareServer(t, logger, irma.NewSchemeManagerIdentifier("test"), 0)
	defer keyshareServer.Stop()

	client, clientHandler := createClient(t)

	require.NoError(t, clientHandler.AwaitEnrollmentResult())

	sessionHandler := irmaclient.NewTestHandler(t)

	issuanceRequest := createIssuanceRequest()

	qr, _, _, err := irmaServer.irma.StartSession(issuanceRequest, nil, "")
	require.NoError(t, err)

	session := irmaclient.SessionRequestData{
		Qr:       *qr,
		Protocol: "irma",
	}
	sessionJson, err := json.Marshal(session)
	require.NoError(t, err)

	client.NewSession(string(sessionJson), sessionHandler)
	sessionHandler.AwaitPermissionRequest()
	sessionHandler.ProceedIssuance()
	require.True(t, sessionHandler.AwaitSessionEnd())

	infoList := client.CredentialInfoList()
	require.Equal(t, 3, len(infoList))
}

func createIssuanceRequest() *irma.IssuanceRequest {
	var sdJwtBatchSize uint
	sdJwtBatchSize = 10
	req := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier("test.test.email"),
			Attributes: map[string]string{
				"email": "test@gmail.com",
			},
			SdJwtBatchSize: &sdJwtBatchSize,
		},
	})
	req.RequestSdJwts = true
	return req
}

func createClient(t *testing.T) (*irmaclient.Client, *irmaclient.MockClientHandler) {
	var aesKey [32]byte
	copy(aesKey[:], "asdfasdfasdfasdfasdfasdfasdfasdf")

	path := test.FindTestdataFolder(t)
	storageFolder := test.CreateTestStorage(t)
	storagePath := filepath.Join(storageFolder, "client")
	irmaConfigurationPath := filepath.Join(path, "irma_configuration")

	clientHandler := irmaclient.NewMockClientHandler()
	client, err := irmaclient.New(storagePath, irmaConfigurationPath, clientHandler, test.NewSigner(t), aesKey)
	require.NoError(t, err)

	client.SetPreferences(irmaclient.Preferences{DeveloperMode: true})
	client.KeyshareEnroll(irma.NewSchemeManagerIdentifier("test"), nil, "12345", "en")

	return client, clientHandler
}

func IrmaServerConfWithSdJwtEnabled() *server.Configuration {
	conf := IrmaServerConfiguration()
	conf.SdJwtIssuanceSettings = &server.SdJwtIssuanceSettings{
		Issuer:                 "https://openid4vc.staging.yivi.app",
		IssuerCertificateChain: string(testdata.IssuerCert_openid4vc_staging_yivi_app_Bytes),
		JwtPrivateKey:          string(testdata.IssuerPrivKeyBytes),
	}
	return conf
}
