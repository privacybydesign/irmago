package sessiontest

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	httpServer     *http.Server
	irmaServer     *irmaserver.Server
	combinedServer *irmaserver.Server

	logger   = logrus.New()
	testdata = test.FindTestdataFolder(nil)
)

func init() {
	logger.Level = logrus.ErrorLevel
	logger.Formatter = &logrus.TextFormatter{}
}

func StartIrmaServer(configuration *irmaserver.Configuration) {
	go func() {
		var err error
		if combinedServer, err = irmaserver.New(configuration); err != nil {
			panic(err)
		}
		if err = combinedServer.Start(configuration); err != nil {
			panic("Starting server failed: " + err.Error())
		}
	}()
	time.Sleep(100 * time.Millisecond) // Give server time to start
}

func StopIrmaServer() {
	_ = combinedServer.Stop()
}

func StartIrmaClientServer(t *testing.T) {
	testdata := test.FindTestdataFolder(t)

	logger := logrus.New()
	logger.Level = logrus.WarnLevel
	logger.Formatter = &logrus.TextFormatter{}

	var err error
	irmaServer, err = irmaserver.New(&server.Configuration{
		URL:                   "http://localhost:48680",
		Logger:                logger,
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
	})

	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", irmaServer.HttpHandlerFunc())
	httpServer = &http.Server{Addr: ":48680", Handler: mux}
	go func() {
		_ = httpServer.ListenAndServe()
	}()
}

func StopIrmaClientServer() {
	_ = httpServer.Close()
}

var IrmaServerConfiguration = &irmaserver.Configuration{
	Configuration: &server.Configuration{
		URL:                   "http://localhost:48682/irma",
		Logger:                logger,
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
	},
	DisableRequestorAuthentication: true,
	Port: 48682,
}

var JwtServerConfiguration = &irmaserver.Configuration{
	Configuration: &server.Configuration{
		URL:                   "http://localhost:48682/irma",
		Logger:                logger,
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
	},
	Port: 48682,
	DisableRequestorAuthentication: false,
	MaxRequestAge:                  3,
	Permissions: irmaserver.Permissions{
		Disclosing: []string{"*"},
		Signing:    []string{"*"},
		Issuing:    []string{"*"},
	},
	Requestors: map[string]irmaserver.Requestor{
		"requestor1": {
			AuthenticationMethod:  irmaserver.AuthenticationMethodPublicKey,
			AuthenticationKeyFile: filepath.Join(testdata, "jwtkeys", "requestor1.pem"),
		},
		"requestor2": {
			AuthenticationMethod: irmaserver.AuthenticationMethodToken,
			AuthenticationKey:    "xa6=*&9?8jeUu5>.f-%rVg`f63pHim",
		},
		"requestor3": {
			AuthenticationMethod: irmaserver.AuthenticationMethodHmac,
			AuthenticationKey:    "eGE2PSomOT84amVVdTU+LmYtJXJWZ2BmNjNwSGltCg==",
		},
	},
	JwtPrivateKeyFile: filepath.Join(testdata, "jwtkeys", "sk.pem"),
}
