package sessiontest

import (
	"path/filepath"
	"time"

	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

var (
	logger   = logrus.New()
	testdata = test.FindTestdataFolder(nil)
)

func init() {
	logger.Level = logrus.WarnLevel
	logger.Formatter = &logrus.TextFormatter{}
}

func StartIrmaServer(configuration *irmaserver.Configuration) {
	go func() {
		err := irmaserver.Start(configuration)
		if err != nil {
			panic("Starting server failed: " + err.Error())
		}
	}()
	time.Sleep(100 * time.Millisecond) // Give server time to start
}

func StopIrmaServer() {
	_ = irmaserver.Stop()
}

var IrmaServerConfiguration = &irmaserver.Configuration{
	Configuration: &server.Configuration{
		URL:                   "http://localhost:48682/irma",
		Logger:                logger,
		IrmaConfigurationPath: filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
	},
	DisableRequestorAuthentication: true,
	Port: 48682,
}

var JwtServerConfiguration = &irmaserver.Configuration{
	Configuration: &server.Configuration{
		URL:                   "http://localhost:48682/irma",
		Logger:                logger,
		IrmaConfigurationPath: filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
	},
	Port: 48682,
	DisableRequestorAuthentication: false,
	GlobalPermissions: irmaserver.Permissions{
		Disclosing: []string{"*"},
		Signing:    []string{"*"},
		Issuing:    []string{"*"},
	},
	Requestors: map[string]irmaserver.Requestor{
		"requestor1": {
			AuthenticationMethod: irmaserver.AuthenticationMethodPublicKey,
			AuthenticationKey:    filepath.Join(testdata, "jwtkeys", "requestor1.pem"),
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
	JwtPrivateKey: filepath.Join(testdata, "jwtkeys", "sk.pem"),
}
