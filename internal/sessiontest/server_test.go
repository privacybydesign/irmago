package sessiontest

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/test"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var (
	httpServer              *http.Server
	irmaServer              *irmaserver.Server
	irmaServerConfiguration *server.Configuration
	requestorServer         *requestorserver.Server

	logger   = logrus.New()
	testdata = test.FindTestdataFolder(nil)

	revocationTestAttr  = irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	revocationTestCred  = revocationTestAttr.CredentialTypeIdentifier()
	revKeyshareTestAttr = irma.NewAttributeTypeIdentifier("test.test.email.email")
	revKeyshareTestCred = revKeyshareTestAttr.CredentialTypeIdentifier()
)

func init() {
	logger.Level = logrus.FatalLevel
	logger.Formatter = &prefixed.TextFormatter{
		ForceFormatting: true,
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: "15:04:05.000000",
	}
}

func StartRequestorServer(configuration *requestorserver.Configuration) {
	go func() {
		var err error
		if requestorServer, err = requestorserver.New(configuration); err != nil {
			panic(err)
		}
		if err = requestorServer.Start(configuration); err != nil {
			panic("Starting server failed: " + err.Error())
		}
	}()
	time.Sleep(100 * time.Millisecond) // Give server time to start
}

func StopRequestorServer() {
	requestorServer.Stop()
}

func StartIrmaServer(t *testing.T, updatedIrmaConf bool, storage string) {
	testdata := test.FindTestdataFolder(t)
	irmaconf := "irma_configuration"
	if updatedIrmaConf {
		irmaconf += "_updated"
	}

	var assets string
	path := filepath.Join(testdata, irmaconf)
	if storage != "" {
		assets = path
		path = storage
	}
	irmaServerConfiguration = &server.Configuration{
		URL:                   "http://localhost:48680",
		Logger:                logger,
		DisableSchemesUpdate:  true,
		SchemesPath:           path,
		SchemesAssetsPath:     assets,
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
		RevocationSettings: irma.RevocationSettings{
			revocationTestCred:  {RevocationServerURL: "http://localhost:48683", SSE: true},
			revKeyshareTestCred: {RevocationServerURL: "http://localhost:48683"},
		},
	}
	var err error
	irmaServer, err = irmaserver.New(irmaServerConfiguration)

	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", irmaServer.HandlerFunc())
	httpServer = &http.Server{Addr: "localhost:48680", Handler: mux}
	go func() {
		_ = httpServer.ListenAndServe()
	}()
}

func StopIrmaServer() {
	irmaServer.Stop()
	_ = httpServer.Close()
}

var IrmaServerConfiguration = &requestorserver.Configuration{
	Configuration: &server.Configuration{
		URL:                   "http://localhost:48682/irma",
		Logger:                logger,
		DisableSchemesUpdate:  true,
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
		RevocationSettings: irma.RevocationSettings{
			revocationTestCred:  {RevocationServerURL: "http://localhost:48683"},
			revKeyshareTestCred: {RevocationServerURL: "http://localhost:48683"},
		},
	},
	DisableRequestorAuthentication: true,
	ListenAddress:                  "localhost",
	Port:                           48682,
}

var JwtServerConfiguration = &requestorserver.Configuration{
	Configuration: &server.Configuration{
		URL:                   "http://localhost:48682/irma",
		Logger:                logger,
		DisableSchemesUpdate:  true,
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
		RevocationSettings: irma.RevocationSettings{
			revocationTestCred:  {RevocationServerURL: "http://localhost:48683"},
			revKeyshareTestCred: {RevocationServerURL: "http://localhost:48683"},
		},
		JwtPrivateKeyFile: filepath.Join(testdata, "jwtkeys", "sk.pem"),
		StaticSessions: map[string]interface{}{
			"staticsession": irma.ServiceProviderRequest{
				RequestorBaseRequest: irma.RequestorBaseRequest{
					CallbackURL: "http://localhost:48685",
				},
				Request: &irma.DisclosureRequest{
					BaseRequest: irma.BaseRequest{LDContext: irma.LDContextDisclosureRequest},
					Disclose: irma.AttributeConDisCon{
						{{irma.NewAttributeRequest("irma-demo.RU.studentCard.level")}},
					},
				},
			},
		},
	},
	ListenAddress:                  "localhost",
	Port:                           48682,
	DisableRequestorAuthentication: false,
	MaxRequestAge:                  3,
	Permissions: requestorserver.Permissions{
		Disclosing: []string{"*"},
		Signing:    []string{"*"},
		Issuing:    []string{"*"},
	},
	Requestors: map[string]requestorserver.Requestor{
		"requestor1": {
			AuthenticationMethod:  requestorserver.AuthenticationMethodPublicKey,
			AuthenticationKeyFile: filepath.Join(testdata, "jwtkeys", "requestor1.pem"),
		},
		"requestor2": {
			AuthenticationMethod: requestorserver.AuthenticationMethodToken,
			AuthenticationKey:    "xa6=*&9?8jeUu5>.f-%rVg`f63pHim",
		},
		"requestor3": {
			AuthenticationMethod: requestorserver.AuthenticationMethodHmac,
			AuthenticationKey:    "eGE2PSomOT84amVVdTU+LmYtJXJWZ2BmNjNwSGltCg==",
		},
	},
}
