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
	"github.com/x-cray/logrus-prefixed-formatter"
)

var (
	httpServer       *http.Server
	irmaServer       *irmaserver.Server
	revHttpServer    *http.Server
	revocationServer *irmaserver.Server
	requestorServer  *requestorserver.Server

	logger   = logrus.New()
	testdata = test.FindTestdataFolder(nil)
)

func init() {
	logger.Level = logrus.TraceLevel
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

func StartRevocationServer(t *testing.T) {
	var err error
	cred := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
	conf := &server.Configuration{
		Logger:               logger,
		DisableSchemesUpdate: true,
		SchemesPath:          filepath.Join(testdata, "irma_configuration"),
		RevocationPath:       filepath.Join(testdata, "tmp", "issuer"), // todo rename this path to revocation?
		RevocationServers: map[irma.CredentialTypeIdentifier]server.RevocationServer{
			cred: {},
		},
	}
	revocationServer, err = irmaserver.New(conf)
	require.NoError(t, err)

	sk, err := conf.PrivateKey(cred.IssuerIdentifier())
	require.NoError(t, err)
	require.NotNil(t, sk)
	revsk, err := sk.RevocationKey()
	require.NoError(t, err)
	db, err := conf.IrmaConfiguration.RevocationStorage.DB(cred)
	require.NoError(t, err)
	err = db.EnableRevocation(revsk)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", revocationServer.HandlerFunc())
	revHttpServer = &http.Server{Addr: ":48683", Handler: mux}
	go func() {
		_ = revHttpServer.ListenAndServe()
	}()
}

func StopRevocationServer() {
	revocationServer.Stop()
	_ = revHttpServer.Close()
}

func StartIrmaServer(t *testing.T, updatedIrmaConf bool) {
	testdata := test.FindTestdataFolder(t)
	irmaconf := "irma_configuration"
	if updatedIrmaConf {
		irmaconf += "_updated"
	}

	var err error
	irmaServer, err = irmaserver.New(&server.Configuration{
		URL:                  "http://localhost:48680",
		Logger:               logger,
		DisableSchemesUpdate: true,
		SchemesPath:          filepath.Join(testdata, irmaconf),
		RevocationPath:       filepath.Join(testdata, "tmp", "revocation"),
	})

	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", irmaServer.HandlerFunc())
	httpServer = &http.Server{Addr: ":48680", Handler: mux}
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
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
		RevocationPath:        filepath.Join(testdata, "tmp", "revocation"),
	},
	DisableRequestorAuthentication: true,
	Port: 48682,
}

var JwtServerConfiguration = &requestorserver.Configuration{
	Configuration: &server.Configuration{
		URL:                   "http://localhost:48682/irma",
		Logger:                logger,
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
		RevocationPath:        filepath.Join(testdata, "tmp", "revocation"),
	},
	Port: 48682,
	DisableRequestorAuthentication: false,
	MaxRequestAge: 3,
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
	JwtPrivateKeyFile: filepath.Join(testdata, "jwtkeys", "sk.pem"),
}
