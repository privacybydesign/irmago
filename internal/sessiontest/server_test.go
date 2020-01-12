package sessiontest

import (
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/jinzhu/gorm"
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

	revocationConfiguration *server.Configuration
	logger                  = logrus.New()
	testdata                = test.FindTestdataFolder(nil)
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

	irma.Logger = logger

	//dbtype, dbstr := "postgres", "host=127.0.0.1 port=5432 user=testuser dbname=test password='testpassword' sslmode=disable"
	dbtype, dbstr := "mysql", "testuser:testpassword@tcp(127.0.0.1)/test"

	// Connect to database and clear records from previous test runs
	g, err := gorm.Open(dbtype, dbstr)
	require.NoError(t, err)
	require.NoError(t, g.DropTableIfExists((*irma.EventRecord)(nil)).Error)
	require.NoError(t, g.DropTableIfExists((*irma.AccumulatorRecord)(nil)).Error)
	require.NoError(t, g.DropTableIfExists((*irma.IssuanceRecord)(nil)).Error)
	require.NoError(t, g.AutoMigrate((*irma.EventRecord)(nil)).Error)
	require.NoError(t, g.AutoMigrate((*irma.AccumulatorRecord)(nil)).Error)
	require.NoError(t, g.AutoMigrate((*irma.IssuanceRecord)(nil)).Error)
	require.NoError(t, g.Close())

	cred := irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root")
	settings := map[irma.CredentialTypeIdentifier]*irma.RevocationSetting{
		cred: {Mode: irma.RevocationModeServer},
	}
	irmaconf, err := irma.NewConfiguration(filepath.Join(testdata, "irma_configuration"), irma.ConfigurationOptions{
		RevocationDBConnStr: dbstr,
		RevocationDBType:    dbtype,
		RevocationSettings:  settings,
	})
	require.NoError(t, err)
	require.NoError(t, irmaconf.ParseFolder())

	conf := &server.Configuration{
		Logger:               logger,
		DisableSchemesUpdate: true,
		SchemesPath:          filepath.Join(testdata, "irma_configuration"),
		RevocationSettings:   settings,
		IrmaConfiguration:    irmaconf,
		RevocationDBConnStr:  dbstr,
		RevocationDBType:     dbtype,
	}

	// Enable revocation for our credential type
	sk, err := irmaconf.Revocation.Keys.PrivateKeyLatest(cred.IssuerIdentifier())
	require.NoError(t, err)
	require.NoError(t, irmaconf.Revocation.EnableRevocation(cred, sk))

	// Start revocation server
	revocationServer, err = irmaserver.New(conf)
	revocationConfiguration = conf
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
		RevocationSettings: map[irma.CredentialTypeIdentifier]*irma.RevocationSetting{
			irma.NewCredentialTypeIdentifier("irma-demo.MijnOverheid.root"): {
				ServerURL: "http://localhost:48683/",
			},
		},
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
	},
	Port: 48682,
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
