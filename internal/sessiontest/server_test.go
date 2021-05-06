package sessiontest

import (
	"encoding/json"
	"github.com/alicebob/miniredis"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
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
	nextRequestServer       *http.Server
	irmaServer              *irmaserver.Server
	irmaServerConfiguration *server.Configuration
	requestorServer         *requestorserver.Server
	testWithRedis           bool
	mr                      *miniredis.Miniredis

	logger   = logrus.New()
	testdata = test.FindTestdataFolder(nil)

	revocationTestAttr  = irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	revocationTestCred  = revocationTestAttr.CredentialTypeIdentifier()
	revKeyshareTestAttr = irma.NewAttributeTypeIdentifier("test.test.email.email")
	revKeyshareTestCred = revKeyshareTestAttr.CredentialTypeIdentifier()
)

func init() {
	common.ForceHTTPS = false // globally disable https enforcement
	irma.SetLogger(logger)
	logger.Level = logrus.FatalLevel
	logger.Formatter = &prefixed.TextFormatter{
		ForceFormatting: true,
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: "15:04:05.000000",
	}
}

func StartMiniRedis() {
	if mr == nil {
		var err error
		mr, err = miniredis.Run()
		if err != nil {
			panic(err)
		}
	}
}

func StopRedis() {
	if mr != nil {
		mr.Close()
	}
}

func maybeUseRedisInRequestor(c *requestorserver.Configuration) {
	if testWithRedis {
		StartMiniRedis()
		c.StoreType = "redis"
		c.RedisSettings.Host = mr.Host()
		c.RedisSettings.Port = mr.Port()
	} else {
		c.StoreType = "memory"
	}
}

func maybeUseRedis(c *server.Configuration) {
	if testWithRedis {
		StartMiniRedis()
		c.StoreType = "redis"
		c.RedisSettings.Host = mr.Host()
		c.RedisSettings.Port = mr.Port()
	} else {
		c.StoreType = "memory"
	}
}

func StartRequestorServer(configuration *requestorserver.Configuration) {
	go func() {
		maybeUseRedisInRequestor(configuration)
		var err error
		if requestorServer, err = requestorserver.New(configuration); err != nil {
			panic(err)
		}
		if err = requestorServer.Start(configuration); err != nil {
			panic("Starting server failed: " + err.Error())
		}
	}()
	time.Sleep(200 * time.Millisecond) // Give server time to start
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
	maybeUseRedis(irmaServerConfiguration)
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

func chainedServerHandler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	id := irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.studentID")

	// Note: these chained session requests just serve to test the full functionality of this
	// feature, and don't necessarily represent a chain of sessions that would be sensible or
	// desirable in production settings; probably a chain should not be longer than two sessions,
	// with an issuance session at the end.

	mux.HandleFunc("/1", func(w http.ResponseWriter, r *http.Request) {
		request := &irma.ServiceProviderRequest{
			Request: getDisclosureRequest(id),
			RequestorBaseRequest: irma.RequestorBaseRequest{
				NextSession: &irma.NextSessionData{URL: "http://localhost:48686/2"},
			},
		}
		bts, err := json.Marshal(request)
		require.NoError(t, err)
		_, err = w.Write(bts)
		require.NoError(t, err)
	})

	var attr *string
	mux.HandleFunc("/2", func(w http.ResponseWriter, r *http.Request) {
		bts, err := ioutil.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())

		var result server.SessionResult
		require.NoError(t, json.Unmarshal(bts, &result))
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.Len(t, result.Disclosed, 1)
		require.Len(t, result.Disclosed[0], 1)
		attr = result.Disclosed[0][0].RawValue
		require.NotNil(t, attr)

		cred := &irma.CredentialRequest{
			CredentialTypeID: id.CredentialTypeIdentifier(),
			Attributes: map[string]string{
				"level":             *attr,
				"studentCardNumber": *attr,
				"studentID":         *attr,
				"university":        *attr,
			},
		}

		bts, err = json.Marshal(irma.IdentityProviderRequest{
			Request: irma.NewIssuanceRequest([]*irma.CredentialRequest{cred}),
			RequestorBaseRequest: irma.RequestorBaseRequest{
				NextSession: &irma.NextSessionData{URL: "http://localhost:48686/3"},
			},
		})
		require.NoError(t, err)

		logger.Trace("2nd request: ", string(bts))
		_, err = w.Write(bts)
		require.NoError(t, err)
	})

	mux.HandleFunc("/3", func(w http.ResponseWriter, r *http.Request) {
		request := irma.NewDisclosureRequest()
		request.Disclose = irma.AttributeConDisCon{{{{
			Type:  irma.NewAttributeTypeIdentifier("irma-demo.RU.studentCard.level"),
			Value: attr,
		}}}}
		bts, err := json.Marshal(request)
		require.NoError(t, err)
		logger.Trace("3rd request: ", string(bts))
		_, err = w.Write(bts)
		require.NoError(t, err)
	})

	return mux
}

func StartNextRequestServer(t *testing.T) {
	nextRequestServer = &http.Server{
		Addr:    "localhost:48686",
		Handler: chainedServerHandler(t),
	}
	go func() {
		_ = nextRequestServer.ListenAndServe()
	}()
}

func StopNextRequestServer() {
	_ = nextRequestServer.Close()
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
