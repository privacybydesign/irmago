package sessiontest

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
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
	logger   = logrus.New()
	testdata = test.FindTestdataFolder(nil)

	revocationTestAttr  = irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	revocationTestCred  = revocationTestAttr.CredentialTypeIdentifier()
	revKeyshareTestAttr = irma.NewAttributeTypeIdentifier("test.test.revocable.email")
	revKeyshareTestCred = revKeyshareTestAttr.CredentialTypeIdentifier()

	TokenAuthenticationKey = "xa6=*&9?8jeUu5>.f-%rVg`f63pHim"
	HmacAuthenticationKey  = "eGE2PSomOT84amVVdTU+LmYtJXJWZ2BmNjNwSGltCg=="

	jwtPrivkeyPath = filepath.Join(testdata, "jwtkeys", "sk.pem")
)

const (
	irmaServerPort = 48680

	schemeServerURL = "http://localhost:48681"

	requestorServerPort = 48682
	requestorServerURL  = "http://localhost:48682"

	revocationServerPort = 48683
	revocationServerURL  = "http://localhost:48683"

	staticSessionServerPort = 48685
	staticSessionServerURL  = "http://localhost:48685"

	nextSessionServerPort = 48686
	nextSessionServerURL  = "http://localhost:48686"
)

type IrmaServer struct {
	irma *irmaserver.Server
	http *http.Server
	conf *server.Configuration
}

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

// apply performs partial function application: it takes (1) a test function which apart from
// *testing.T additionally accepting a configuration function and session options, and (2) a
// configuration function and session objects, and returns a function suitable for unit testing by
// applying the configuration function and session options in the rightmost two parameter slots of
// the specified function.
func apply(
	test func(t *testing.T, conf interface{}, opts ...option),
	conf interface{}, opts ...option,
) func(*testing.T) {
	return func(t *testing.T) {
		test(t, conf, opts...)
	}
}

func StartRequestorServer(t *testing.T, configuration *requestorserver.Configuration) *requestorserver.Server {
	requestorServer, err := requestorserver.New(configuration)
	require.NoError(t, err)
	go func() {
		err := requestorServer.Start(configuration)
		require.NoError(t, err)
	}()
	time.Sleep(200 * time.Millisecond) // Give server time to start
	return requestorServer
}

func StartIrmaServer(t *testing.T, conf *server.Configuration) *IrmaServer {
	if conf == nil {
		conf = IrmaServerConfiguration()
	}

	irmaServer, err := irmaserver.New(conf)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", irmaServer.HandlerFunc())
	httpServer := &http.Server{Addr: fmt.Sprintf("localhost:%d", irmaServerPort), Handler: mux}
	go func() {
		_ = httpServer.ListenAndServe()
	}()
	return &IrmaServer{
		irma: irmaServer,
		conf: conf,
		http: httpServer,
	}
}

func (s *IrmaServer) Stop() {
	s.irma.Stop()
	_ = s.http.Close()
}

func chainedServerHandler(t *testing.T, jwtPubKey *rsa.PublicKey) http.Handler {
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
				NextSession: &irma.NextSessionData{URL: nextSessionServerURL + "/2"},
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

		claims := &struct {
			jwt.RegisteredClaims
			server.SessionResult
		}{}
		_, err = jwt.ParseWithClaims(string(bts), claims, func(_ *jwt.Token) (interface{}, error) {
			return jwtPubKey, nil
		})
		require.NoError(t, err)
		result := claims.SessionResult
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
				NextSession: &irma.NextSessionData{URL: nextSessionServerURL + "/3"},
			},
		})
		require.NoError(t, err)

		// Simulate a slowly responding server
		time.Sleep(200 * time.Millisecond)

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

func StartNextRequestServer(t *testing.T, jwtPubKey *rsa.PublicKey) *http.Server {
	s := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", nextSessionServerPort),
		Handler: chainedServerHandler(t, jwtPubKey),
	}
	go func() {
		_ = s.ListenAndServe()
	}()
	return s
}

func IrmaServerConfiguration() *server.Configuration {
	return &server.Configuration{
		URL:                   fmt.Sprintf("http://localhost:%d", irmaServerPort),
		Logger:                logger,
		DisableSchemesUpdate:  true,
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
		RevocationSettings: irma.RevocationSettings{
			revocationTestCred:  {RevocationServerURL: revocationServerURL, SSE: true},
			revKeyshareTestCred: {RevocationServerURL: revocationServerURL},
		},
		JwtPrivateKeyFile: jwtPrivkeyPath,
		StaticSessions: map[string]interface{}{
			"staticsession": irma.ServiceProviderRequest{
				RequestorBaseRequest: irma.RequestorBaseRequest{
					CallbackURL: staticSessionServerURL,
				},
				Request: &irma.DisclosureRequest{
					BaseRequest: irma.BaseRequest{LDContext: irma.LDContextDisclosureRequest},
					Disclose: irma.AttributeConDisCon{
						{{irma.NewAttributeRequest("irma-demo.RU.studentCard.level")}},
					},
				},
			},
		},
	}
}

func RequestorServerConfiguration() *requestorserver.Configuration {
	irmaServerConf := IrmaServerConfiguration()
	irmaServerConf.URL = requestorServerURL + "/irma"
	return &requestorserver.Configuration{
		Configuration:                  irmaServerConf,
		DisableRequestorAuthentication: true,
		ListenAddress:                  "localhost",
		Port:                           requestorServerPort,
		MaxRequestAge:                  3,
		Permissions: requestorserver.Permissions{
			Disclosing: []string{"*"},
			Signing:    []string{"*"},
			Issuing:    []string{"*"},
		},
	}
}

func RequestorServerAuthConfiguration() *requestorserver.Configuration {
	conf := RequestorServerConfiguration()
	conf.DisableRequestorAuthentication = false
	conf.Requestors = map[string]requestorserver.Requestor{
		"requestor1": {
			AuthenticationMethod:  requestorserver.AuthenticationMethodPublicKey,
			AuthenticationKeyFile: filepath.Join(testdata, "jwtkeys", "requestor1.pem"),
		},
		"requestor2": {
			AuthenticationMethod: requestorserver.AuthenticationMethodToken,
			AuthenticationKey:    TokenAuthenticationKey,
		},
		"requestor3": {
			AuthenticationMethod: requestorserver.AuthenticationMethodHmac,
			AuthenticationKey:    HmacAuthenticationKey,
		},
	}
	return conf
}
