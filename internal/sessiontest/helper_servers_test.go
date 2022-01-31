package sessiontest

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
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
	revKeyshareTestAttr = irma.NewAttributeTypeIdentifier("test.test.email.email")
	revKeyshareTestCred = revKeyshareTestAttr.CredentialTypeIdentifier()

	TokenAuthenticationKey = "xa6=*&9?8jeUu5>.f-%rVg`f63pHim"
	HmacAuthenticationKey  = "eGE2PSomOT84amVVdTU+LmYtJXJWZ2BmNjNwSGltCg=="

	jwtPrivkeyPath = filepath.Join(testdata, "jwtkeys", "sk.pem")
)

// Some urls are hardcoded in the test configuration, so we have to hardcode them here too.
const (
	schemeServerURL = "http://localhost:48681"

	revocationServerPort = 48683
	revocationServerURL  = "http://localhost:48683"
)

// The doSession helper expects the requestor server URL to be globally defined, to support the optionReuseServer.
var (
	requestorServerPort = findFreePort()
	requestorServerURL  = fmt.Sprintf("http://localhost:%d", requestorServerPort)
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

func findFreePort() int {
	s := httptest.NewUnstartedServer(http.NotFoundHandler())
	defer s.Close()
	return s.Listener.Addr().(*net.TCPAddr).Port
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

	mux := http.NewServeMux()
	httpServer := httptest.NewServer(mux)

	// Make sure domain is used instead of IP address.
	conf.URL = strings.Replace(httpServer.URL, "127.0.0.1", "localhost", 1)
	irmaServer, err := irmaserver.New(conf)
	require.NoError(t, err)

	mux.HandleFunc("/", irmaServer.HandlerFunc())
	return &IrmaServer{
		irma: irmaServer,
		conf: conf,
		http: httpServer.Config,
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
				NextSession: &irma.NextSessionData{URL: fmt.Sprintf("http://%s/2", r.Host)},
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
				NextSession: &irma.NextSessionData{URL: fmt.Sprintf("http://%s/3", r.Host)},
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

func IrmaServerConfiguration() *server.Configuration {
	return &server.Configuration{
		Logger:                logger,
		DisableSchemesUpdate:  true,
		SchemesPath:           filepath.Join(testdata, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdata, "privatekeys"),
		RevocationSettings: irma.RevocationSettings{
			revocationTestCred:  {RevocationServerURL: revocationServerURL, SSE: true},
			revKeyshareTestCred: {RevocationServerURL: revocationServerURL},
		},
		JwtPrivateKeyFile: jwtPrivkeyPath,
		StaticSessions:    map[string]interface{}{},
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
