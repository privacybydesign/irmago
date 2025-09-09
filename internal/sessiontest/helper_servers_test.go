package sessiontest

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	logger         = logrus.New()
	testdataFolder = test.FindTestdataFolder(nil)

	revocationTestAttr        = irma.NewAttributeTypeIdentifier("irma-demo.MijnOverheid.root.BSN")
	revocationTestCred        = revocationTestAttr.CredentialTypeIdentifier()
	revKeyshareTestAttr       = irma.NewAttributeTypeIdentifier("test.test.revocable.email")
	revKeyshareTestCred       = revKeyshareTestAttr.CredentialTypeIdentifier()
	revKeyshareSecondTestAttr = irma.NewAttributeTypeIdentifier("test.test.revocable-2.email")
	revKeyshareSecondTestCred = revKeyshareSecondTestAttr.CredentialTypeIdentifier()

	TokenAuthenticationKey = "xa6=*&9?8jeUu5>.f-%rVg`f63pHim"
	HmacAuthenticationKey  = "eGE2PSomOT84amVVdTU+LmYtJXJWZ2BmNjNwSGltCg=="

	jwtPrivkeyPath = filepath.Join(testdataFolder, "jwtkeys", "sk.pem")

	sdJwtIssuerPrivKeysDir = filepath.Join(testdataFolder, "eudi", "irma_server_config", "sdjwt_priv_keys")
	sdJwtIssuerCertsDir    = filepath.Join(testdataFolder, "eudi", "irma_server_config", "sdjwt_certs")
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

// Setup symbolic links for tests that require them
func ensureSymlinks(tb testing.TB) {
	// Some tests expect symbolic links to be present
	// Notation is <symlink location> : <target>
	symlinks := map[string]string{
		filepath.Join("..", "..", "testdata", "irma_configuration_updated", "test"):  filepath.Join("..", "..", "testdata", "irma_configuration", "test"),
		filepath.Join("..", "..", "testdata", "irma_configuration_updated", "test2"): filepath.Join("..", "..", "testdata", "irma_configuration", "test2"),
	}

	var c *exec.Cmd
	var symlinkError error

	for symlinkLocation, target := range symlinks {
		// Create the symbolic link
		switch runtime.GOOS {
		case "windows":
			if _, err := os.Stat(symlinkLocation); os.IsNotExist(err) {
				c = exec.Command("cmd", "/c", "mklink", "/J", symlinkLocation, target)
				symlinkError = c.Run()
			}

		default: //Mac & Linux
			if _, err := os.Lstat(symlinkLocation); os.IsNotExist(err) {
				symlinkError = os.Symlink(target, symlinkLocation)
			}
		}

		if symlinkError != nil {
			fmt.Println("Error creating symbolic links: ", symlinkError)
		}
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
	ensureSymlinks(t)

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

func chainedServerHandler(
	t *testing.T,
	publicKey *rsa.PublicKey,
	credentialTypes map[irma.CredentialTypeIdentifier]*irma.CredentialType,
	id irma.AttributeTypeIdentifier, cred irma.CredentialTypeIdentifier,
) http.Handler {
	mux := http.NewServeMux()

	// Note: these chained session requests just serve to test the full functionality of this
	// feature, and don't necessarily represent a chain of sessions that would be sensible or
	// desirable in production settings; probably a chain should not be longer than two sessions,
	// with an issuance session at the end.

	// Request disclosure of attribute specified by the id parameter
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

	// Read the disclosed value, and issue a new credential of type specified by the cred parameter,
	// whose attributes all have the value that was just disclosed
	mux.HandleFunc("/2", func(w http.ResponseWriter, r *http.Request) {
		bts, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())

		claims := &struct {
			jwt.RegisteredClaims
			server.SessionResult
		}{}
		_, err = jwt.ParseWithClaims(string(bts), claims, func(_ *jwt.Token) (interface{}, error) {
			//return &conf.JwtRSAPrivateKey.PublicKey, nil
			return publicKey, nil
		})
		require.NoError(t, err)
		result := claims.SessionResult
		require.Equal(t, irma.ProofStatusValid, result.ProofStatus)
		require.Len(t, result.Disclosed, 1)
		require.Len(t, result.Disclosed[0], 1)
		attr = result.Disclosed[0][0].RawValue
		require.NotNil(t, attr)

		credreq := &irma.CredentialRequest{
			CredentialTypeID: cred,
			Attributes:       map[string]string{},
		}
		for _, attrtype := range credentialTypes[cred].AttributeTypes {
			credreq.Attributes[attrtype.ID] = *attr
		}

		bts, err = json.Marshal(irma.IdentityProviderRequest{
			Request: irma.NewIssuanceRequest([]*irma.CredentialRequest{credreq}),
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

	// Disclose the newly issued attribute, and check that it has the correct value,
	// i.e. the value disclosed in session 1 that was issued to the new credential in session 2
	mux.HandleFunc("/3", func(w http.ResponseWriter, r *http.Request) {
		request := irma.NewDisclosureRequest()
		request.Disclose = irma.AttributeConDisCon{{{{
			Type:  credentialTypes[cred].AttributeTypes[0].GetAttributeTypeIdentifier(),
			Value: attr,
		}}}}
		bts, err := json.Marshal(request)
		require.NoError(t, err)
		logger.Trace("3rd request: ", string(bts))
		_, err = w.Write(bts)
		require.NoError(t, err)
	})

	// Request disclosure of attribute specified by the id parameter
	mux.HandleFunc("/unauthorized-next-session-1", func(w http.ResponseWriter, r *http.Request) {
		request := &irma.ServiceProviderRequest{
			Request: getDisclosureRequest(id),
			RequestorBaseRequest: irma.RequestorBaseRequest{
				NextSession: &irma.NextSessionData{URL: nextSessionServerURL + "/unauthorized-next-session-2"},
			},
		}
		bts, err := json.Marshal(request)
		require.NoError(t, err)
		_, err = w.Write(bts)
		require.NoError(t, err)
	})

	// Try to issue a credential without being authorized in the requestor server configuration
	mux.HandleFunc("/unauthorized-next-session-2", func(w http.ResponseWriter, r *http.Request) {
		expiry := irma.Timestamp(irma.FloorToEpochBoundary(time.Now().AddDate(1, 0, 0)))
		request := irma.NewIssuanceRequest([]*irma.CredentialRequest{
			{
				Validity:         &expiry,
				CredentialTypeID: irma.NewCredentialTypeIdentifier("irma-demo.RU.studentCard"),
				Attributes: map[string]string{
					"university":        "Radboud",
					"studentCardNumber": "31415927",
					"studentID":         "s1234567",
					"level":             "42",
				},
			},
		})
		bts, err := json.Marshal(request)
		require.NoError(t, err)
		logger.Trace("Unauthorized next session request: ", string(bts))
		_, err = w.Write(bts)
		require.NoError(t, err)
	})

	return mux
}

func StartNextRequestServer(
	t *testing.T, publicKey *rsa.PublicKey, credentialTypes map[irma.CredentialTypeIdentifier]*irma.CredentialType,
	id irma.AttributeTypeIdentifier, cred irma.CredentialTypeIdentifier,
) *http.Server {
	s := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", nextSessionServerPort),
		Handler: chainedServerHandler(t, publicKey, credentialTypes, id, cred),
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
		SchemesPath:           filepath.Join(testdataFolder, "irma_configuration"),
		IssuerPrivateKeysPath: filepath.Join(testdataFolder, "privatekeys"),
		RevocationSettings: irma.RevocationSettings{
			revocationTestCred:        {RevocationServerURL: revocationServerURL, SSE: true},
			revKeyshareTestCred:       {RevocationServerURL: revocationServerURL},
			revKeyshareSecondTestCred: {RevocationServerURL: revocationServerURL},
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
	irmaServerConf.DisableTLS = true
	irmaServerConf.SdJwtIssuanceSettings = &server.SdJwtIssuanceSettings{
		SdJwtIssuerCertificatesDir: sdJwtIssuerCertsDir,
		SdJwtIssuerPrivKeysDir:     sdJwtIssuerPrivKeysDir,
	}
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
			AuthenticationKeyFile: filepath.Join(testdataFolder, "jwtkeys", "requestor1.pem"),
			Permissions: requestorserver.Permissions{
				Hosts: []string{"localhost:48682"},
			},
		},
		"requestor2": {
			AuthenticationMethod: requestorserver.AuthenticationMethodToken,
			AuthenticationKey:    TokenAuthenticationKey,
			Permissions: requestorserver.Permissions{
				Hosts: []string{"localhost:48682"},
			},
		},
		"requestor3": {
			AuthenticationMethod: requestorserver.AuthenticationMethodHmac,
			AuthenticationKey:    HmacAuthenticationKey,
			Permissions: requestorserver.Permissions{
				Hosts: []string{"localhost:48682"},
			},
		},
	}
	return conf
}

// RequestorServerPermissionsConfiguration returns a requestor server configuration with
// 'requestor1' as requestor, is only allowed to disclose irma-demo.MijnOverheid credentials and issue the irma-demo.IRMATube.member attribute.
func RequestorServerPermissionsConfiguration() *requestorserver.Configuration {
	conf := RequestorServerConfiguration()
	irmaServerConf := IrmaServerConfiguration()
	irmaServerConf.URL = requestorServerURL + "/irma"
	conf.DisableRequestorAuthentication = false
	conf.Production = true
	conf.DisableTLS = true
	conf.AllowUnsignedCallbacks = true
	conf.Permissions = requestorserver.Permissions{}
	conf.Requestors = map[string]requestorserver.Requestor{
		"requestor1": {
			AuthenticationMethod: requestorserver.AuthenticationMethodToken,
			AuthenticationKey:    TokenAuthenticationKey,
			Permissions: requestorserver.Permissions{
				Hosts:      []string{"localhost:48682"},
				Disclosing: []string{"irma-demo.MijnOverheid.*"},
				Issuing:    []string{"irma-demo.MijnOverheid.*"},
			},
		},
	}
	return conf
}
