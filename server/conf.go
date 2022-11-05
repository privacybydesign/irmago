package server

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-co-op/gocron"
	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/gabi/gabikeys"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/sirupsen/logrus"
)

// Configuration contains configuration for the irmaserver library and irmad.
type Configuration struct {
	// irma_configuration. If not given, this will be popupated using SchemesPath.
	IrmaConfiguration *irma.Configuration `json:"-"`
	// Path to IRMA schemes to parse into IrmaConfiguration (only used if IrmaConfiguration == nil).
	// If left empty, default value is taken using DefaultSchemesPath().
	// If an empty folder is specified, default schemes (irma-demo and pbdf) are downloaded into it.
	SchemesPath string `json:"schemes_path" mapstructure:"schemes_path"`
	// If specified, schemes found here are copied into SchemesPath (only used if IrmaConfiguration == nil)
	SchemesAssetsPath string `json:"schemes_assets_path" mapstructure:"schemes_assets_path"`
	// Disable scheme updating
	DisableSchemesUpdate bool `json:"disable_schemes_update" mapstructure:"disable_schemes_update"`
	// Update all schemes every x minutes (default value 0 means 60) (use DisableSchemesUpdate to disable)
	SchemesUpdateInterval int `json:"schemes_update" mapstructure:"schemes_update"`
	// Path to issuer private keys to parse
	IssuerPrivateKeysPath string `json:"privkeys" mapstructure:"privkeys"`
	// URL at which the IRMA app can reach this server during sessions
	URL string `json:"url" mapstructure:"url"`
	// Required to be set to true if URL does not begin with https:// in production mode.
	// In this case, the server would communicate with IRMA apps over plain HTTP. You must otherwise
	// ensure (using eg a reverse proxy with TLS enabled) that the attributes are protected in transit.
	DisableTLS bool `json:"disable_tls" mapstructure:"disable_tls"`
	// (Optional) email address of server admin, for incidental notifications such as breaking API changes
	// See https://github.com/privacybydesign/irmago/tree/master/server#specifying-an-email-address
	// for more information
	Email string `json:"email" mapstructure:"email"`
	// Enable server sent events for status updates (experimental; tends to hang when a reverse proxy is used)
	EnableSSE bool `json:"enable_sse" mapstructure:"enable_sse"`
	// StoreType in which session data will be stored.
	// If left empty, session data will be stored in memory by default.
	StoreType string `json:"store_type" mapstructure:"store_type"`
	// RedisSettings that need to be specified when Redis is used as session data store.
	RedisSettings *RedisSettings `json:"redis_settings" mapstructure:"redis_settings"`

	// Static session requests that can be created by POST /session/{name}
	StaticSessions map[string]interface{} `json:"static_sessions"`
	// Static session requests after parsing
	StaticSessionRequests map[string]irma.RequestorRequest `json:"-"`

	// Session Timeout in minutes (default value 0 means 5)
	MaxSessionLifetime int `json:"max_session_lifetime" mapstructure:"max_session_lifetime"`

	// Used in the "iss" field of result JWTs from /result-jwt and /getproof
	JwtIssuer string `json:"jwt_issuer" mapstructure:"jwt_issuer"`
	// Private key to sign result JWTs with. If absent, /result-jwt and /getproof are disabled.
	JwtPrivateKey     string `json:"jwt_privkey" mapstructure:"jwt_privkey"`
	JwtPrivateKeyFile string `json:"jwt_privkey_file" mapstructure:"jwt_privkey_file"`
	// Parsed JWT private key
	JwtRSAPrivateKey *rsa.PrivateKey `json:"-"`
	// Whether to allow callbackUrl to be set in session requests when no JWT privatekey is installed
	// (which is potentially unsafe depending on the setup)
	AllowUnsignedCallbacks bool `json:"allow_unsigned_callbacks" mapstructure:"allow_unsigned_callbacks"`
	// Whether to augment the clientreturnurl with the server token of the request (this allows for stateless
	// requestor servers more easily)
	AugmentClientReturnURL bool `json:"augment_client_return_url" mapstructure:"augment_client_return_url"`

	// Logging verbosity level: 0 is normal, 1 includes DEBUG level, 2 includes TRACE level
	Verbose int `json:"verbose" mapstructure:"verbose"`
	// Don't log anything at all
	Quiet bool `json:"quiet" mapstructure:"quiet"`
	// Output structured log in JSON format
	LogJSON bool `json:"log_json" mapstructure:"log_json"`
	// Custom logger instance. If specified, Verbose, Quiet and LogJSON are ignored.
	Logger *logrus.Logger `json:"-"`

	// Connection string for revocation database
	RevocationDBConnStr string `json:"revocation_db_str" mapstructure:"revocation_db_str"`
	// Database type for revocation database, supported: postgres, mysql
	RevocationDBType string `json:"revocation_db_type" mapstructure:"revocation_db_type"`
	// Credentials types for which revocation database should be hosted
	RevocationSettings irma.RevocationSettings `json:"revocation_settings" mapstructure:"revocation_settings"`

	// Production mode: enables safer and stricter defaults and config checking
	Production bool `json:"production" mapstructure:"production"`
}

type RedisSettings struct {
	Addr     string `json:"address,omitempty" mapstructure:"address"`
	Password string `json:"password,omitempty" mapstructure:"password"`
	DB       int    `json:"db,omitempty" mapstructure:"db"`

	TLSCertificate     string `json:"tls_cert,omitempty" mapstructure:"tls_cert"`
	TLSCertificateFile string `json:"tls_cert_file,omitempty" mapstructure:"tls_cert_file"`
	DisableTLS         bool   `json:"no_tls,omitempty" mapstructure:"no_tls"`
}

// Check ensures that the Configuration is loaded, usable and free of errors.
func (conf *Configuration) Check() error {
	if conf.Logger == nil {
		conf.Logger = NewLogger(conf.Verbose, conf.Quiet, conf.LogJSON)
	}
	Logger = conf.Logger
	irma.SetLogger(conf.Logger)

	// Use default session lifetime if not specified
	if conf.MaxSessionLifetime == 0 {
		conf.MaxSessionLifetime = 5
	}

	// loop to avoid repetetive err != nil line triplets
	for _, f := range []func() error{
		conf.verifyIrmaConf,
		conf.verifyPrivateKeys,
		conf.verifyURL,
		conf.verifyEmail,
		conf.verifyRevocation,
		conf.verifyJwtPrivateKey,
		conf.verifyStaticSessions,
	} {
		if err := f(); err != nil {
			_ = LogError(err)
			if conf.IrmaConfiguration != nil && conf.IrmaConfiguration.Revocation != nil {
				if e := conf.IrmaConfiguration.Revocation.Close(); e != nil {
					_ = LogError(e)
				}
			}
			return err
		}
	}

	if conf.EnableSSE && conf.StoreType == "redis" {
		return errors.New("Currently server-sent events (SSE) cannot be used simultaneously with the Redis session store.")
	}

	return nil
}

func (conf *Configuration) HavePrivateKeys() bool {
	var err error
	for id := range conf.IrmaConfiguration.Issuers {
		if conf.IrmaConfiguration.SchemeManagers[id.SchemeManagerIdentifier()].Demo {
			continue
		}
		if _, err = conf.IrmaConfiguration.PrivateKeys.Latest(id); err == nil {
			return true
		}
	}
	return false
}

// helpers

func (conf *Configuration) verifyStaticSessions() error {
	conf.StaticSessionRequests = make(map[string]irma.RequestorRequest)
	if len(conf.StaticSessions) > 0 && conf.JwtRSAPrivateKey == nil && !conf.AllowUnsignedCallbacks {
		return errors.New("static sessions configured but no JWT private key is installed: either install JWT or enable allow_unsigned_callbacks in configuration")
	}
	for name, r := range conf.StaticSessions {
		if !regexp.MustCompile("^[a-zA-Z0-9_]+$").MatchString(name) {
			return errors.Errorf("static session name %s not allowed, must be alphanumeric", name)
		}
		j, err := json.Marshal(r)
		if err != nil {
			return errors.WrapPrefix(err, "failed to parse static session request "+name, 0)
		}
		rrequest, err := ParseSessionRequest(j)
		if err != nil {
			return errors.WrapPrefix(err, "failed to parse static session request "+name, 0)
		}
		action := rrequest.SessionRequest().Action()
		if action != irma.ActionDisclosing && action != irma.ActionSigning {
			return errors.Errorf("static session %s must be either a disclosing or signing session", name)
		}
		base := rrequest.Base()
		if base.CallbackURL == "" && (base.NextSession == nil || base.NextSession.URL == "") {
			return errors.Errorf("static session %s has no callback URL or next session URL", name)
		}
		conf.StaticSessionRequests[name] = rrequest
	}
	return nil
}

func GocronPanicHandler(logger *logrus.Logger) gocron.PanicHandlerFunc {
	return func(jobName string, recoverData interface{}) {
		var details string
		b, err := json.Marshal(recoverData)
		if err == nil {
			details = string(b)
		} else {
			details = "failed to marshal recovered data: " + err.Error()
		}
		logger.Error(fmt.Sprintf("panic during gocron job '%s': %s", jobName, details))
	}
}

func (conf *Configuration) verifyIrmaConf() error {
	if conf.IrmaConfiguration == nil {
		var (
			err    error
			exists bool
		)
		if conf.SchemesPath == "" {
			conf.SchemesPath = irma.DefaultSchemesPath() // Returns an existing path
		}
		if exists, err = common.PathExists(conf.SchemesPath); err != nil {
			return err
		}
		if !exists {
			return errors.Errorf("Nonexisting schemes_path provided: %s", conf.SchemesPath)
		}
		conf.Logger.WithField("schemes_path", conf.SchemesPath).Info("Determined schemes path")
		conf.IrmaConfiguration, err = irma.NewConfiguration(conf.SchemesPath, irma.ConfigurationOptions{
			Assets:              conf.SchemesAssetsPath,
			RevocationDBType:    conf.RevocationDBType,
			RevocationDBConnStr: conf.RevocationDBConnStr,
			RevocationSettings:  conf.RevocationSettings,
		})
		if err != nil {
			return err
		}
		if err = conf.IrmaConfiguration.ParseFolder(); err != nil {
			return err
		}
	}

	if len(conf.IrmaConfiguration.SchemeManagers) == 0 {
		conf.Logger.Infof("No schemes found in %s, downloading default (irma-demo and pbdf)", conf.SchemesPath)
		if err := conf.IrmaConfiguration.DownloadDefaultSchemes(); err != nil {
			return err
		}
	}
	if conf.SchemesUpdateInterval == 0 {
		conf.SchemesUpdateInterval = 60
	}
	if !conf.DisableSchemesUpdate {
		if err := conf.IrmaConfiguration.AutoUpdateSchemes(conf.SchemesUpdateInterval); err != nil {
			return err
		}
	}

	return nil
}

func (conf *Configuration) verifyPrivateKeys() error {
	if conf.IssuerPrivateKeysPath == "" {
		return nil
	}
	ring, err := irma.NewPrivateKeyRingFolder(conf.IssuerPrivateKeysPath, conf.IrmaConfiguration)
	if err != nil {
		return err
	}
	return conf.IrmaConfiguration.AddPrivateKeyRing(ring)
}

func (conf *Configuration) prepareRevocation(credid irma.CredentialTypeIdentifier) error {
	var sk *gabikeys.PrivateKey
	err := conf.IrmaConfiguration.PrivateKeys.Iterate(credid.IssuerIdentifier(), func(isk *gabikeys.PrivateKey) error {
		if !isk.RevocationSupported() {
			return nil
		}
		sk = isk
		exists, err := conf.IrmaConfiguration.Revocation.Exists(credid, isk.Counter)
		if err != nil {
			return errors.WrapPrefix(err, fmt.Sprintf("failed to check if accumulator exists for %s-%d", credid, isk.Counter), 0)
		}
		if !exists {
			conf.Logger.Warnf("Creating initial accumulator for %s-%d", credid, isk.Counter)
			if err = conf.IrmaConfiguration.Revocation.EnableRevocation(credid, sk); err != nil {
				return errors.WrapPrefix(err, fmt.Sprintf("failed create initial accumulator for %s-%d", credid, isk.Counter), 0)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if sk == nil {
		return errors.Errorf("revocation server mode enabled for %s but no private key installed", credid)
	}
	return nil
}

func (conf *Configuration) verifyRevocation() error {
	rev := conf.IrmaConfiguration.Revocation

	// viper lowercases configuration keys, so we have to un-lowercase them back.
	for id := range conf.IrmaConfiguration.CredentialTypes {
		lc := irma.NewCredentialTypeIdentifier(strings.ToLower(id.String()))
		if lc == id {
			continue
		}
		if s, ok := conf.RevocationSettings[lc]; ok {
			delete(conf.RevocationSettings, lc)
			conf.RevocationSettings[id] = s
		}
	}

	for credid, settings := range conf.RevocationSettings {
		if _, known := conf.IrmaConfiguration.CredentialTypes[credid]; !known {
			return errors.Errorf("unknown credential type %s in revocation settings", credid)
		}
		if settings.Authority {
			conf.Logger.Info("authoritative revocation server mode enabled for " + credid.String())
			if err := conf.prepareRevocation(credid); err != nil {
				return err
			}
		} else if settings.Server {
			conf.Logger.Info("revocation server mode enabled for " + credid.String())
		}
		if settings.Server {
			conf.Logger.Info("Being the revocation server for a credential type comes with special responsibilities. Failure can lead to all IRMA apps being unable to disclose credentials of this type. Read more at https://irma.app/docs/revocation/#issuer-responsibilities.")
		}
	}

	for credid, credtype := range conf.IrmaConfiguration.CredentialTypes {
		if !credtype.RevocationSupported() {
			continue
		}
		_, err := rev.Keys.PrivateKeyLatest(credid.IssuerIdentifier())
		haveSK := err == nil
		settings := conf.RevocationSettings[credid]
		if haveSK && (settings == nil || (settings.RevocationServerURL == "" && !settings.Server)) {
			message := "Revocation-supporting private key installed for %s, but no revocation server is configured: issuance sessions will always fail"
			if conf.IrmaConfiguration.SchemeManagers[credid.IssuerIdentifier().SchemeManagerIdentifier()].Demo {
				conf.Logger.Warnf(message, credid)
			} else {
				return errors.Errorf(message, credid)
			}
		}
		if settings != nil && settings.RevocationServerURL != "" {
			url := settings.RevocationServerURL
			if url[len(url)-1] == '/' {
				settings.RevocationServerURL = url[:len(url)-1]
			}
		}
	}

	return nil
}

func (conf *Configuration) verifyURL() error {
	if conf.URL != "" {
		if !strings.HasSuffix(conf.URL, "/") {
			conf.URL = conf.URL + "/"
		}
		if !strings.HasPrefix(conf.URL, "https://") {
			if !conf.Production || conf.DisableTLS {
				conf.DisableTLS = true
				conf.Logger.Warnf("TLS is not enabled on the url \"%s\" to which the IRMA app will connect. "+
					"Ensure that attributes are encrypted in transit by either enabling TLS or adding TLS in a reverse proxy.", conf.URL)
			} else {
				return errors.Errorf("Running without TLS in production mode is unsafe without a reverse proxy. " +
					"Either use a https:// URL or explicitly disable TLS.")
			}
		}
	} else {
		conf.Logger.Warn("No url parameter specified in configuration; unless an url is elsewhere prepended in the QR, the IRMA client will not be able to connect")
	}
	return nil
}

type serverInfo struct {
	Email   string `json:"email"`
	Version string `json:"version"`
}

func (conf *Configuration) verifyEmail() error {
	if conf.Email == "" {
		return nil
	}
	if !strings.Contains(conf.Email, "@") || strings.Contains(conf.Email, "\n") {
		return errors.New("Invalid email address specified")
	}
	t := irma.NewHTTPTransport("https://privacybydesign.foundation/", true)
	t.SetHeader("User-Agent", "irmaserver")
	data := &serverInfo{Email: conf.Email, Version: irma.Version}

	go func() {
		err := t.Post("serverinfo/", nil, data)
		if err != nil {
			conf.Logger.Trace("Failed to send email and version number:", err)
		}
	}()

	return nil
}

func (conf *Configuration) verifyJwtPrivateKey() error {
	if conf.JwtPrivateKey == "" && conf.JwtPrivateKeyFile == "" {
		return nil
	}

	keybytes, err := common.ReadKey(conf.JwtPrivateKey, conf.JwtPrivateKeyFile)
	if err != nil {
		return errors.WrapPrefix(err, "failed to read private key", 0)
	}

	conf.JwtRSAPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(keybytes)
	conf.Logger.Info("Private key parsed, JWT endpoints enabled")
	return err
}

// ReplacePortString is a helper that returns a copy of the specified url of the form
// "http(s)://...:port" with "port" replaced by the specified port.
func ReplacePortString(url string, port int) string {
	return regexp.MustCompile("(https?://[^/]*):port").ReplaceAllString(url, "$1:"+strconv.Itoa(port))
}

func TLSConf(cert, certfile, key, keyfile string) (*tls.Config, error) {
	if cert == "" && certfile == "" && key == "" && keyfile == "" {
		return nil, nil
	}

	var certbts, keybts []byte
	var err error
	if certbts, err = common.ReadKey(cert, certfile); err != nil {
		return nil, err
	}
	if keybts, err = common.ReadKey(key, keyfile); err != nil {
		return nil, err
	}

	cer, err := tls.X509KeyPair(certbts, keybts)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cer},
		MinVersion:   tls.VersionTLS12,

		// Safe according to https://safecurves.cr.yp.to/; fairly widely supported according to
		// https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations#Supported_elliptic_curves
		CurvePreferences: []tls.CurveID{tls.X25519},

		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
	}, nil
}
