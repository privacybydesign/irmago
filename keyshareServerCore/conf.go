package keyshareServerCore

import (
	"encoding/binary"
	"io/ioutil"
	"os"
	"strings"

	"github.com/privacybydesign/irmago/keyshareCore"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

// Configuration contains configuration for the irmaserver library and irmad.
type Configuration struct {
	// Irma server configuration. If not given, this will be populated using information here
	ServerConfiguration *server.Configuration `json:"-"`
	// Path to IRMA schemes to parse into server configuration (only used if ServerConfiguration == nil).
	// If left empty, default value is taken using DefaultSchemesPath().
	// If an empty folder is specified, default schemes (irma-demo and pbdf) are downloaded into it.
	SchemesPath string `json:"schemes_path" mapstructure:"schemes_path"`
	// If specified, schemes found here are copied into SchemesPath (only used if ServerConfiguration == nil)
	SchemesAssetsPath string `json:"schemes_assets_path" mapstructure:"schemes_assets_path"`
	// Disable scheme updating (used only if ServerConfiguration == nil)
	DisableSchemesUpdate bool `json:"disable_schemes_update" mapstructure:"disable_schemes_update"`
	// Update all schemes every x minutes (default value 0 means 60) (use DisableSchemesUpdate to disable)
	// (used only if ServerConfiguration == nil)
	SchemesUpdateInterval int `json:"schemes_update" mapstructure:"schemes_update"`
	// Path to issuer private keys to parse
	IssuerPrivateKeysPath string `json:"privkeys" mapstructure:"privkeys"`
	// Issuer private keys
	IssuerPrivateKeys map[irma.IssuerIdentifier]*gabi.PrivateKey `json:"-"`
	// URL at which the IRMA app can reach this keyshare server during sessions
	URL string `json:"url" mapstructure:"url"`
	// Required to be set to true if URL does not begin with https:// in production mode.
	// In this case, the server would communicate with IRMA apps over plain HTTP. You must otherwise
	// ensure (using eg a reverse proxy with TLS enabled) that the attributes are protected in transit.
	DisableTLS bool `json:"no_tls" mapstructure:"no_tls"`

	// Configuration of secure Core
	// Private key used to sign JWTs with
	JwtKeyId          int    `json:"jwt_key_id" mapstructure:"jwt_key_id"`
	JwtPrivateKey     string `json:"jwt_privkey" mapstructure:"jwt_privkey"`
	JwtPrivateKeyFile string `json:"jwt_privkey_file" mapstructure:"jwt_privkey_file"`
	// Decryption keys used for keyshare packets
	StorageFallbackKeyFiles []string `json:"storage_fallback_key_files" mapstructure:"storage_fallback_key_files"`
	StoragePrimaryKeyFile   string   `json:"storage_primary_key_file" mapstructure:"storage_primary_key_file"`

	// Keyshare credential to issue during registration
	KeyshareCredential string
	KeyshareAttribute  string

	// Logging verbosity level: 0 is normal, 1 includes DEBUG level, 2 includes TRACE level
	Verbose int `json:"verbose" mapstructure:"verbose"`
	// Don't log anything at all
	Quiet bool `json:"quiet" mapstructure:"quiet"`
	// Output structured log in JSON format
	LogJSON bool `json:"log_json" mapstructure:"log_json"`
	// Custom logger instance. If specified, Verbose, Quiet and LogJSON are ignored.
	Logger *logrus.Logger `json:"-"`

	// Production mode: enables safer and stricter defaults and config checking
	Production bool `json:"production" mapstructure:"production"`
}

func readAESKey(filename string) (uint32, keyshareCore.AesKey, error) {
	keyFile, err := os.Open(filename)
	if err != nil {
		return 0, keyshareCore.AesKey{}, err
	}
	defer keyFile.Close()
	keyData, err := ioutil.ReadAll(keyFile)
	if err != nil {
		return 0, keyshareCore.AesKey{}, err
	}
	if len(keyData) != 32+4 {
		return 0, keyshareCore.AesKey{}, errors.New("Invalid aes key")
	}
	var key [32]byte
	copy(key[:], keyData[4:36])
	return binary.LittleEndian.Uint32(keyData[0:4]), key, nil
}

// Process a passed configuration to ensure all field values are valid and initialized
// as required by the rest of this keyshare server component.
func processConfiguration(conf *Configuration) (*keyshareCore.KeyshareCore, error) {
	// Setup log
	if conf.Logger == nil {
		conf.Logger = server.NewLogger(conf.Verbose, conf.Quiet, conf.LogJSON)
	}
	server.Logger = conf.Logger
	irma.Logger = conf.Logger

	// Setup server configuration if needed
	if conf.ServerConfiguration == nil {
		conf.ServerConfiguration = &server.Configuration{
			SchemesPath:           conf.SchemesPath,
			SchemesAssetsPath:     conf.SchemesAssetsPath,
			DisableSchemesUpdate:  conf.DisableSchemesUpdate,
			SchemesUpdateInterval: conf.SchemesUpdateInterval,
			IssuerPrivateKeys:     conf.IssuerPrivateKeys,
			IssuerPrivateKeysPath: conf.IssuerPrivateKeysPath,
			DisableTLS:            conf.DisableTLS,
			Logger:                conf.Logger,
		}
	}

	// Force loggers to match (TODO: reevaluate once logging is reworked in irma server)
	conf.ServerConfiguration.Logger = conf.Logger

	// Force production status to match
	conf.ServerConfiguration.Production = conf.Production

	// Load configuration (because server setup needs this to be in place)
	if conf.ServerConfiguration.IrmaConfiguration == nil {
		var (
			err    error
			exists bool
		)
		if conf.ServerConfiguration.SchemesPath == "" {
			conf.ServerConfiguration.SchemesPath = server.DefaultSchemesPath() // Returns an existing path
		}
		if exists, err = fs.PathExists(conf.ServerConfiguration.SchemesPath); err != nil {
			return nil, server.LogError(err)
		}
		if !exists {
			return nil, server.LogError(errors.Errorf("Nonexisting schemes_path provided: %s", conf.ServerConfiguration.SchemesPath))
		}
		conf.Logger.WithField("schemes_path", conf.ServerConfiguration.SchemesPath).Info("Determined schemes path")
		if conf.ServerConfiguration.SchemesAssetsPath == "" {
			conf.ServerConfiguration.IrmaConfiguration, err = irma.NewConfiguration(conf.ServerConfiguration.SchemesPath)
		} else {
			conf.ServerConfiguration.IrmaConfiguration, err = irma.NewConfigurationFromAssets(
				conf.ServerConfiguration.SchemesPath, conf.ServerConfiguration.SchemesAssetsPath)
		}
		if err != nil {
			return nil, server.LogError(err)
		}
		if err = conf.ServerConfiguration.IrmaConfiguration.ParseFolder(); err != nil {
			return nil, server.LogError(err)
		}
	}

	// Setup server urls
	if !strings.HasSuffix(conf.URL, "/") {
		conf.URL = conf.URL + "/"
	}
	if !strings.HasPrefix(conf.URL, "https://") {
		if !conf.Production || conf.DisableTLS {
			conf.DisableTLS = true
			conf.Logger.Warnf("TLS is not enabled on the url \"%s\" to which the IRMA app will connect. "+
				"Ensure that attributes are encrypted in transit by either enabling TLS or adding TLS in a reverse proxy.", conf.URL)
		} else {
			return nil, server.LogError(errors.Errorf("Running without TLS in production mode is unsafe without a reverse proxy. " +
				"Either use a https:// URL or explicitly disable TLS."))
		}
	}
	if conf.ServerConfiguration.URL == "" {
		conf.ServerConfiguration.URL = conf.URL + "irma/"
		conf.ServerConfiguration.DisableTLS = conf.DisableTLS // ensure matching checks
	}

	// Parse keyshareCore private keys and create a valid keyshare core
	core := keyshareCore.NewKeyshareCore()
	if conf.JwtPrivateKey == "" && conf.JwtPrivateKeyFile == "" {
		return nil, server.LogError(errors.Errorf("Missing keyshare server jwt key"))
	}
	keybytes, err := fs.ReadKey(conf.JwtPrivateKey, conf.JwtPrivateKeyFile)
	if err != nil {
		return nil, server.LogError(errors.WrapPrefix(err, "failed to read keyshare server jwt key", 0))
	}
	jwtPrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keybytes)
	if err != nil {
		return nil, server.LogError(errors.WrapPrefix(err, "failed to read keyshare server jwt key", 0))
	}
	core.DangerousSetSignKey(jwtPrivateKey)
	encId, encKey, err := readAESKey(conf.StoragePrimaryKeyFile)
	if err != nil {
		return nil, server.LogError(errors.WrapPrefix(err, "failed to load primary storage key", 0))
	}
	core.DangerousSetAESEncryptionKey(encId, encKey)
	for _, keyFile := range conf.StorageFallbackKeyFiles {
		id, key, err := readAESKey(keyFile)
		if err != nil {
			return nil, server.LogError(errors.WrapPrefix(err, "failed to load fallback key "+keyFile, 0))
		}
		core.DangerousAddAESKey(id, key)
	}

	return core, nil
}
