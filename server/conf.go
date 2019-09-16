package server

import (
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
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
	// Issuer private keys
	IssuerPrivateKeys map[irma.IssuerIdentifier]*gabi.PrivateKey `json:"-"`
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

	// Logging verbosity level: 0 is normal, 1 includes DEBUG level, 2 includes TRACE level
	Verbose int `json:"verbose" mapstructure:"verbose"`
	// Don't log anything at all
	Quiet bool `json:"quiet" mapstructure:"quiet"`
	// Output structured log in JSON format
	LogJSON bool `json:"log_json" mapstructure:"log_json"`
	// Custom logger instance. If specified, Verbose, Quiet and LogJSON are ignored.
	Logger *logrus.Logger `json:"-"`

	// Path at which to store revocation databases
	RevocationPath string `json:"revocation_path" mapstructure:"revocation_path"`
	// Credentials types for which revocation database should be hosted
	RevocationServers map[irma.CredentialTypeIdentifier]RevocationServer `json:"revocation_servers" mapstructure:"revocation_servers"`

	// Production mode: enables safer and stricter defaults and config checking
	Production bool `json:"production" mapstructure:"production"`
}

type RevocationServer struct {
	PostURLs []string `json:"post_urls" mapstructure:"post_urls"`
}

// Check ensures that the Configuration is loaded, usable and free of errors.
func (conf *Configuration) Check() error {
	if conf.Logger == nil {
		conf.Logger = NewLogger(conf.Verbose, conf.Quiet, conf.LogJSON)
	}
	Logger = conf.Logger
	irma.Logger = conf.Logger

	// loop to avoid repetetive err != nil line triplets
	for _, f := range []func() error{
		conf.verifyIrmaConf, conf.verifyPrivateKeys, conf.verifyURL, conf.verifyEmail, conf.verifyRevocation,
	} {
		if err := f(); err != nil {
			if e := conf.IrmaConfiguration.RevocationStorage.Close(); e != nil {
				_ = LogError(err)
			}
			return err
		}
	}

	return nil
}

func (conf *Configuration) PrivateKey(id irma.IssuerIdentifier) (sk *gabi.PrivateKey, err error) {
	sk = conf.IssuerPrivateKeys[id]
	if sk == nil {
		if sk, err = conf.IrmaConfiguration.PrivateKey(id); err != nil {
			return nil, err
		}
	}
	return sk, nil
}

func (conf *Configuration) HavePrivateKeys() (bool, error) {
	var err error
	var sk *gabi.PrivateKey
	for id := range conf.IrmaConfiguration.Issuers {
		sk, err = conf.PrivateKey(id)
		if err != nil {
			return false, err
		}
		if sk != nil {
			return true, nil
		}
	}
	return false, nil
}

// helpers

func (conf *Configuration) verifyIrmaConf() error {
	if conf.IrmaConfiguration == nil {
		var (
			err    error
			exists bool
		)
		if conf.SchemesPath == "" {
			conf.SchemesPath = irma.DefaultSchemesPath() // Returns an existing path
		}
		if exists, err = fs.PathExists(conf.SchemesPath); err != nil {
			return LogError(err)
		}
		if !exists {
			return LogError(errors.Errorf("Nonexisting schemes_path provided: %s", conf.SchemesPath))
		}
		conf.Logger.WithField("schemes_path", conf.SchemesPath).Info("Determined schemes path")
		if conf.SchemesAssetsPath == "" {
			conf.IrmaConfiguration, err = irma.NewConfiguration(conf.SchemesPath)
		} else {
			conf.IrmaConfiguration, err = irma.NewConfigurationFromAssets(conf.SchemesPath, conf.SchemesAssetsPath)
		}
		if err != nil {
			return LogError(err)
		}
		if err = conf.IrmaConfiguration.ParseFolder(); err != nil {
			return LogError(err)
		}
		if err = fs.EnsureDirectoryExists(conf.RevocationPath); err != nil {
			return LogError(err)
		}
		conf.IrmaConfiguration.RevocationPath = conf.RevocationPath
	}

	if len(conf.IrmaConfiguration.SchemeManagers) == 0 {
		conf.Logger.Infof("No schemes found in %s, downloading default (irma-demo and pbdf)", conf.SchemesPath)
		if err := conf.IrmaConfiguration.DownloadDefaultSchemes(); err != nil {
			return LogError(err)
		}
	}
	if conf.SchemesUpdateInterval == 0 {
		conf.SchemesUpdateInterval = 60
	}
	if !conf.DisableSchemesUpdate {
		conf.IrmaConfiguration.AutoUpdateSchemes(uint(conf.SchemesUpdateInterval))
	}

	return nil
}

func (conf *Configuration) verifyPrivateKeys() error {
	if conf.IssuerPrivateKeys == nil {
		conf.IssuerPrivateKeys = make(map[irma.IssuerIdentifier]*gabi.PrivateKey)
	}
	if conf.IssuerPrivateKeysPath != "" {
		files, err := ioutil.ReadDir(conf.IssuerPrivateKeysPath)
		if err != nil {
			return LogError(err)
		}
		for _, file := range files {
			filename := file.Name()
			if filepath.Ext(filename) != ".xml" || filename[0] == '.' || strings.Count(filename, ".") != 2 {
				conf.Logger.WithField("file", filename).Infof("Skipping non-private key file encountered in private keys path")
				continue
			}
			issid := irma.NewIssuerIdentifier(strings.TrimSuffix(filename, filepath.Ext(filename))) // strip .xml
			if _, ok := conf.IrmaConfiguration.Issuers[issid]; !ok {
				return LogError(errors.Errorf("Private key %s belongs to an unknown issuer", filename))
			}
			sk, err := gabi.NewPrivateKeyFromFile(filepath.Join(conf.IssuerPrivateKeysPath, filename))
			if err != nil {
				return LogError(err)
			}
			conf.IssuerPrivateKeys[issid] = sk
		}
	}
	for issid, sk := range conf.IssuerPrivateKeys {
		pk, err := conf.IrmaConfiguration.PublicKey(issid, int(sk.Counter))
		if err != nil {
			return LogError(err)
		}
		if pk == nil {
			return LogError(errors.Errorf("Missing public key belonging to private key %s-%d", issid.String(), sk.Counter))
		}
		if new(big.Int).Mul(sk.P, sk.Q).Cmp(pk.N) != 0 {
			return LogError(errors.Errorf("Private key %s-%d does not belong to corresponding public key", issid.String(), sk.Counter))
		}
	}

	return nil
}

func (conf *Configuration) verifyRevocation() error {
	for credid, settings := range conf.RevocationServers {
		if _, known := conf.IrmaConfiguration.CredentialTypes[credid]; !known {
			return LogError(errors.Errorf("unknown credential type %s in revocation settings", credid))
		}

		db, err := conf.IrmaConfiguration.RevocationStorage.RevocationDB(credid)
		if err != nil {
			return LogError(err)
		}

		db.OnChange(func(record *irma.Record) {
			transport := irma.NewHTTPTransport("")
			o := struct{}{}
			for _, url := range settings.PostURLs {
				if err := transport.Post(url+"/-/revocation/records", &o, &[]*irma.Record{record}); err != nil {
					conf.Logger.Warn("error sending revocation update", err)
				}
			}
		})
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
				return LogError(errors.Errorf("Running without TLS in production mode is unsafe without a reverse proxy. " +
					"Either use a https:// URL or explicitly disable TLS."))
			}
		}
	} else {
		conf.Logger.Warn("No url parameter specified in configuration; unless an url is elsewhere prepended in the QR, the IRMA client will not be able to connect")
	}
	return nil
}

func (conf *Configuration) verifyEmail() error {
	if conf.Email != "" {
		// Very basic sanity checks
		if !strings.Contains(conf.Email, "@") || strings.Contains(conf.Email, "\n") {
			return LogError(errors.New("Invalid email address specified"))
		}
		t := irma.NewHTTPTransport("https://metrics.privacybydesign.foundation/history")
		t.SetHeader("User-Agent", "irmaserver")
		var x string
		_ = t.Post("email", &x, conf.Email)
	}
	return nil
}
