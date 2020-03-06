package myirmaserver

import (
	"net/smtp"
	"strings"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

type DatabaseType string

var ErrUnknownDatabaseType = errors.New("Unknown database type")

const (
	DatabaseTypeMemory   = "memory"
	DatabaseTypePostgres = "postgres"
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
	// URL at which the IRMA app can reach this keyshare server during sessions
	URL string `json:"url" mapstructure:"url"`
	// Required to be set to true if URL does not begin with https:// in production mode.
	// In this case, the server would communicate with IRMA apps over plain HTTP. You must otherwise
	// ensure (using eg a reverse proxy with TLS enabled) that the attributes are protected in transit.
	DisableTLS bool `json:"no_tls" mapstructure:"no_tls"`

	// Path to static content to serve (for testing)
	StaticPath   string
	StaticPrefix string

	// Database configuration (ignored when database is provided)
	DbType       DatabaseType `json:"db_type" mapstructure:"db_type"`
	DbConnstring string       `json:"db_connstring" mapstructure:"db_connstring"`
	// Provide a prepared database (useful for testing)
	DB MyirmaDB `json:"-"`

	// Session lifetime in seconds
	SessionLifetime int

	// Keyshare attributes to use for login
	KeyshareAttributeNames []string
	KeyshareAttributes     []irma.AttributeTypeIdentifier

	// Configuration for email sending during login (email address use will be disabled if not present)
	EmailServer     string
	EmailAuth       smtp.Auth
	EmailFrom       string
	DefaultLanguage string

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

// Process a passed configuration to ensure all field values are valid and initialized
// as required by the rest of this keyshare server component.
func processConfiguration(conf *Configuration) error {
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
			IssuerPrivateKeysPath: conf.IssuerPrivateKeysPath,
			DisableTLS:            conf.DisableTLS,
			Logger:                conf.Logger,
		}
	}

	// Force loggers to match (TODO: reevaluate once logging is reworked in irma server)
	conf.ServerConfiguration.Logger = conf.Logger

	// Force production status to match
	conf.ServerConfiguration.Production = conf.Production

	// Setup data for login requests
	if len(conf.KeyshareAttributeNames) != 0 {
		for _, v := range conf.KeyshareAttributeNames {
			conf.KeyshareAttributes = append(
				conf.KeyshareAttributes,
				irma.NewAttributeTypeIdentifier(v))
		}
	}

	// TODO: Setup email templates

	// Verify email configuration
	if conf.EmailServer != "" {
		// TODO
	}

	// Setup database
	if conf.DB == nil {
		switch conf.DbType {
		case DatabaseTypeMemory:
			conf.DB = NewMyirmaMemoryDB()
		default:
			return server.LogError(ErrUnknownDatabaseType)
		}
	}

	// Set default if needed for session lifetime
	if conf.SessionLifetime == 0 {
		conf.SessionLifetime = 15 * 60 // default to 15 minutes
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
			return server.LogError(errors.Errorf("Running without TLS in production mode is unsafe without a reverse proxy. " +
				"Either use a https:// URL or explicitly disable TLS."))
		}
	}
	if conf.ServerConfiguration.URL == "" {
		conf.ServerConfiguration.URL = conf.URL + "irma/"
		conf.ServerConfiguration.DisableTLS = conf.DisableTLS // ensure matching checks
	}

	return nil
}
