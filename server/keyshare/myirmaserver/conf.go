package myirmaserver

import (
	"html/template"
	"net/url"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/go-multierror"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"
)

type DBType string

var errUnknownDBType = errors.New("Unknown database type")

const (
	DBTypeMemory   DBType = "memory"
	DBTypePostgres DBType = "postgres"

	SessionLifetimeDefault = 15 * 60 // seconds
)

// Configuration contains configuration for the irmaserver library and irmad.
type Configuration struct {
	// IRMA server configuration. If not given, this will be populated using information here
	*server.Configuration `mapstructure:",squash"`

	CORSAllowedOrigins []string `json:"cors_allowed_origins" mapstructure:"cors_allowed_origins"`

	// Path to static content to serve (for testing)
	StaticPath   string `json:"static_path" mapstructure:"static_path"`
	StaticPrefix string `json:"static_prefix" mapstructure:"static_prefix"`

	// Database configuration (ignored when database is provided)
	DBType            DBType `json:"db_type" mapstructure:"db_type"`
	DBConnStr         string `json:"db_str" mapstructure:"db_str"`
	DBMaxIdleConns    int    `json:"db_max_idle" mapstructure:"db_max_idle"`
	DBMaxOpenConns    int    `json:"db_max_open" mapstructure:"db_max_open"`
	DBConnMaxIdleTime int    `json:"db_max_idle_time" mapstructure:"db_max_idle_time"`
	DBConnMaxOpenTime int    `json:"db_max_open_time" mapstructure:"db_max_open_time"`
	// DeleteDelay is the delay in days before a user or email address deletion becomes effective.
	DeleteDelay int `json:"delete_delay" mapstructure:"delete_delay"`
	// Provide a prepared database (useful for testing)
	DB db `json:"-"`

	// Session lifetime in seconds
	SessionLifetime int `json:"session_lifetime" mapstructure:"session_lifetime"`

	// Keyshare attributes to use for login
	KeyshareAttributes []irma.AttributeTypeIdentifier `json:"keyshare_attributes" mapstructure:"keyshare_attributes"`
	EmailAttributes    []irma.AttributeTypeIdentifier `json:"email_attributes" mapstructure:"email_attributes"`

	// Configuration for email sending during login (email address use will be disabled if not present)
	keyshare.EmailConfiguration `mapstructure:",squash"`

	LoginURL map[string]string `json:"login_url" mapstructure:"login_url"`

	LoginEmailFiles       map[string]string `json:"login_email_files" mapstructure:"login_email_files"`
	LoginEmailSubjects    map[string]string `json:"login_email_subjects" mapstructure:"login_email_subjects"`
	DeleteEmailFiles      map[string]string `json:"delete_email_files" mapstructure:"delete_email_files"`
	DeleteEmailSubjects   map[string]string `json:"delete_email_subjects" mapstructure:"delete_email_subjects"`
	DeleteAccountFiles    map[string]string `json:"delete_account_files" mapstructure:"delete_account_files"`
	DeleteAccountSubjects map[string]string `json:"delete_account_subjects" mapstructure:"delete_account_subjects"`

	loginEmailTemplates    map[string]*template.Template
	deleteEmailTemplates   map[string]*template.Template
	deleteAccountTemplates map[string]*template.Template
}

// Process a passed configuration to ensure all field values are valid and initialized
// as required by the rest of this keyshare server component.
func processConfiguration(conf *Configuration) error {
	// Verify attriubte configuration
	if len(conf.KeyshareAttributes) == 0 {
		return server.LogError(errors.Errorf("Missing keyshare attributes"))
	}
	if len(conf.EmailAttributes) == 0 {
		return server.LogError(errors.Errorf("Missing email attributes"))
	}
	var multierr multierror.Error
	for _, attr := range conf.KeyshareAttributes {
		if conf.IrmaConfiguration.AttributeTypes[attr] == nil {
			multierr.Errors = append(multierr.Errors, errors.Errorf("Unknown keyshare attribute: %s", attr))
		}
	}
	for _, attr := range conf.EmailAttributes {
		if conf.IrmaConfiguration.AttributeTypes[attr] == nil {
			multierr.Errors = append(multierr.Errors, errors.Errorf("Unknown email attribute: %s", attr))
		}
	}
	if err := multierr.ErrorOrNil(); err != nil {
		return server.LogError(err)
	}

	// Setup email templates
	var err error
	if conf.EmailServer != "" {
		if conf.loginEmailTemplates, err = keyshare.ParseEmailTemplates(
			conf.LoginEmailFiles,
			conf.LoginEmailSubjects,
			conf.DefaultLanguage,
		); err != nil {
			return server.LogError(err)
		}
		if conf.deleteEmailTemplates, err = keyshare.ParseEmailTemplates(
			conf.DeleteEmailFiles,
			conf.DeleteEmailSubjects,
			conf.DefaultLanguage,
		); err != nil {
			return server.LogError(err)
		}
		if conf.deleteAccountTemplates, err = keyshare.ParseEmailTemplates(
			conf.DeleteAccountFiles,
			conf.DeleteAccountSubjects,
			conf.DefaultLanguage,
		); err != nil {
			return server.LogError(err)
		}
		if _, ok := conf.LoginURL[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing login email base url for default language"))
		}
	}

	// Setup database
	if conf.DB == nil {
		switch conf.DBType {
		case DBTypePostgres:
			conf.DB, err = newPostgresDB(conf.DBConnStr,
				conf.DBMaxIdleConns,
				conf.DBMaxOpenConns,
				time.Duration(conf.DBConnMaxIdleTime)*time.Second,
				time.Duration(conf.DBConnMaxOpenTime)*time.Second,
			)
			if err != nil {
				return err
			}
		case DBTypeMemory:
			conf.DB = newMemoryDB()
		default:
			return server.LogError(errUnknownDBType)
		}
	}

	if err = conf.VerifyEmailServer(); err != nil {
		return server.LogError(err)
	}

	// Set default if needed for session lifetime
	if conf.SessionLifetime == 0 {
		conf.SessionLifetime = SessionLifetimeDefault // default to 15 minutes
	}

	// Setup IRMA session server url for in QR code
	if !strings.HasSuffix(conf.URL, "/") {
		conf.URL += "/"
	}
	conf.URL += "irma/"

	for _, origin := range conf.CORSAllowedOrigins {
		if origin == "*" {
			if len(conf.CORSAllowedOrigins) != 1 {
				return server.LogError(errors.New("CORS allowed origin * cannot be specified together with other allowed origins"))
			}
			continue
		}
		u, err := url.Parse(origin)
		if err != nil {
			return server.LogError(errors.Errorf(`Invalid CORS allowed origin "%s": %v`, origin, err))
		}
		if !strings.HasPrefix(u.Scheme, "http") || u.Path != "" || u.RawQuery != "" || u.RawFragment != "" {
			err = errors.Errorf(`Invalid CORS allowed origin "%s": must start with http(s) but be without path, query or fragment`, origin)
			return server.LogError(err)
		}
	}

	return nil
}
