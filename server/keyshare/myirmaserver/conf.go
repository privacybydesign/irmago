package myirmaserver

import (
	"html/template"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"
)

type DatabaseType string

var ErrUnknownDatabaseType = errors.New("Unknown database type")

const (
	DatabaseTypeMemory   = "memory"
	DatabaseTypePostgres = "postgres"
)

// Configuration contains configuration for the irmaserver library and irmad.
type Configuration struct {
	// IRMA server configuration. If not given, this will be populated using information here
	*server.Configuration `mapstructure:",squash"`

	PathPrefix string `json:"path_prefix" mapstructure:"path_prefix"`

	// Path to static content to serve (for testing)
	StaticPath   string `json:"static_path" mapstructure:"static_path"`
	StaticPrefix string `json:"static_prefix" mapstructure:"static_prefix"`

	// Database configuration (ignored when database is provided)
	DBType       DatabaseType `json:"db_type" mapstructure:"db_type"`
	DBConnstring string       `json:"db_connstring" mapstructure:"db_connstring"`
	// DeleteDelay is the delay in days before a user or email address deletion becomes effective.
	DeleteDelay int `json:"delete_delay" mapstructure:"delete_delay"`
	// Provide a prepared database (useful for testing)
	DB MyirmaDB `json:"-"`

	// Session lifetime in seconds
	SessionLifetime int `json:"session_lifetime" mapstructure:"session_lifetime"`

	// Keyshare attributes to use for login
	KeyshareAttributes []irma.AttributeTypeIdentifier `json:"keyshare_attributes" mapstructure:"keyshare_attributes"`
	EmailAttributes    []irma.AttributeTypeIdentifier `json:"email_attributes" mapstructure:"email_attributes"`

	// Configuration for email sending during login (email address use will be disabled if not present)
	keyshare.EmailConfiguration `mapstructure:",squash"`

	LoginEmailBaseURL map[string]string `json:"login_email_base_url" mapstructure:"login_email_base_url"`

	LoginEmailFiles      map[string]string `json:"login_email_files" mapstructure:"login_email_files"`
	LoginEmailSubject    map[string]string `json:"login_email_subject" mapstructure:"login_email_subject"`
	DeleteEmailFiles     map[string]string `json:"delete_email_files" mapstructure:"delete_email_files"`
	DeleteEmailSubject   map[string]string `json:"delete_email_subject" mapstructure:"delete_email_subject"`
	DeleteAccountFiles   map[string]string `json:"delete_account_files" mapstructure:"delete_account_files"`
	DeleteAccountSubject map[string]string `json:"delete_account_subject" mapstructure:"delete_account_subject"`

	loginEmailTemplates    map[string]*template.Template `json:"login_email_templates" mapstructure:"login_email_templates"`
	deleteEmailTemplates   map[string]*template.Template `json:"delete_email_templates" mapstructure:"delete_email_templates"`
	deleteAccountTemplates map[string]*template.Template `json:"delete_account_templates" mapstructure:"delete_account_templates"`
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

	// Setup email templates
	var err error
	if conf.EmailServer != "" {
		if conf.loginEmailTemplates, err = keyshare.ParseEmailTemplates(
			conf.LoginEmailFiles,
			conf.LoginEmailSubject,
			conf.DefaultLanguage,
		); err != nil {
			return server.LogError(err)
		}
		if conf.deleteEmailTemplates, err = keyshare.ParseEmailTemplates(
			conf.DeleteEmailFiles,
			conf.DeleteEmailSubject,
			conf.DefaultLanguage,
		); err != nil {
			return server.LogError(err)
		}
		if conf.deleteAccountTemplates, err = keyshare.ParseEmailTemplates(
			conf.DeleteAccountFiles,
			conf.DeleteAccountSubject,
			conf.DefaultLanguage,
		); err != nil {
			return server.LogError(err)
		}
		if _, ok := conf.LoginEmailBaseURL[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing login email base url for default language"))
		}
	}

	// Setup database
	if conf.DB == nil {
		switch conf.DBType {
		case DatabaseTypePostgres:
			conf.DB, err = NewPostgresDatabase(conf.DBConnstring)
			if err != nil {
				return err
			}
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

	// Setup IRMA session server url for in QR code
	conf.URL = keyshare.AppendURLPrefix(conf.URL, conf.PathPrefix)

	return nil
}
