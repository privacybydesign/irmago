package myirmaserver

import (
	"html/template"
	"strings"

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

	MyIRMAURL string `json:"url" mapstructure:"url"`

	// Path to static content to serve (for testing)
	StaticPath   string
	StaticPrefix string

	// Database configuration (ignored when database is provided)
	DBType       DatabaseType `json:"db_type" mapstructure:"db_type"`
	DBConnstring string       `json:"db_connstring" mapstructure:"db_connstring"`
	DeleteDelay  int          `json:"delete_delay" mapstructure:"delete_delay"`
	// Provide a prepared database (useful for testing)
	DB MyirmaDB `json:"-"`

	// Session lifetime in seconds
	SessionLifetime int

	// Keyshare attributes to use for login
	KeyshareAttributeNames []string
	KeyshareAttributes     []irma.AttributeTypeIdentifier
	EmailAttributeNames    []string
	EmailAttributes        []irma.AttributeTypeIdentifier

	// Configuration for email sending during login (email address use will be disabled if not present)
	keyshare.EmailConfiguration `mapstructure:",squash"`

	LoginEmailBaseURL map[string]string

	LoginEmailFiles      map[string]string
	LoginEmailSubject    map[string]string
	DeleteEmailFiles     map[string]string
	DeleteEmailSubject   map[string]string
	DeleteAccountFiles   map[string]string
	DeleteAccountSubject map[string]string

	loginEmailTemplates    map[string]*template.Template
	deleteEmailTemplates   map[string]*template.Template
	deleteAccountTemplates map[string]*template.Template
}

// Process a passed configuration to ensure all field values are valid and initialized
// as required by the rest of this keyshare server component.
func processConfiguration(conf *Configuration) error {
	// Setup data for login requests
	if len(conf.KeyshareAttributes) == 0 {
		for _, v := range conf.KeyshareAttributeNames {
			conf.KeyshareAttributes = append(
				conf.KeyshareAttributes,
				irma.NewAttributeTypeIdentifier(v))
		}
	}

	// Setup data for email requests
	if len(conf.EmailAttributes) == 0 {
		for _, v := range conf.EmailAttributeNames {
			conf.EmailAttributes = append(
				conf.EmailAttributes,
				irma.NewAttributeTypeIdentifier(v))
		}
	}

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
			conf.DB, err = NewPostgresDatabase(conf.DBConnstring, conf.DeleteDelay)
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

	// Setup server urls
	if !strings.HasSuffix(conf.MyIRMAURL, "/") {
		conf.MyIRMAURL = conf.MyIRMAURL + "/"
	}
	conf.URL = conf.MyIRMAURL + "irma/"

	return nil
}
