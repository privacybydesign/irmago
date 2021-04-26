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

	LoginEmailFiles        map[string]string
	LoginEmailTemplates    map[string]*template.Template
	LoginEmailSubject      map[string]string
	LoginEmailBaseURL      map[string]string
	DeleteEmailFiles       map[string]string
	DeleteEmailTemplates   map[string]*template.Template
	DeleteEmailSubject     map[string]string
	DeleteAccountFiles     map[string]string
	DeleteAccountTemplates map[string]*template.Template
	DeleteAccountSubject   map[string]string
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
	if conf.EmailServer != "" && conf.LoginEmailTemplates == nil {
		conf.LoginEmailTemplates = map[string]*template.Template{}
		for lang, templateFile := range conf.LoginEmailFiles {
			var err error
			conf.LoginEmailTemplates[lang], err = template.ParseFiles(templateFile)
			if err != nil {
				return server.LogError(err)
			}
		}
	}
	if conf.EmailServer != "" && conf.DeleteEmailTemplates == nil {
		conf.DeleteEmailTemplates = map[string]*template.Template{}
		for lang, templateFile := range conf.DeleteEmailFiles {
			var err error
			conf.DeleteEmailTemplates[lang], err = template.ParseFiles(templateFile)
			if err != nil {
				return server.LogError(err)
			}
		}
	}
	if conf.EmailServer != "" && conf.DeleteAccountTemplates == nil {
		conf.DeleteAccountTemplates = map[string]*template.Template{}
		for lang, templateFile := range conf.DeleteAccountFiles {
			var err error
			conf.DeleteAccountTemplates[lang], err = template.ParseFiles(templateFile)
			if err != nil {
				return server.LogError(err)
			}
		}
	}

	// Verify email configuration
	if conf.EmailServer != "" {
		if _, ok := conf.LoginEmailTemplates[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing login email template for default language"))
		}
		if _, ok := conf.LoginEmailSubject[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing login email subject for default language"))
		}
		if _, ok := conf.LoginEmailBaseURL[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing login email base url for default language"))
		}
		if _, ok := conf.DeleteEmailTemplates[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing delete email template for default language"))
		}
		if _, ok := conf.DeleteEmailSubject[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing delete email subject for default language"))
		}
		if _, ok := conf.DeleteAccountTemplates[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing delete account template for default language"))
		}
		if _, ok := conf.DeleteAccountSubject[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing delete account subject for default language"))
		}
	}

	// Setup database
	if conf.DB == nil {
		switch conf.DBType {
		case DatabaseTypePostgres:
			var err error
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
