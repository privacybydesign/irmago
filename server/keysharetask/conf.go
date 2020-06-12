package keysharetask

import (
	"html/template"
	"net/smtp"

	"github.com/pkg/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

type Configuration struct {
	// Database configuration
	DbConnstring string

	// Configuration for deleting expired accounts
	ExpiryDelay int
	DeleteDelay int

	// Email sending configuration
	EmailServer                  string
	EmailAuth                    smtp.Auth
	EmailFrom                    string
	DefaultLanguage              string
	DeleteExpiredAccountFiles    map[string]string
	DeleteExpiredAccountTemplate map[string]*template.Template
	DeleteExpiredAccountSubject  map[string]string

	// Logging verbosity level: 0 is normal, 1 includes DEBUG level, 2 includes TRACE level
	Verbose int `json:"verbose" mapstructure:"verbose"`
	// Don't log anything at all
	Quiet bool `json:"quiet" mapstructure:"quiet"`
	// Output structured log in JSON format
	LogJSON bool `json:"log_json" mapstructure:"log_json"`
	// Custom logger instance. If specified, Verbose, Quiet and LogJSON are ignored.
	Logger *logrus.Logger `json:"-"`
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

	// Setup email templates
	if conf.EmailServer != "" && conf.DeleteExpiredAccountTemplate == nil {
		conf.DeleteExpiredAccountTemplate = map[string]*template.Template{}
		for lang, templateFile := range conf.DeleteExpiredAccountFiles {
			var err error
			conf.DeleteExpiredAccountTemplate[lang], err = template.ParseFiles(templateFile)
			if err != nil {
				return server.LogError(err)
			}
		}
	}

	// Verify email configuration
	if conf.EmailServer != "" {
		if _, ok := conf.DeleteExpiredAccountTemplate[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing delete expired account email template for default language"))
		}
		if _, ok := conf.DeleteExpiredAccountSubject[conf.DefaultLanguage]; !ok {
			return server.LogError(errors.Errorf("Missing delete expired account email subject for default language"))
		}
	}

	return nil
}
