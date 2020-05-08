package cmd

import (
	"net/smtp"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keysharetask"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var confKeyshareTask *keysharetask.Configuration

var keyshareTaskCmd = &cobra.Command{
	Use:   "task",
	Short: "Irma keyshare server background tasks",
	Run: func(command *cobra.Command, args []string) {
		configureKeyshareTask(command)

		task, err := keysharetask.New(confKeyshareTask)
		if err != nil {
			die("", err)
		}

		task.CleanupEmails()
		task.CleanupTokens()
		task.CleanupAccounts()
		task.ExpireAccounts()
	},
}

func init() {
	keyshareRoot.AddCommand(keyshareTaskCmd)

	flags := keyshareTaskCmd.Flags()
	flags.SortFlags = false

	flags.StringP("config", "c", "", "path to configuration file")

	flags.String("db", "", "Database server connection string")
	flags.Lookup("db").Header = `Database configuration`

	flags.Int("expiry-delay", 365, "Number of days of inactivity until account expires")
	flags.Int("delete-delay", 30, "Number of days until expired account should be deleted")
	flags.Lookup("expiry-delay").Header = `Time period configuraiton`

	flags.String("email-server", "", "Email server to use for sending email address confirmation emails")
	flags.String("email-hostname", "", "Hostname used in email server tls certificate (leave empty when mail server does not use tls)")
	flags.String("email-username", "", "Username to use when authenticating with email server")
	flags.String("email-password", "", "Password to use when authenticating with email server")
	flags.String("email-from", "", "Email address to use as sender address")
	flags.String("default-language", "en", "Default language, used as fallback when users prefered language is not available")
	flags.StringToString("expired-email-subject", nil, "Translated subject lines for the expired account email")
	flags.StringToString("expired-email-template", nil, "Translated emails for the expired account email")
	flags.Lookup("email-server").Header = `Email configuration (leave empty to disable sending emails)`

	flags.CountP("verbose", "v", "verbose (repeatable)")
	flags.BoolP("quiet", "q", false, "quiet")
	flags.Bool("log-json", false, "Log in JSON format")
	flags.Lookup("verbose").Header = `Other options`
}

func configureKeyshareTask(cmd *cobra.Command) {
	dashReplacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(dashReplacer)
	viper.SetFileKeyReplacer(dashReplacer)
	viper.SetEnvPrefix("KEYSHARETASK")
	viper.AutomaticEnv()

	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		die("", err)
	}

	// Locate and read configuration file
	confpath := viper.GetString("config")
	if confpath != "" {
		dir, file := filepath.Dir(confpath), filepath.Base(confpath)
		viper.SetConfigName(strings.TrimSuffix(file, filepath.Ext(file)))
		viper.AddConfigPath(dir)
	} else {
		viper.SetConfigName("keysharetask")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/keysharetask/")
	}
	err := viper.ReadInConfig()

	// Create our logger instance
	logger = server.NewLogger(viper.GetInt("verbose"), viper.GetBool("quiet"), viper.GetBool("log-json"))

	// First log output: hello, development or production mode, log level
	mode := "development"
	if viper.GetBool("production") {
		mode = "production"
	}
	logger.WithFields(logrus.Fields{
		"version":   irma.Version,
		"mode":      mode,
		"verbosity": server.Verbosity(viper.GetInt("verbose")),
	}).Info("keyshare task running")

	// Now we finally examine and log any error from viper.ReadInConfig()
	if err != nil {
		if _, notfound := err.(viper.ConfigFileNotFoundError); notfound {
			logger.Info("No configuration file found")
		} else {
			die("", errors.WrapPrefix(err, "Failed to unmarshal configuration file at "+viper.ConfigFileUsed(), 0))
		}
	} else {
		logger.Info("Config file: ", viper.ConfigFileUsed())
	}

	// If username/password are specified for the email server, build an authentication object.
	var emailAuth smtp.Auth
	if viper.GetString("email-username") != "" {
		emailAuth = smtp.PlainAuth("", viper.GetString("email-username"), viper.GetString("email-password"), viper.GetString("email-hostname"))
	}

	confKeyshareTask = &keysharetask.Configuration{
		DbConnstring: viper.GetString("db"),

		ExpiryDelay: viper.GetInt("expiry-delay"),
		DeleteDelay: viper.GetInt("delete-delay"),

		EmailServer:                 viper.GetString("email-server"),
		EmailAuth:                   emailAuth,
		EmailFrom:                   viper.GetString("email-from"),
		DefaultLanguage:             viper.GetString("default-language"),
		DeleteExpiredAccountSubject: viper.GetStringMapString("expired-email-subject"),
		DeleteExpiredAccountFiles:   viper.GetStringMapString("expired-email-template"),

		Verbose: viper.GetInt("verbose"),
		Quiet:   viper.GetBool("quiet"),
		LogJSON: viper.GetBool("log-json"),
		Logger:  logger,
	}
}
