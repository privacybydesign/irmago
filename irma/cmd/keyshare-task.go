package cmd

import (
	"net/smtp"

	"github.com/privacybydesign/irmago/server/keyshare"
	"github.com/privacybydesign/irmago/server/keyshare/taskserver"
	"github.com/sietseringers/cobra"
	"github.com/sietseringers/viper"
)

var confKeyshareTask *taskserver.Configuration

var keyshareTaskCmd = &cobra.Command{
	Use:   "task",
	Short: "IRMA keyshare background task server",
	Run: func(command *cobra.Command, args []string) {
		configureKeyshareTask(command)

		task, err := taskserver.New(confKeyshareTask)
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
	flags.StringToString("expired-email-files", nil, "Translated emails for the expired account email")
	flags.Lookup("email-server").Header = `Email configuration (leave empty to disable sending emails)`

	flags.CountP("verbose", "v", "verbose (repeatable)")
	flags.BoolP("quiet", "q", false, "quiet")
	flags.Bool("log-json", false, "Log in JSON format")
	flags.Lookup("verbose").Header = `Other options`
}

func configureKeyshareTask(cmd *cobra.Command) {
	readConfig(cmd, "keysharetasks", "keyshare task daemon", []string{".", "/etc/keysharetasks"}, nil)

	// If username/password are specified for the email server, build an authentication object.
	var emailAuth smtp.Auth
	if viper.GetString("email-username") != "" {
		emailAuth = smtp.PlainAuth("", viper.GetString("email-username"), viper.GetString("email-password"), viper.GetString("email-hostname"))
	}

	confKeyshareTask = &taskserver.Configuration{
		EmailConfiguration: keyshare.EmailConfiguration{
			EmailServer:     viper.GetString("email-server"),
			EmailAuth:       emailAuth,
			EmailFrom:       viper.GetString("email-from"),
			DefaultLanguage: viper.GetString("default-language"),
		},

		DBConnstring: viper.GetString("db-connstring"),

		ExpiryDelay: viper.GetInt("expiry-delay"),
		DeleteDelay: viper.GetInt("delete-delay"),

		DeleteExpiredAccountSubject: viper.GetStringMapString("expired-email-subject"),
		DeleteExpiredAccountFiles:   viper.GetStringMapString("expired-email-files"),

		Verbose: viper.GetInt("verbose"),
		Quiet:   viper.GetBool("quiet"),
		LogJSON: viper.GetBool("log-json"),
		Logger:  logger,
	}
}
