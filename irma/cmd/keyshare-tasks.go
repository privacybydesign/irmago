package cmd

import (
	"github.com/privacybydesign/irmago/server/keyshare/tasks"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var keyshareTaskCmd = &cobra.Command{
	Use:   "tasks",
	Short: "Perform IRMA keyshare background tasks",
	Run: func(command *cobra.Command, args []string) {
		conf := configureKeyshareTasks(command)
		if err := tasks.Do(conf); err != nil {
			die("", err)
		}
	},
}

func init() {
	keyshareRootCmd.AddCommand(keyshareTaskCmd)

	keyshareTaskCmd.SetUsageTemplate(headerFlagsTemplate)
	headers := map[string]string{}
	flagHeaders["irma keyshare tasks"] = headers

	flags := keyshareTaskCmd.Flags()
	flags.SortFlags = false

	flags.StringP("config", "c", "", "path to configuration file")

	headers["db-str"] = "Database configuration"
	flags.String("db-str", "", "Database server connection string")

	headers["expiry-delay"] = "Time period configuration"
	flags.Int("expiry-delay", 365, "Number of days of inactivity until account expires")
	flags.Int("delete-delay", 30, "Number of days until expired account should be deleted")

	headers["email-server"] = "Email configuration (leave empty to disable sending emails)"
	flags.String("email-server", "", "Email server to use for sending email address confirmation emails")
	flags.String("email-hostname", "", "Hostname used in email server tls certificate (leave empty when mail server does not use tls)")
	flags.String("email-username", "", "Username to use when authenticating with email server")
	flags.String("email-password", "", "Password to use when authenticating with email server")
	flags.String("email-from", "", "Email address to use as sender address")
	flags.String("default-language", "en", "Default language, used as fallback when users preferred language is not available")
	flags.StringToString("expired-email-subjects", nil, "Translated subject lines for the expired account email")
	flags.StringToString("expired-email-files", nil, "Translated emails for the expired account email")

	headers["verbose"] = "Other options"
	flags.CountP("verbose", "v", "verbose (repeatable)")
	flags.BoolP("quiet", "q", false, "quiet")
	flags.Bool("log-json", false, "Log in JSON format")
}

func configureKeyshareTasks(cmd *cobra.Command) *tasks.Configuration {
	readConfig(cmd, "keysharetasks", "keyshare tasks", []string{".", "/etc/keysharetasks"}, nil)

	return &tasks.Configuration{
		EmailConfiguration: configureEmail(),

		DBConnStr: viper.GetString("db_str"),

		ExpiryDelay: viper.GetInt("expiry_delay"),
		DeleteDelay: viper.GetInt("delete_delay"),

		DeleteExpiredAccountSubjects: viper.GetStringMapString("expired_email_subjects"),
		DeleteExpiredAccountFiles:    viper.GetStringMapString("expired_email_files"),

		Verbose: viper.GetInt("verbose"),
		Quiet:   viper.GetBool("quiet"),
		LogJSON: viper.GetBool("log_json"),
		Logger:  logger,
	}
}
