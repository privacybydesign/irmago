package cmd

import (
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare/myirmaserver"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var myirmaServerCmd = &cobra.Command{
	Use:   "myirmaserver",
	Short: "IRMA keyshare MyIRMA server",
	Run: func(command *cobra.Command, args []string) {
		conf, err := configureMyirmaServer(command)
		if err != nil {
			die("failed to read configuration", err)
		}

		// Create main server
		myirmaServer, err := myirmaserver.New(conf)
		if err != nil {
			die("", err)
		}

		runServer(myirmaServer, conf.Logger)
	},
}

func init() {
	keyshareRootCmd.AddCommand(myirmaServerCmd)

	myirmaServerCmd.SetUsageTemplate(headerFlagsTemplate)
	headers := map[string]string{}
	flagHeaders["irma keyshare myirmaserver"] = headers

	flags := myirmaServerCmd.Flags()
	flags.SortFlags = false

	flags.StringP("config", "c", "", "path to configuration file")
	flags.StringP("schemes-path", "s", irma.DefaultSchemesPath(), "path to irma_configuration")
	flags.String("schemes-assets-path", "", "if specified, copy schemes from here into --schemes-path")
	flags.Int("schemes-update", 60, "update IRMA schemes every x minutes (0 to disable)")
	flags.StringP("url", "u", "", "external URL to server to which the IRMA client connects, \":port\" being replaced by --port value")
	flags.String("static-path", "", "Host files under this path as static files (leave empty to disable)")
	flags.String("static-prefix", "/", "Host static files under this URL prefix")
	flags.Bool("sse", false, "Enable server sent for status updates (experimental)")

	headers["port"] = "Server address and port to listen on"
	flags.IntP("port", "p", 8080, "port at which to listen")
	flags.StringP("listen-addr", "l", "", "address at which to listen (default 0.0.0.0)")
	flags.StringSlice("cors-allowed-origins", nil, "CORS allowed origins")

	headers["db-type"] = "Database configuration"
	flags.String("db-type", string(myirmaserver.DBTypePostgres), "Type of database to connect keyshare server to")
	flags.String("db-str", "", "Database server connection string")
	flags.Int("db-max-idle", 2, "Maximum number of database connections in the idle connection pool")
	flags.Int("db-max-open", 0, "Maximum number of open database connections (default unlimited)")
	flags.Int("db-max-idle-time", 0, "Time in seconds after which idle database connections are closed (default unlimited)")
	flags.Int("db-max-open-time", 0, "Maximum lifetime in seconds of open database connections (default unlimited)")

	headers["keyshare-attributes"] = "IRMA session configuration"
	flags.StringSlice("keyshare-attributes", nil, "Attributes allowed for login to myirma")
	flags.StringSlice("email-attributes", nil, "Attributes allowed for adding email addresses")
	flags.Int("session-lifetime", myirmaserver.SessionLifetimeDefault, "Session lifetime in seconds")

	headers["email-server"] = "Email configuration (leave empty to disable sending emails)"
	flags.String("email-server", "", "Email server to use for sending email address confirmation emails")
	flags.String("email-hostname", "", "Hostname used in email server tls certificate (leave empty when mail server does not use tls)")
	flags.String("email-username", "", "Username to use when authenticating with email server")
	flags.String("email-password", "", "Password to use when authenticating with email server")
	flags.String("email-from", "", "Email address to use as sender address")
	flags.String("default-language", "en", "Default language, used as fallback when users preferred language is not available")
	flags.StringToString("login-email-subjects", nil, "Translated subject lines for the login email")
	flags.StringToString("login-email-files", nil, "Translated emails for the login email")
	flags.StringToString("login-url", nil, "Base URL for the email verification link (localized)")
	flags.StringToString("delete-email-subjects", nil, "Translated subject lines for the delete email email")
	flags.StringToString("delete-email-files", nil, "Translated emails for the delete email email")
	flags.StringToString("delete-account-subjects", nil, "Translated subject lines for the delete account email")
	flags.StringToString("delete-account-files", nil, "Translated emails for the delete account email")
	flags.Int("delete-delay", 0, "delay in days before a user or email address deletion becomes effective")

	headers["tls-cert"] = "TLS configuration (leave empty to disable TLS)"
	flags.String("tls-cert", "", "TLS certificate (chain)")
	flags.String("tls-cert-file", "", "path to TLS certificate (chain)")
	flags.String("tls-privkey", "", "TLS private key")
	flags.String("tls-privkey-file", "", "path to TLS private key")
	flags.Bool("no-tls", false, "Disable TLS")

	headers["verbose"] = "Other options"
	flags.CountP("verbose", "v", "verbose (repeatable)")
	flags.BoolP("quiet", "q", false, "quiet")
	flags.Bool("log-json", false, "Log in JSON format")
	flags.Bool("production", false, "Production mode")
}

func configureMyirmaServer(cmd *cobra.Command) (*myirmaserver.Configuration, error) {
	readConfig(cmd, "myirmaserver", "myirmaserver", []string{".", "/etc/myirmaserver/"}, nil)

	// And build the configuration
	conf := &myirmaserver.Configuration{
		Configuration:      configureIRMAServer(),
		EmailConfiguration: configureEmail(),

		CORSAllowedOrigins: viper.GetStringSlice("cors_allowed_origins"),

		StaticPath:   viper.GetString("static_path"),
		StaticPrefix: viper.GetString("static_prefix"),

		DBType:            myirmaserver.DBType(viper.GetString("db_type")),
		DBConnStr:         viper.GetString("db_str"),
		DBMaxIdleConns:    viper.GetInt("db_max_idle"),
		DBMaxOpenConns:    viper.GetInt("db_max_open"),
		DBConnMaxIdleTime: viper.GetInt("db_max_idle_time"),
		DBConnMaxOpenTime: viper.GetInt("db_max_open_time"),

		LoginEmailSubjects:    viper.GetStringMapString("login_email_subjects"),
		LoginEmailFiles:       viper.GetStringMapString("login_email_files"),
		LoginURL:              viper.GetStringMapString("login_url"),
		DeleteEmailFiles:      viper.GetStringMapString("delete_email_files"),
		DeleteEmailSubjects:   viper.GetStringMapString("delete_email_subjects"),
		DeleteAccountFiles:    viper.GetStringMapString("delete_account_files"),
		DeleteAccountSubjects: viper.GetStringMapString("delete_account_subjects"),
		DeleteDelay:           viper.GetInt("delete_delay"),

		SessionLifetime: viper.GetInt("session_lifetime"),
	}

	if conf.Production && conf.DBType != myirmaserver.DBTypePostgres {
		return nil, errors.New("in production mode, db-type must be postgres")
	}

	conf.URL = server.ReplacePortString(viper.GetString("url"), viper.GetInt("port"))

	for _, v := range viper.GetStringSlice("keyshare_attributes") {
		conf.KeyshareAttributes = append(
			conf.KeyshareAttributes,
			irma.NewAttributeTypeIdentifier(v))
	}
	for _, v := range viper.GetStringSlice("email_attributes") {
		conf.EmailAttributes = append(
			conf.EmailAttributes,
			irma.NewAttributeTypeIdentifier(v))
	}

	return conf, nil
}
