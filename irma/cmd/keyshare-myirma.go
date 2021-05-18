package cmd

import (
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare/myirmaserver"
	"github.com/sietseringers/cobra"
	"github.com/sietseringers/viper"
)

var myirmadCmd = &cobra.Command{
	Use:   "myirma",
	Short: "IRMA keyshare myirma server",
	Run: func(command *cobra.Command, args []string) {
		conf := configureMyirmad(command)

		// Create main server
		myirmaServer, err := myirmaserver.New(conf)
		if err != nil {
			die("", err)
		}

		runServer(myirmaServer, conf.Logger)
	},
}

func init() {
	keyshareRoot.AddCommand(myirmadCmd)

	flags := myirmadCmd.Flags()
	flags.SortFlags = false

	flags.StringP("config", "c", "", "path to configuration file")
	flags.StringP("schemes-path", "s", irma.DefaultSchemesPath(), "path to irma_configuration")
	flags.String("schemes-assets-path", "", "if specified, copy schemes from here into --schemes-path")
	flags.Int("schemes-update", 60, "update IRMA schemes every x minutes (0 to disable)")
	flags.StringP("url", "u", "", "external URL to server to which the IRMA client connects, \":port\" being replaced by --port value")
	flags.String("static-path", "", "Host files under this path as static files (leave empty to disable)")
	flags.String("static-prefix", "/", "Host static files under this URL prefix")
	flags.Bool("sse", false, "Enable server sent for status updates (experimental)")

	flags.IntP("port", "p", 8080, "port at which to listen")
	flags.StringP("listen-addr", "l", "", "address at which to listen (default 0.0.0.0)")
	flags.StringSlice("cors-allowed-origins", nil, "CORS allowed origins")
	flags.Lookup("port").Header = `Server address and port to listen on`

	flags.String("db-type", myirmaserver.DatabaseTypePostgres, "Type of database to connect keyshare server to")
	flags.String("db", "", "Database server connection string")
	flags.Lookup("db-type").Header = `Database configuration`

	flags.StringSlice("keyshare-attributes", nil, "Attributes allowed for login to myirma")
	flags.StringSlice("email-attributes", nil, "Attributes allowed for adding email addresses")
	flags.Int("session-lifetime", myirmaserver.SessionLifetimeDefault, "Session lifetime in seconds")
	flags.Lookup("keyshare-attributes").Header = `IRMA session configuration`

	flags.String("email-server", "", "Email server to use for sending email address confirmation emails")
	flags.String("email-hostname", "", "Hostname used in email server tls certificate (leave empty when mail server does not use tls)")
	flags.String("email-username", "", "Username to use when authenticating with email server")
	flags.String("email-password", "", "Password to use when authenticating with email server")
	flags.String("email-from", "", "Email address to use as sender address")
	flags.String("default-language", "en", "Default language, used as fallback when users prefered language is not available")
	flags.StringToString("login-email-subject", nil, "Translated subject lines for the login email")
	flags.StringToString("login-email-files", nil, "Translated emails for the login email")
	flags.StringToString("login-url", nil, "Base URL for the email verification link (localized)")
	flags.StringToString("delete-email-subject", nil, "Translated subject lines for the delete email email")
	flags.StringToString("delete-email-files", nil, "Translated emails for the delete email email")
	flags.StringToString("delete-account-subject", nil, "Translated subject lines for the delete account email")
	flags.StringToString("delete-account-files", nil, "Translated emails for the delete account email")
	flags.Int("delete-delay", 0, "delay in days before a user or email address deletion becomes effective")
	flags.Lookup("email-server").Header = `Email configuration (leave empty to disable sending emails)`

	flags.String("tls-cert", "", "TLS certificate (chain)")
	flags.String("tls-cert-file", "", "path to TLS certificate (chain)")
	flags.String("tls-privkey", "", "TLS private key")
	flags.String("tls-privkey-file", "", "path to TLS private key")
	flags.Bool("no-tls", false, "Disable TLS")
	flags.Lookup("tls-cert").Header = `TLS configuration (leave empty to disable TLS)`

	flags.CountP("verbose", "v", "verbose (repeatable)")
	flags.BoolP("quiet", "q", false, "quiet")
	flags.Bool("log-json", false, "Log in JSON format")
	flags.Bool("production", false, "Production mode")
	flags.Lookup("verbose").Header = `Other options`
}

func configureMyirmad(cmd *cobra.Command) *myirmaserver.Configuration {
	readConfig(cmd, "myirmaserver", "myirmaserver", []string{".", "/etc/myirmaserver/"}, nil)

	// And build the configuration
	conf := &myirmaserver.Configuration{
		Configuration:      configureIRMAServer(),
		EmailConfiguration: configureEmail(),

		CORSAllowedOrigins: viper.GetStringSlice("cors-allowed-origins"),

		StaticPath:   viper.GetString("static-path"),
		StaticPrefix: viper.GetString("static-prefix"),

		DBType:       myirmaserver.DatabaseType(viper.GetString("db-type")),
		DBConnstring: viper.GetString("db-connstring"),

		LoginEmailSubject:    viper.GetStringMapString("login-email-subject"),
		LoginEmailFiles:      viper.GetStringMapString("login-email-files"),
		LoginEmailBaseURL:    viper.GetStringMapString("login-url"),
		DeleteEmailFiles:     viper.GetStringMapString("delete-email-files"),
		DeleteEmailSubject:   viper.GetStringMapString("delete-email-subject"),
		DeleteAccountFiles:   viper.GetStringMapString("delete-account-files"),
		DeleteAccountSubject: viper.GetStringMapString("delete-account-subject"),
		DeleteDelay:          viper.GetInt("delete-delay"),

		SessionLifetime: viper.GetInt("session-lifetime"),
	}

	conf.URL = server.ReplacePortString(viper.GetString("url"), viper.GetInt("port"))

	for _, v := range viper.GetStringSlice("keyshare-attributes") {
		conf.KeyshareAttributes = append(
			conf.KeyshareAttributes,
			irma.NewAttributeTypeIdentifier(v))
	}
	for _, v := range viper.GetStringSlice("email-attributes") {
		conf.EmailAttributes = append(
			conf.EmailAttributes,
			irma.NewAttributeTypeIdentifier(v))
	}

	return conf
}
