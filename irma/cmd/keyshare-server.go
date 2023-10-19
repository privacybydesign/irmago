package cmd

import (
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare/keyshareserver"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var keyshareServerCmd = &cobra.Command{
	Use:   "server",
	Short: "IRMA keyshare server",
	Run: func(command *cobra.Command, args []string) {
		conf, err := configureKeyshareServer(command)
		if err != nil {
			die("failed to read configuration", err)
		}

		// Create main server
		keyshareServer, err := keyshareserver.New(conf)
		if err != nil {
			die("", err)
		}

		runServer(keyshareServer, conf.Logger)
	},
}

func init() {
	keyshareRootCmd.AddCommand(keyshareServerCmd)

	keyshareServerCmd.SetUsageTemplate(headerFlagsTemplate)
	headers := map[string]string{}
	flagHeaders["irma keyshare server"] = headers

	flags := keyshareServerCmd.Flags()
	flags.SortFlags = false
	flags.StringP("config", "c", "", "path to configuration file")
	flags.StringP("schemes-path", "s", irma.DefaultSchemesPath(), "path to irma_configuration")
	flags.String("schemes-assets-path", irma.DefaultSchemesAssetsPath(), "if specified, copy schemes from here into --schemes-path")
	flags.Int("schemes-update", 60, "update IRMA schemes every x minutes (0 to disable)")
	flags.StringP("privkeys", "k", "", "path to IRMA private keys")
	flags.StringP("url", "u", "", "external URL to server to which the IRMA client connects, \":port\" being replaced by --port value")

	headers["port"] = "Server address and port to listen on"
	flags.IntP("port", "p", 8080, "port at which to listen")
	flags.StringP("listen-addr", "l", "", "address at which to listen (default 0.0.0.0)")

	headers["db-type"] = "Database configuration"
	flags.String("db-type", string(keyshareserver.DBTypePostgres), "Type of database to connect keyshare server to")
	flags.String("db-str", "", "Database server connection string")
	flags.Int("db-max-idle", 2, "Maximum number of database connections in the idle connection pool")
	flags.Int("db-max-open", 0, "Maximum number of open database connections (default unlimited)")
	flags.Int("db-max-idle-time", 0, "Time in seconds after which idle database connections are closed (default unlimited)")
	flags.Int("db-max-open-time", 0, "Maximum lifetime in seconds of open database connections (default unlimited)")

	headers["store-type"] = "Session store configuration"
	flags.String("store-type", "", "specifies how session state will be saved on the server (default \"memory\")")
	flags.String("redis-addr", "", "Redis address, to be specified as host:port")
	flags.StringSlice("redis-sentinel-addrs", nil, "Redis Sentinel addresses, to be specified as host:port")
	flags.String("redis-sentinel-master-name", "", "Redis Sentinel master name")
	flags.Bool("redis-accept-inconsistency-risk", false, "accept the risk of inconsistent session state when using Redis Sentinel")
	flags.String("redis-username", "", "Redis server username (when using ACLs)")
	flags.String("redis-pw", "", "Redis server password")
	flags.Bool("redis-allow-empty-password", false, "explicitly allow an empty string as Redis password")
	flags.Bool("redis-acl-use-key-prefixes", false, "if enabled all Redis keys will be prefixed with the username for ACLs (username:key)")
	flags.Int("redis-db", 0, "database to be selected after connecting to the server (default 0)")
	flags.String("redis-tls-cert", "", "use Redis TLS with specific certificate or certificate authority")
	flags.String("redis-tls-cert-file", "", "use Redis TLS path to specific certificate or certificate authority")
	flags.Bool("redis-no-tls", false, "disable Redis TLS (by default, Redis TLS is enabled with the system certificate pool)")

	headers["jwt-privkey"] = "Cryptographic keys"
	flags.String("jwt-privkey", "", "Private jwt key of keyshare server")
	flags.String("jwt-privkey-file", "", "Path to file containing private jwt key of keyshare server")
	flags.Int("jwt-privkey-id", 0, "Key identifier of keyshare server public key matching used private key")
	flags.String("jwt-issuer", keysharecore.JWTIssuerDefault, "JWT issuer used in \"iss\" field")
	flags.Int("jwt-pin-expiry", keysharecore.JWTPinExpiryDefault, "Expiry of PIN JWT in seconds")
	flags.String("storage-primary-key-file", "", "Primary key used for encrypting and decrypting secure containers")
	flags.StringSlice("storage-fallback-key-file", nil, "Fallback key(s) used to decrypt older secure containers")

	headers["keyshare-attribute"] = "Keyshare server attribute issued during registration"
	flags.String("keyshare-attribute", "", "Attribute identifier that contains username")

	headers["email-server"] = "Email configuration (leave empty to disable sending emails)"
	flags.String("email-server", "", "Email server to use for sending email address confirmation emails")
	flags.String("email-hostname", "", "Hostname used in email server tls certificate (leave empty when mail server does not use tls)")
	flags.String("email-username", "", "Username to use when authenticating with email server")
	flags.String("email-password", "", "Password to use when authenticating with email server")
	flags.String("email-from", "", "Email address to use as sender address")
	flags.String("default-language", "en", "Default language, used as fallback when users preferred language is not available")
	flags.StringToString("registration-email-subjects", nil, "Translated subject lines for the registration email")
	flags.StringToString("registration-email-files", nil, "Translated emails for the registration email")
	flags.StringToString("verification-url", nil, "Base URL for the email verification link (localized)")
	flags.Int("email-token-validity", 168, "Validity of email token in hours")

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

func configureKeyshareServer(cmd *cobra.Command) (*keyshareserver.Configuration, error) {
	readConfig(cmd, "keyshareserver", "keyshareserver", []string{".", "/etc/keyshareserver"}, nil)

	irmaServerConf, err := configureIRMAServer()
	if err != nil {
		return nil, err
	}

	// And build the configuration
	conf := &keyshareserver.Configuration{
		Configuration:      irmaServerConf,
		EmailConfiguration: configureEmail(),

		DBType:            keyshareserver.DBType(viper.GetString("db_type")),
		DBConnStr:         viper.GetString("db_str"),
		DBConnMaxIdle:     viper.GetInt("db_max_idle"),
		DBConnMaxOpen:     viper.GetInt("db_max_open"),
		DBConnMaxIdleTime: viper.GetInt("db_max_idle_time"),
		DBConnMaxOpenTime: viper.GetInt("db_max_open_time"),

		JwtKeyID:                viper.GetUint32("jwt_privkey_id"),
		JwtPrivateKey:           viper.GetString("jwt_privkey"),
		JwtPrivateKeyFile:       viper.GetString("jwt_privkey_file"),
		JwtIssuer:               viper.GetString("jwt_issuer"),
		JwtPinExpiry:            viper.GetInt("jwt_pin_expiry"),
		StoragePrimaryKeyFile:   viper.GetString("storage_primary_key_file"),
		StorageFallbackKeyFiles: viper.GetStringSlice("storage_fallback_key_file"),

		KeyshareAttribute: irma.NewAttributeTypeIdentifier(viper.GetString("keyshare_attribute")),

		RegistrationEmailSubjects: viper.GetStringMapString("registration_email_subjects"),
		RegistrationEmailFiles:    viper.GetStringMapString("registration_email_files"),
		VerificationURL:           viper.GetStringMapString("verification_url"),
		EmailTokenValidity:        viper.GetInt("email_token_validity"),
	}

	if conf.Production && conf.DBType != keyshareserver.DBTypePostgres {
		return nil, errors.New("in production mode, db-type must be postgres")
	}

	conf.URL = server.ReplacePortString(viper.GetString("url"), viper.GetInt("port"))

	return conf, nil
}
