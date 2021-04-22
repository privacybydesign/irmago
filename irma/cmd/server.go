package cmd

import (
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/go-errors/errors"
	"github.com/mitchellh/mapstructure"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/sietseringers/cobra"
	"github.com/sietseringers/viper"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
)

var conf *requestorserver.Configuration

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "IRMA server for verifying and issuing attributes",
	Run: func(command *cobra.Command, args []string) {
		if err := configureServer(command); err != nil {
			die("", errors.WrapPrefix(err, "Failed to read configuration", 0))
		}
		serv, err := requestorserver.New(conf)
		if err != nil {
			die("", errors.WrapPrefix(err, "Failed to configure server", 0))
		}

		stopped := make(chan struct{})
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

		go func() {
			if err := serv.Start(conf); err != nil {
				die("", errors.WrapPrefix(err, "Failed to start server", 0))
			}
			conf.Logger.Debug("Server stopped")
			stopped <- struct{}{}
		}()

		for {
			select {
			case <-interrupt:
				conf.Logger.Debug("Caught interrupt")
				serv.Stop() // causes serv.Start() above to return
				conf.Logger.Debug("Sent stop signal to server")
			case <-stopped:
				conf.Logger.Info("Exiting")
				close(stopped)
				close(interrupt)
				return
			}
		}
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)

	if err := setFlags(serverCmd, productionMode()); err != nil {
		die("", errors.WrapPrefix(err, "Failed to attach flags to "+serverCmd.Name()+" command", 0))
	}
}

func setFlags(cmd *cobra.Command, production bool) error {
	flags := cmd.Flags()
	flags.SortFlags = false

	var defaulturl string
	var err error
	if !production {
		defaulturl, err = server.LocalIP()
		if err != nil {
			logger.Warn("Could not determine local IP address: ", err.Error())
		} else {
			defaulturl = "http://" + defaulturl + ":port"
		}
	}

	schemespath := irma.DefaultSchemesPath()

	flags.StringP("config", "c", "", "path to configuration file")
	flags.StringP("schemes-path", "s", schemespath, "path to irma_configuration")
	flags.String("schemes-assets-path", "", "if specified, copy schemes from here into --schemes-path")
	flags.Int("schemes-update", 60, "update IRMA schemes every x minutes (0 to disable)")
	flags.StringP("privkeys", "k", "", "path to IRMA private keys")
	flags.String("static-path", "", "Host files under this path as static files (leave empty to disable)")
	flags.String("static-prefix", "/", "Host static files under this URL prefix")
	flags.StringP("url", "u", defaulturl, "external URL to server to which the IRMA client connects, \":port\" being replaced by --port value")
	flags.String("revocation-db-type", "", "database type for revocation database (supported: mysql, postgres)")
	flags.String("revocation-db-str", "", "connection string for revocation database")
	flags.Bool("sse", false, "Enable server sent for status updates (experimental)")
	flags.String("store-type", "memory", "Specify how session state will be saved on the server.")
	flags.String("redis-settings", "", "redis settings (in JSON)")

	flags.IntP("port", "p", 8088, "port at which to listen")
	flags.StringP("listen-addr", "l", "", "address at which to listen (default 0.0.0.0)")
	flags.Int("client-port", 0, "if specified, start a separate server for the IRMA app at this port")
	flags.String("client-listen-addr", "", "address at which server for IRMA app listens")
	flags.Lookup("port").Header = `Server address and port to listen on`

	flags.Bool("no-auth", !production, "whether or not to authenticate requestors (and reject all authenticated requests)")
	flags.String("requestors", "", "requestor configuration (in JSON)")
	flags.StringSlice("disclose-perms", nil, "list of attributes that all requestors may verify (default *)")
	flags.StringSlice("sign-perms", nil, "list of attributes that all requestors may request in signatures (default *)")
	issHelp := "list of attributes that all requestors may issue"
	if !production {
		issHelp += " (default *)"
	}
	flags.StringSlice("issue-perms", nil, issHelp)
	flags.StringSlice("revoke-perms", nil, "list of credentials that all requestors may revoke")
	flags.Bool("skip-private-keys-check", false, "whether or not to skip checking whether the private keys that requestors have permission for using are present in the configuration")
	flags.String("static-sessions", "", "preconfigured static sessions (in JSON)")
	flags.Lookup("no-auth").Header = `Requestor authentication and default requestor permissions`

	flags.String("revocation-settings", "", "revocation settings (in JSON)")

	flags.StringP("jwt-issuer", "j", "irmaserver", "JWT issuer")
	flags.String("jwt-privkey", "", "JWT private key")
	flags.String("jwt-privkey-file", "", "path to JWT private key")
	flags.Int("max-request-age", 300, "max age in seconds of a session request JWT")
	flags.Bool("allow-unsigned-callbacks", false, "Allow callbackUrl in session requests when no JWT privatekey is installed (potentially unsafe)")
	flags.Bool("augment-client-return-url", false, "Augment the client return url with the server session token if present")
	flags.Lookup("jwt-issuer").Header = `JWT configuration`

	flags.String("tls-cert", "", "TLS certificate (chain)")
	flags.String("tls-cert-file", "", "path to TLS certificate (chain)")
	flags.String("tls-privkey", "", "TLS private key")
	flags.String("tls-privkey-file", "", "path to TLS private key")
	flags.String("client-tls-cert", "", "TLS certificate (chain) for IRMA app server")
	flags.String("client-tls-cert-file", "", "path to TLS certificate (chain) for IRMA app server")
	flags.String("client-tls-privkey", "", "TLS private key for IRMA app server")
	flags.String("client-tls-privkey-file", "", "path to TLS private key for IRMA app server")
	flags.Bool("no-tls", false, "Disable TLS")
	flags.Lookup("tls-cert").Header = "TLS configuration (leave empty to disable TLS)"

	flags.StringP("email", "e", "", "Email address of server admin, for incidental notifications such as breaking API changes")
	flags.Bool("no-email", !production, "Opt out of providing an email address with --email")
	flags.Lookup("email").Header = "Email address (see README for more info)"

	flags.CountP("verbose", "v", "verbose (repeatable)")
	flags.BoolP("quiet", "q", false, "quiet")
	flags.Bool("log-json", false, "Log in JSON format")
	flags.Bool("production", false, "Production mode")
	flags.Lookup("verbose").Header = `Other options`

	return nil
}

func configureServer(cmd *cobra.Command) error {
	dashReplacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(dashReplacer)
	viper.SetFileKeyReplacer(dashReplacer)
	viper.SetEnvPrefix("IRMASERVER")
	viper.AutomaticEnv()
	if err := viper.BindPFlags(cmd.Flags()); err != nil {
		return err
	}

	// Locate and read configuration file
	confpath := viper.GetString("config")
	if confpath != "" {
		dir, file := filepath.Dir(confpath), filepath.Base(confpath)
		viper.SetConfigName(strings.TrimSuffix(file, filepath.Ext(file)))
		viper.AddConfigPath(dir)
	} else {
		viper.SetConfigName("irmaserver")
		viper.AddConfigPath(".")
		viper.AddConfigPath("/etc/irmaserver/")
		viper.AddConfigPath("$HOME/.irmaserver")
	}
	err := viper.ReadInConfig() // Hold error checking until we know how much of it to log

	// Create our logger instance
	logger = server.NewLogger(viper.GetInt("verbose"), viper.GetBool("quiet"), viper.GetBool("log-json"))

	// First log output: hello, development or production mode, log level
	mode := "development"
	if viper.GetBool("production") {
		mode = "production"
		viper.SetDefault("no-auth", false)
		viper.SetDefault("no-email", false)
		viper.SetDefault("url", "")
	}
	logger.WithFields(logrus.Fields{
		"version":   irma.Version,
		"mode":      mode,
		"verbosity": server.Verbosity(viper.GetInt("verbose")),
	}).Info("irma server running")

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

	// Read configuration from flags and/or environmental variables
	conf = &requestorserver.Configuration{
		Configuration: &server.Configuration{
			SchemesPath:            viper.GetString("schemes-path"),
			SchemesAssetsPath:      viper.GetString("schemes-assets-path"),
			SchemesUpdateInterval:  viper.GetInt("schemes-update"),
			DisableSchemesUpdate:   viper.GetInt("schemes-update") == 0,
			IssuerPrivateKeysPath:  viper.GetString("privkeys"),
			RevocationDBType:       viper.GetString("revocation-db-type"),
			RevocationDBConnStr:    viper.GetString("revocation-db-str"),
			RevocationSettings:     irma.RevocationSettings{},
			URL:                    viper.GetString("url"),
			DisableTLS:             viper.GetBool("no-tls"),
			Email:                  viper.GetString("email"),
			EnableSSE:              viper.GetBool("sse"),
			StoreType:              viper.GetString("store-type"),
			RedisSettings:          irma.RedisSettings{},
			Verbose:                viper.GetInt("verbose"),
			Quiet:                  viper.GetBool("quiet"),
			LogJSON:                viper.GetBool("log-json"),
			Logger:                 logger,
			Production:             viper.GetBool("production"),
			JwtIssuer:              viper.GetString("jwt-issuer"),
			JwtPrivateKey:          viper.GetString("jwt-privkey"),
			JwtPrivateKeyFile:      viper.GetString("jwt-privkey-file"),
			AllowUnsignedCallbacks: viper.GetBool("allow-unsigned-callbacks"),
			AugmentClientReturnURL: viper.GetBool("augment-client-return-url"),
		},
		Permissions: requestorserver.Permissions{
			Disclosing: handlePermission("disclose-perms"),
			Signing:    handlePermission("sign-perms"),
			Issuing:    handlePermission("issue-perms"),
			Revoking:   handlePermission("revoke-perms"),
		},
		SkipPrivateKeysCheck:           viper.GetBool("skip-private-keys-check"),
		ListenAddress:                  viper.GetString("listen-addr"),
		Port:                           viper.GetInt("port"),
		ClientListenAddress:            viper.GetString("client-listen-addr"),
		ClientPort:                     viper.GetInt("client-port"),
		DisableRequestorAuthentication: viper.GetBool("no-auth"),
		Requestors:                     make(map[string]requestorserver.Requestor),
		MaxRequestAge:                  viper.GetInt("max-request-age"),
		StaticPath:                     viper.GetString("static-path"),
		StaticPrefix:                   viper.GetString("static-prefix"),

		TlsCertificate:           viper.GetString("tls-cert"),
		TlsCertificateFile:       viper.GetString("tls-cert-file"),
		TlsPrivateKey:            viper.GetString("tls-privkey"),
		TlsPrivateKeyFile:        viper.GetString("tls-privkey-file"),
		ClientTlsCertificate:     viper.GetString("client-tls-cert"),
		ClientTlsCertificateFile: viper.GetString("client-tls-cert-file"),
		ClientTlsPrivateKey:      viper.GetString("client-tls-privkey"),
		ClientTlsPrivateKeyFile:  viper.GetString("client-tls-privkey-file"),
	}

	if conf.Production {
		if !viper.GetBool("no-email") && conf.Email == "" {
			return errors.New("In production mode it is required to specify either an email address with the --email flag, or explicitly opting out with --no-email. See help or README for more info.")
		}
		if viper.GetBool("no-email") && conf.Email != "" {
			return errors.New("--no-email cannot be combined with --email")
		}
	}

	// Handle requestors
	if err = handleMapOrString("requestors", &conf.Requestors); err != nil {
		return err
	}
	if err = handleMapOrString("static-sessions", &conf.StaticSessions); err != nil {
		return err
	}
	var m map[string]*irma.RevocationSetting
	if err = handleMapOrString("revocation-settings", &m); err != nil {
		return err
	}
	for i, s := range m {
		conf.RevocationSettings[irma.NewCredentialTypeIdentifier(i)] = s
	}

	// Parse Redis store configuration
	if err = handleMapOrString("redis-settings", &conf.RedisSettings); err != nil {
		return err
	}


	logger.Debug("Done configuring")

	return nil
}

func handleMapOrString(key string, dest interface{}) error {
	var m map[string]interface{}
	var err error
	if val, flagOrEnv := viper.Get(key).(string); !flagOrEnv || val != "" {
		if m, err = cast.ToStringMapE(viper.Get(key)); err != nil {
			return errors.WrapPrefix(err, "Failed to unmarshal "+key+" from flag or env var", 0)
		}
	}
	if len(m) == 0 {
		return nil
	}
	if err := mapstructure.Decode(m, dest); err != nil {
		return errors.WrapPrefix(err, "Failed to unmarshal "+key+" from config file", 0)
	}
	return nil
}

func handlePermission(typ string) []string {
	if !viper.IsSet(typ) {
		if typ == "revoke-perms" || (viper.GetBool("production") && typ == "issue-perms") {
			return []string{}
		} else {
			return []string{"*"}
		}
	}
	perms := viper.GetStringSlice(typ)
	if perms == nil {
		return []string{}
	}
	return perms
}

// productionMode examines the arguments passed to the executable to see if --production is enabled.
// (This should really be done using viper, but when the help message is printed, viper is not yet
// initialized.)
func productionMode() bool {
	r := regexp.MustCompile("^--production(=(.*))?$")
	for _, arg := range os.Args {
		matches := r.FindStringSubmatch(arg)
		if len(matches) != 3 {
			continue
		}
		if matches[1] == "" {
			return true
		}
		return checkConfVal(matches[2])
	}

	return checkConfVal(os.Getenv("IRMASERVER_PRODUCTION"))
}

func checkConfVal(val string) bool {
	lc := strings.ToLower(val)
	return lc == "1" || lc == "true" || lc == "yes" || lc == "t"
}
