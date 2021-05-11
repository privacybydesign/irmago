package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/sietseringers/cobra"
	"github.com/sietseringers/viper"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "IRMA server for verifying and issuing attributes",
	Run: func(command *cobra.Command, args []string) {
		conf, err := configureServer(command)
		if err != nil {
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

func configureServer(cmd *cobra.Command) (*requestorserver.Configuration, error) {
	readConfig(cmd, "irmaserver", "irma server", []string{".", "/etc/irmaserver/", "$HOME/.irmaserver"},
		map[string]interface{}{
			"no-auth":  false,
			"no-email": false,
			"url":      "",
		},
	)

	// Read configuration from flags and/or environmental variables
	conf := &requestorserver.Configuration{
		Configuration: configureIRMAServer(),
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
			return nil, errors.New("In production mode it is required to specify either an email address with the --email flag, or explicitly opting out with --no-email. See help or README for more info.")
		}
		if viper.GetBool("no-email") && conf.Email != "" {
			return nil, errors.New("--no-email cannot be combined with --email")
		}
	}

	// Handle requestors
	var err error
	if err = handleMapOrString("requestors", &conf.Requestors); err != nil {
		return nil, err
	}
	if err = handleMapOrString("static-sessions", &conf.StaticSessions); err != nil {
		return nil, err
	}
	var m map[string]*irma.RevocationSetting
	if err = handleMapOrString("revocation-settings", &m); err != nil {
		return nil, err
	}
	for i, s := range m {
		conf.RevocationSettings[irma.NewCredentialTypeIdentifier(i)] = s
	}

	logger.Debug("Done configuring")

	return conf, nil
}
