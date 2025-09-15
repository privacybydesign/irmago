package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/requestorserver"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	localIP, localIPErr = server.LocalIP()
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
	cmd.SetUsageTemplate(headerFlagsTemplate)
	headers := map[string]string{}
	flagHeaders["irma server"] = headers

	var defaulturl string
	if !production {
		if localIP != "" {
			defaulturl = "http://" + localIP + ":port"
		}
	}

	schemesPath := irma.DefaultSchemesPath()
	schemesAssetsPath := irma.DefaultSchemesAssetsPath()

	flags := cmd.Flags()
	flags.SortFlags = false

	flags.StringP("config", "c", "", "path to configuration file")
	flags.StringP("schemes-path", "s", schemesPath, "path to irma_configuration")
	flags.String("schemes-assets-path", schemesAssetsPath, "if specified, copy schemes from here into --schemes-path")
	flags.Int("schemes-update", 60, "update IRMA schemes every x minutes (0 to disable)")
	flags.StringP("privkeys", "k", "", "path to IRMA private keys")
	flags.String("static-path", "", "Host files under this path as static files (leave empty to disable)")
	flags.String("static-prefix", "/", "Host static files under this URL prefix")
	flags.StringP("url", "u", defaulturl, "external URL to server to which the IRMA client connects, \":port\" being replaced by --port value")
	flags.String("revocation-db-type", "", "database type for revocation database (supported: mysql, postgres)")
	flags.String("revocation-db-str", "", "connection string for revocation database")
	flags.Bool("sse", false, "Enable server sent for status updates (experimental)")

	headers["port"] = "Server address and port to listen on"
	flags.IntP("port", "p", 8088, "port at which to listen")
	flags.StringP("listen-addr", "l", "", "address at which to listen (default 0.0.0.0)")
	flags.StringP("api-prefix", "a", "/", "prefix API endpoints with this string, e.g. POST /session becomes POST {api-prefix}/session")
	flags.Int("client-port", 0, "if specified, start a separate server for the IRMA app at this port")
	flags.String("client-listen-addr", "", "address at which server for IRMA app listens")

	headers["no-auth"] = "Requestor authentication and default requestor permissions"
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
	flags.Int("max-session-lifetime", 15, "maximum duration of a session once a client connects in minutes")
	flags.Int("session-result-lifetime", 5, "determines how long a session result is preserved in minutes")

	flags.String("revocation-settings", "", "revocation settings (in JSON)")

	headers["sdjwtvc-issuer-certificates-dir"] = "SD-JWT VC issuance configuration"
	flags.String("sdjwtvc-issuer-certificates-dir", "", "SD-JWT VC issuer certificates directory dir")
	flags.String("sdjwtvc-issuer-private-keys-dir", "", "SD-JWT VC issuer private keys directory dir")

	headers["store-type"] = "Session store configuration"
	flags.String("store-type", "", "specifies how session state will be saved on the server (default \"memory\")")
	flags.String("redis-addr", "", "Redis address, to be specified as host:port")
	flags.StringSlice("redis-sentinel-addrs", nil, "Redis Sentinel addresses, to be specified as host:port")
	flags.String("redis-sentinel-master-name", "", "Redis Sentinel master name")
	flags.Bool("redis-accept-inconsistency-risk", false, "accept the risk of inconsistent session state when using Redis Sentinel")
	flags.String("redis-username", "", "Redis server username (when using ACLs)")
	flags.String("redis-pw", "", "Redis server password")
	flags.String("redis-sentinel-username", "", "Redis Sentinel username (when using ACLs)")
	flags.String("redis-sentinel-pw", "", "Redis Sentinel password")
	flags.Bool("redis-allow-empty-password", false, "explicitly allow an empty string as Redis password")
	flags.Bool("redis-acl-use-key-prefixes", false, "if enabled all Redis keys will be prefixed with the username for ACLs (username:key)")
	flags.Int("redis-db", 0, "database to be selected after connecting to the server (default 0)")
	flags.String("redis-tls-cert", "", "use Redis TLS with specific certificate or certificate authority")
	flags.String("redis-tls-cert-file", "", "use Redis TLS path to specific certificate or certificate authority")
	flags.String("redis-tls-client-key-file", "", "use Redis mTLS with specified client key path")
	flags.String("redis-tls-client-cert-file", "", "use Redis mTLS with specified client certificate path")
	flags.Bool("redis-no-tls", false, "disable Redis TLS (by default, Redis TLS is enabled with the system certificate pool)")

	headers["jwt-issuer"] = "JWT configuration"
	flags.StringP("jwt-issuer", "j", "irmaserver", "JWT issuer")
	flags.String("jwt-privkey", "", "JWT private key")
	flags.String("jwt-privkey-file", "", "path to JWT private key")
	flags.Int("max-request-age", 300, "max age in seconds of a session request JWT")
	flags.Bool("allow-unsigned-callbacks", false, "Allow callbackUrl in session requests when no JWT privatekey is installed (potentially unsafe)")
	flags.Bool("augment-client-return-url", false, "Augment the client return url with the server session token if present")

	headers["tls-cert"] = "TLS configuration (leave empty to disable TLS)"
	flags.String("tls-cert", "", "TLS certificate (chain)")
	flags.String("tls-cert-file", "", "path to TLS certificate (chain)")
	flags.String("tls-privkey", "", "TLS private key")
	flags.String("tls-privkey-file", "", "path to TLS private key")
	flags.String("client-tls-cert", "", "TLS certificate (chain) for IRMA app server")
	flags.String("client-tls-cert-file", "", "path to TLS certificate (chain) for IRMA app server")
	flags.String("client-tls-privkey", "", "TLS private key for IRMA app server")
	flags.String("client-tls-privkey-file", "", "path to TLS private key for IRMA app server")
	flags.Bool("no-tls", false, "disable TLS")

	headers["email"] = "Email address (see README for more info)"
	flags.StringP("email", "e", "", "Email address of server admin, for incidental notifications such as breaking API changes")
	flags.Bool("no-email", !production, "Opt out of providing an email address with --email")

	headers["verbose"] = "Other options"
	flags.CountP("verbose", "v", "verbose (repeatable)")
	flags.BoolP("quiet", "q", false, "quiet")
	flags.Bool("log-json", false, "Log in JSON format")
	flags.Bool("production", false, "Production mode")

	return nil
}

func configureServer(cmd *cobra.Command) (*requestorserver.Configuration, error) {
	if localIPErr != nil {
		logger.Warn("Could not determine local IP address: ", localIPErr.Error())
	}

	readConfig(cmd, "irmaserver", "irma server", []string{".", "/etc/irmaserver/", "$HOME/.irmaserver"},
		map[string]interface{}{
			"no_auth":  false,
			"no_email": false,
			"url":      "",
		},
	)

	irmaServerConf, err := configureIRMAServer()
	if err != nil {
		return nil, err
	}

	// Read configuration from flags and/or environmental variables
	conf := &requestorserver.Configuration{
		Configuration: irmaServerConf,
		Permissions: requestorserver.Permissions{
			Disclosing: handlePermission("disclose_perms"),
			Signing:    handlePermission("sign_perms"),
			Issuing:    handlePermission("issue_perms"),
			Revoking:   handlePermission("revoke_perms"),
		},
		SkipPrivateKeysCheck:           viper.GetBool("skip_private_keys_check"),
		ListenAddress:                  viper.GetString("listen_addr"),
		Port:                           viper.GetInt("port"),
		ApiPrefix:                      viper.GetString("api_prefix"),
		ClientListenAddress:            viper.GetString("client_listen_addr"),
		ClientPort:                     viper.GetInt("client_port"),
		DisableRequestorAuthentication: viper.GetBool("no_auth"),
		Requestors:                     make(map[string]requestorserver.Requestor),
		MaxRequestAge:                  viper.GetInt("max_request_age"),
		StaticPath:                     viper.GetString("static_path"),
		StaticPrefix:                   viper.GetString("static_prefix"),

		TlsCertificate:           viper.GetString("tls_cert"),
		TlsCertificateFile:       viper.GetString("tls_cert_file"),
		TlsPrivateKey:            viper.GetString("tls_privkey"),
		TlsPrivateKeyFile:        viper.GetString("tls_privkey_file"),
		ClientTlsCertificate:     viper.GetString("client_tls_cert"),
		ClientTlsCertificateFile: viper.GetString("client_tls_cert_file"),
		ClientTlsPrivateKey:      viper.GetString("client_tls_privkey"),
		ClientTlsPrivateKeyFile:  viper.GetString("client_tls_privkey_file"),
	}

	if conf.Production {
		if !viper.GetBool("no_email") && conf.Email == "" {
			return nil, errors.New("In production mode it is required to specify either an email address with the --email flag, or explicitly opting out with --no-email. See help or README for more info.")
		}
		if viper.GetBool("no_email") && conf.Email != "" {
			return nil, errors.New("--no-email cannot be combined with --email")
		}
	}

	// no error handling for this one, as it can be left empty
	if wasProvidedInAnyWay("sdjwtvc") {
		if err := handleMapOrString("sdjwtvc", &conf.SdJwtIssuanceSettings); err != nil {
			return nil, err
		}
	}

	// Handle requestors
	if err := handleMapOrString("requestors", &conf.Requestors); err != nil {
		return nil, err
	}
	if err := handleMapOrString("static_sessions", &conf.StaticSessions); err != nil {
		return nil, err
	}
	var m map[string]*irma.RevocationSetting
	if err = handleMapOrString("revocation_settings", &m); err != nil {
		return nil, err
	}
	for i, s := range m {
		conf.RevocationSettings[irma.NewCredentialTypeIdentifier(i)] = s
	}

	logger.Debug("Done configuring")

	return conf, nil
}
