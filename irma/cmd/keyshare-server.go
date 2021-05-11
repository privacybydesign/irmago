package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare/keyshareserver"
	"github.com/sietseringers/cobra"
	"github.com/sietseringers/viper"
)

var keysharedCmd = &cobra.Command{
	Use:   "server",
	Short: "IRMA keyshare server",
	Run: func(command *cobra.Command, args []string) {
		conf := configureKeyshared(command)

		// Determine full listening address.
		fullAddr := fmt.Sprintf("%s:%d", viper.GetString("listen-addr"), viper.GetInt("port"))

		// Load TLS configuration
		TLSConfig, err := kesyharedTLS(
			viper.GetString("tls-cert"),
			viper.GetString("tls-cert-file"),
			viper.GetString("tls-privkey"),
			viper.GetString("tls-privkey-file"))
		if err != nil {
			die("", err)
		}

		// Create main server
		keyshareServer, err := keyshareserver.New(conf)
		if err != nil {
			die("", err)
		}

		serv := &http.Server{
			Addr:      fullAddr,
			Handler:   keyshareServer.Handler(),
			TLSConfig: TLSConfig,
		}

		stopped := make(chan struct{})
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

		go func() {
			if TLSConfig != nil {
				err = serv.ListenAndServeTLS("", "")
			} else {
				err = serv.ListenAndServe()
			}
			conf.Logger.Debug("Server stopped")
			stopped <- struct{}{}
		}()

		for {
			select {
			case <-interrupt:
				conf.Logger.Debug("Caught interrupt")
				err = serv.Shutdown(context.Background())
				if err != nil {
					_ = server.LogError(err)
				}
				keyshareServer.Stop()
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
	keyshareRoot.AddCommand(keysharedCmd)

	flags := keysharedCmd.Flags()
	flags.SortFlags = false
	flags.StringP("config", "c", "", "path to configuration file")
	flags.StringP("schemes-path", "s", irma.DefaultSchemesPath(), "path to irma_configuration")
	flags.String("schemes-assets-path", "", "if specified, copy schemes from here into --schemes-path")
	flags.Int("schemes-update", 60, "update IRMA schemes every x minutes (0 to disable)")
	flags.StringP("privkeys", "k", "", "path to IRMA private keys")
	flags.StringP("url", "u", "", "external URL to server to which the IRMA client connects, \":port\" being replaced by --port value")

	flags.IntP("port", "p", 8080, "port at which to listen")
	flags.StringP("listen-addr", "l", "", "address at which to listen (default 0.0.0.0)")
	flags.Lookup("port").Header = `Server address and port to listen on`

	flags.String("db-type", keyshareserver.DatabaseTypePostgres, "Type of database to connect keyshare server to")
	flags.String("db", "", "Database server connection string")
	flags.Lookup("db-type").Header = `Database configuration`

	flags.String("jwt-privkey", "", "Private jwt key of keyshare server")
	flags.String("jwt-privkey-file", "", "Path to file containing private jwt key of keyshare server")
	flags.Int("jwt-privkey-id", 0, "Key identifier of keyshare server public key matching used private key")
	flags.String("storage-primary-keyfile", "", "Primary key used for encrypting and decrypting secure containers")
	flags.StringSlice("storage-fallback-keyfile", nil, "Fallback key(s) used to decrypt older secure containers")
	flags.Lookup("jwt-privkey").Header = `Cryptographic keys`

	flags.String("keyshare-credential", "", "Credential issued during keyshare server registration")
	flags.String("keyshare-attribute", "", "Attribute within keyshare credential that contains username")
	flags.Lookup("keyshare-credential").Header = `Keyshare server credential`

	flags.String("email-server", "", "Email server to use for sending email address confirmation emails")
	flags.String("email-hostname", "", "Hostname used in email server tls certificate (leave empty when mail server does not use tls)")
	flags.String("email-username", "", "Username to use when authenticating with email server")
	flags.String("email-password", "", "Password to use when authenticating with email server")
	flags.String("email-from", "", "Email address to use as sender address")
	flags.String("default-language", "en", "Default language, used as fallback when users prefered language is not available")
	flags.StringToString("registration-email-subject", nil, "Translated subject lines for the registration email")
	flags.StringToString("registration-email-files", nil, "Translated emails for the registration email")
	flags.StringToString("verification-url", nil, "Base URL for the email verification link (localized)")
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

func configureKeyshared(cmd *cobra.Command) *keyshareserver.Configuration {
	readConfig(cmd, "keyshareserver", "keyshareserver", []string{".", "/etc/keyshareserver"}, nil)

	// And build the configuration
	conf := &keyshareserver.Configuration{
		Configuration:      configureIRMAServer(),
		EmailConfiguration: configureEmail(),

		DBType:       keyshareserver.DatabaseType(viper.GetString("db-type")),
		DBConnstring: viper.GetString("db-connstring"),

		JwtKeyID:                viper.GetUint32("jwt-privkey-id"),
		JwtPrivateKey:           viper.GetString("jwt-privkey"),
		JwtPrivateKeyFile:       viper.GetString("jwt-privkey-file"),
		StoragePrimaryKeyFile:   viper.GetString("storage-primary-keyfile"),
		StorageFallbackKeyFiles: viper.GetStringSlice("storage-fallback-keyfile"),

		KeyshareAttribute: irma.NewAttributeTypeIdentifier(viper.GetString("keyshare-attribute")),

		RegistrationEmailSubject: viper.GetStringMapString("registration-email-subject"),
		RegistrationEmailFiles:   viper.GetStringMapString("registration-email-files"),
		VerificationURL:          viper.GetStringMapString("verification-url"),
	}

	conf.URL = server.ReplacePortString(viper.GetString("url"), viper.GetInt("port"))

	return conf
}

func kesyharedTLS(cert, certfile, key, keyfile string) (*tls.Config, error) {
	if cert == "" && certfile == "" && key == "" && keyfile == "" {
		return nil, nil
	}

	var certbts, keybts []byte
	var err error
	if certbts, err = common.ReadKey(cert, certfile); err != nil {
		return nil, err
	}
	if keybts, err = common.ReadKey(key, keyfile); err != nil {
		return nil, err
	}

	cer, err := tls.X509KeyPair(certbts, keybts)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:             []tls.Certificate{cer},
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}, nil
}
