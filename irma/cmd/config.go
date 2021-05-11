package cmd

import (
	"net/smtp"
	"path/filepath"
	"strings"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"

	"github.com/sietseringers/cobra"
	"github.com/sietseringers/viper"
	"github.com/sirupsen/logrus"
)

func configureEmail() keyshare.EmailConfiguration {
	// If username/password are specified for the email server, build an authentication object.
	var emailAuth smtp.Auth
	if viper.GetString("email-username") != "" {
		emailAuth = smtp.PlainAuth(
			"",
			viper.GetString("email-username"),
			viper.GetString("email-password"),
			viper.GetString("email-hostname"),
		)
	}

	return keyshare.EmailConfiguration{
		EmailServer:     viper.GetString("email-server"),
		EmailAuth:       emailAuth,
		EmailFrom:       viper.GetString("email-from"),
		DefaultLanguage: viper.GetString("default-language"),
	}
}

func configureIRMAServer() *server.Configuration {
	return &server.Configuration{
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
	}
}

func readConfig(cmd *cobra.Command, name, logname string, configpaths []string, productionDefaults map[string]interface{}) {
	dashReplacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(dashReplacer)
	viper.SetFileKeyReplacer(dashReplacer)
	viper.SetEnvPrefix(strings.ToUpper(name))
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
		viper.SetConfigName(name)
		for _, path := range configpaths {
			viper.AddConfigPath(path)
		}
	}

	err := viper.ReadInConfig() // Hold error checking until we know how much of it to log

	// Create our logger instance
	logger = server.NewLogger(viper.GetInt("verbose"), viper.GetBool("quiet"), viper.GetBool("log-json"))

	// First log output: hello, development or production mode, log level
	mode := "development"
	if viper.GetBool("production") {
		mode = "production"
		for key, val := range productionDefaults {
			viper.SetDefault(key, val)
		}
	}
	logger.WithFields(logrus.Fields{
		"version":   irma.Version,
		"mode":      mode,
		"verbosity": server.Verbosity(viper.GetInt("verbose")),
	}).Info(logname + " running")

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
}
