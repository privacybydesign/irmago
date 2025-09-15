package cmd

import (
	"crypto/tls"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"

	"github.com/go-errors/errors"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cast"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func configureEmail() keyshare.EmailConfiguration {
	// If username/password are specified for the email server, build an authentication object.
	var emailAuth smtp.Auth
	if viper.GetString("email_username") != "" {
		emailAuth = smtp.PlainAuth(
			"",
			viper.GetString("email_username"),
			viper.GetString("email_password"),
			viper.GetString("email_hostname"),
		)
	}

	return keyshare.EmailConfiguration{
		EmailServer:     viper.GetString("email_server"),
		EmailHostname:   viper.GetString("email_hostname"),
		EmailAuth:       emailAuth,
		EmailFrom:       viper.GetString("email_from"),
		DefaultLanguage: viper.GetString("default_language"),
	}
}

func getSdJwtIssuanceConfigFromCli() *server.SdJwtIssuanceSettings {
	certChainsDir := viper.GetString("sdjwtvc_issuer_certificates_dir")
	privKeysDir := viper.GetString("sdjwtvc_issuer_private_keys_dir")

	if certChainsDir == "" && privKeysDir == "" {
		return nil
	}

	return &server.SdJwtIssuanceSettings{
		SdJwtIssuerCertificatesDir: certChainsDir,
		SdJwtIssuerPrivKeysDir:     privKeysDir,
	}
}

func configureIRMAServer() (*server.Configuration, error) {
	conf := &server.Configuration{
		SchemesPath:            viper.GetString("schemes_path"),
		SchemesAssetsPath:      viper.GetString("schemes_assets_path"),
		SchemesUpdateInterval:  viper.GetInt("schemes_update"),
		DisableSchemesUpdate:   viper.GetInt("schemes_update") == 0,
		IssuerPrivateKeysPath:  viper.GetString("privkeys"),
		RevocationDBType:       viper.GetString("revocation_db_type"),
		RevocationDBConnStr:    viper.GetString("revocation_db_str"),
		RevocationSettings:     irma.RevocationSettings{},
		URL:                    viper.GetString("url"),
		DisableTLS:             viper.GetBool("no_tls"),
		Email:                  viper.GetString("email"),
		EnableSSE:              viper.GetBool("sse"),
		StoreType:              viper.GetString("store_type"),
		Verbose:                viper.GetInt("verbose"),
		Quiet:                  viper.GetBool("quiet"),
		LogJSON:                viper.GetBool("log_json"),
		Logger:                 logger,
		Production:             viper.GetBool("production"),
		MaxSessionLifetime:     viper.GetInt("max_session_lifetime"),
		SessionResultLifetime:  viper.GetInt("session_result_lifetime"),
		JwtIssuer:              viper.GetString("jwt_issuer"),
		JwtPrivateKey:          viper.GetString("jwt_privkey"),
		JwtPrivateKeyFile:      viper.GetString("jwt_privkey_file"),
		AllowUnsignedCallbacks: viper.GetBool("allow_unsigned_callbacks"),
		AugmentClientReturnURL: viper.GetBool("augment_client_return_url"),
		SdJwtIssuanceSettings:  getSdJwtIssuanceConfigFromCli(),
	}

	// Parse session store configuration
	switch conf.StoreType {
	case "redis":
		conf.RedisSettings = &server.RedisSettings{}
		conf.RedisSettings.Addr = viper.GetString("redis_addr")
		conf.RedisSettings.SentinelAddrs = viper.GetStringSlice("redis_sentinel_addrs")
		conf.RedisSettings.SentinelMasterName = viper.GetString("redis_sentinel_master_name")
		conf.RedisSettings.AcceptInconsistencyRisk = viper.GetBool("redis_accept_inconsistency_risk")

		if conf.RedisSettings.Addr == "" && len(conf.RedisSettings.SentinelAddrs) == 0 || conf.RedisSettings.Addr != "" && len(conf.RedisSettings.SentinelAddrs) > 0 {
			return nil, errors.New("When Redis is used as session data store, either --redis-addr or --redis-sentinel-addrs must be specified.")
		}

		conf.RedisSettings.Username = viper.GetString("redis_username")
		if conf.RedisSettings.Password = viper.GetString("redis_pw"); conf.RedisSettings.Password == "" && !viper.GetBool("redis_allow_empty_password") {
			return nil, errors.New("When Redis is used as session data store, a non-empty Redis password must be specified with the --redis-pw flag. This restriction can be relaxed by setting the --redis-allow-empty-password flag to true.")
		}
		conf.RedisSettings.SentinelUsername = viper.GetString("redis_sentinel_username")
		conf.RedisSettings.SentinelPassword = viper.GetString("redis_sentinel_pw")
		conf.RedisSettings.ACLUseKeyPrefixes = viper.GetBool("redis_acl_use_key_prefixes")

		conf.RedisSettings.DB = viper.GetInt("redis_db")

		conf.RedisSettings.TLSCertificate = viper.GetString("redis_tls_cert")
		conf.RedisSettings.TLSCertificateFile = viper.GetString("redis_tls_cert_file")
		conf.RedisSettings.TLSClientKeyFile = viper.GetString("redis_tls_client_key_file")
		conf.RedisSettings.TLSClientCertificateFile = viper.GetString("redis_tls_client_cert_file")

		conf.RedisSettings.DisableTLS = viper.GetBool("redis_no_tls")
	}
	return conf, nil
}

func configureTLS() *tls.Config {
	conf, err := server.TLSConf(
		viper.GetString("tls_cert"),
		viper.GetString("tls_cert_file"),
		viper.GetString("tls_privkey"),
		viper.GetString("tls_privkey_file"))
	if err != nil {
		die("", err)
	}
	return conf
}

func readConfig(cmd *cobra.Command, name, logname string, configpaths []string, productionDefaults map[string]interface{}) {
	dashReplacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(dashReplacer)
	viper.SetEnvPrefix(strings.ToUpper(name))
	viper.AutomaticEnv()

	// Bind cmd flags to viper, such that configuration files use underscores instead of dashes
	f := cmd.Flags()
	normalizeFunc := f.GetNormalizeFunc()
	f.SetNormalizeFunc(func(fs *pflag.FlagSet, name string) pflag.NormalizedName {
		return pflag.NormalizedName(dashReplacer.Replace(string(normalizeFunc(fs, name))))
	})
	if err := viper.BindPFlags(f); err != nil {
		die("", err)
	}

	// Locate and read configuration file
	confpath := viper.GetString("config")
	if confpath != "" {
		info, err := os.Stat(confpath)
		if err != nil {
			if os.IsNotExist(err) {
				die("specified configuration file does not exist", nil)
			} else {
				die("failed to stat configuration file", err)
			}
		}
		if info.IsDir() {
			die("specified configuration file is a directory", nil)
		}
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
	logger = server.NewLogger(viper.GetInt("verbose"), viper.GetBool("quiet"), viper.GetBool("log_json"))

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

	if logger.Level >= logrus.TraceLevel {
		logger.Warn("Logger has been configured to show TRACE messages. These messages may contain untrusted user input and personal data of users. Use this option with care!")
	}

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

func wasProvidedInAnyWay(key string) bool {
	if val, flagOrEnv := viper.Get(key).(string); !flagOrEnv || val != "" {
		if _, err := cast.ToStringMapE(viper.Get(key)); err != nil {
			return false
		}
	}
	return true
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
		if typ == "revoke_perms" || (viper.GetBool("production") && typ == "issue_perms") {
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
