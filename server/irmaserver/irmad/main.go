// Executable for the irmaserver.
package main

import (
	"encoding/json"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/core"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger = logrus.StandardLogger()
var conf *irmaserver.Configuration

func main() {
	var cmd = &cobra.Command{
		Use:   "irmaserver",
		Short: "IRMA server for verifying and issuing attributes",
		Run: func(command *cobra.Command, args []string) {
			if err := configure(); err != nil {
				die(errors.WrapPrefix(err, "Failed to configure server", 0))
			}
			if err := irmaserver.Start(conf); err != nil {
				die(errors.WrapPrefix(err, "Failed to start server", 0))
			}
		},
	}

	logger.Level = logrus.InfoLevel
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	if err := setFlags(cmd); err != nil {
		die(errors.WrapPrefix(err, "Failed to attach flags", 0))
	}

	if err := cmd.Execute(); err != nil {
		die(errors.WrapPrefix(err, "Failed to execute command", 0))
	}
}

func die(err *errors.Error) {
	logger.Error(err.Error())
	logger.Trace(string(err.Stack()))
	os.Exit(1)
}

func setFlags(cmd *cobra.Command) error {
	flags := cmd.Flags()
	flags.SortFlags = false

	cachepath, err := core.CachePath()
	if err != nil {
		return err
	}
	defaulturl, err := localIP()
	if err != nil {
		logger.Warn("Could not determine local IP address: ", err.Error())
	} else {
		defaulturl = "http://" + defaulturl + ":port"
	}

	flags.StringP("config", "c", "", "Path to configuration file")
	flags.StringP("irmaconf", "i", "", "path to irma_configuration")
	flags.StringP("privatekeys", "k", "", "path to IRMA private keys")
	flags.String("cachepath", cachepath, "Directory for writing cache files to")
	flags.StringP("jwtissuer", "j", "irmaserver", "JWT issuer")
	flags.StringP("jwtprivatekey", "w", "", "JWT private key or path to it")
	flags.StringP("url", "u", defaulturl, "External URL to server to which the IRMA client connects")
	flags.StringP("listenaddr", "l", "0.0.0.0", "Address at which to listen")
	flags.IntP("port", "p", 8088, "Port at which to listen")
	flags.Bool("noauth", false, "Whether or not to authenticate requestors")
	flags.String("requestors", "", "Requestor configuration (in JSON)")

	flags.StringSlice("disclose", []string{"*"}, "Comma-separated list of attributes that all requestors may verify")
	flags.StringSlice("sign", []string{"*"}, "Comma-separated list of attributes that all requestors may request in signatures")
	flags.StringSlice("issue", nil, "Comma-separated list of attributes that all requestors may issue")

	flags.CountP("verbose", "v", "verbose (repeatable)")
	flags.BoolP("quiet", "q", false, "quiet")

	// Environment variables
	viper.SetEnvPrefix("IRMASERVER")
	viper.AutomaticEnv()

	return viper.BindPFlags(flags)
}

func configure() error {
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

	// Set log level
	verbosity := viper.GetInt("verbose")
	if verbosity == 1 {
		logger.Level = logrus.DebugLevel
	}
	if verbosity >= 2 {
		logger.Level = logrus.TraceLevel
	}
	if viper.GetBool("quiet") {
		logger.Out = ioutil.Discard
	}

	logger.Debug("Configuring")
	logger.Debug("Log level: ", logger.Level.String())
	if err != nil {
		if _, notfound := err.(viper.ConfigFileNotFoundError); notfound {
			logger.Info("No configuration file found")
		} else {
			die(errors.WrapPrefix(err, "Failed to unmarshal configuration file at "+viper.ConfigFileUsed(), 0))
		}
	} else {
		logger.Info("Config file: ", viper.ConfigFileUsed())
	}

	// Read configuration from flags and/or environmental variables
	conf = &irmaserver.Configuration{
		Configuration: &server.Configuration{
			IrmaConfigurationPath: viper.GetString("irmaconf"),
			IssuerPrivateKeysPath: viper.GetString("privatekeys"),
			CachePath:             viper.GetString("cachepath"),
			URL:                   viper.GetString("url"),
			Logger:                logger,
		},
		ListenAddress: viper.GetString("listenaddr"),
		Port:          viper.GetInt("port"),
		DisableRequestorAuthentication: viper.GetBool("noauth"),
		Requestors:                     make(map[string]irmaserver.Requestor),
		GlobalPermissions:              irmaserver.Permissions{},
		JwtIssuer:                      viper.GetString("jwtissuer"),
		JwtPrivateKey:                  viper.GetString("jwtprivatekey"),
		Verbose:                        viper.GetInt("verbose"),
		Quiet:                          viper.GetBool("quiet"),
	}
	// replace "port" in url with actual port
	replace := "$1:" + strconv.Itoa(conf.Port)
	conf.URL = string(regexp.MustCompile("(https?://[^/]*):port").ReplaceAll([]byte(conf.URL), []byte(replace)))

	// Handle global permissions
	if len(viper.GetStringMap("permissions")) > 0 { // First read config file
		if err := viper.UnmarshalKey("permissions", &conf.GlobalPermissions); err != nil {
			return errors.WrapPrefix(err, "Failed to unmarshal permissions from config file", 0)
		}
	}
	conf.GlobalPermissions.Disclosing = handlePermission(conf.GlobalPermissions.Disclosing, "disclose")
	conf.GlobalPermissions.Signing = handlePermission(conf.GlobalPermissions.Signing, "sign")
	conf.GlobalPermissions.Issuing = handlePermission(conf.GlobalPermissions.Issuing, "issue")

	// Handle requestors
	if len(viper.GetStringMap("requestors")) > 0 { // First read config file
		if err := viper.UnmarshalKey("requestors", &conf.Requestors); err != nil {
			return errors.WrapPrefix(err, "Failed to unmarshal requestors from config file", 0)
		}
	}
	requestors := viper.GetString("requestors") // Read flag or env var
	if len(requestors) > 0 {
		if err := json.Unmarshal([]byte(requestors), &conf.Requestors); err != nil {
			return errors.WrapPrefix(err, "Failed to unmarshal requestors from json", 0)
		}
	}

	bts, _ := json.MarshalIndent(conf, "", "   ")
	logger.Debug(string(bts), "\n")
	logger.Debug("Done configuring")

	return nil
}

func handlePermission(conf []string, typ string) []string {
	perms := viper.GetStringSlice(typ)
	if len(perms) == 0 {
		return conf
	}
	if perms[0] == "" {
		perms = perms[1:]
	}
	if perms[len(perms)-1] == "" {
		perms = perms[:len(perms)-1]
	}
	return perms
}

func localIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("No IP found")
}
