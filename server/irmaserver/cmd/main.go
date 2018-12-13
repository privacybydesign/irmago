package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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

	if err := setFlags(cmd); err != nil {
		die(errors.WrapPrefix(err, "Failed to attach flags", 0))
	}

	if err := cmd.Execute(); err != nil {
		die(errors.WrapPrefix(err, "Failed to execute command", 0))
	}
}

func die(err *errors.Error) {
	fmt.Println(err.Error())
	fmt.Println()
	fmt.Println(string(err.Stack()))
	os.Exit(1)
}

func setFlags(cmd *cobra.Command) error {
	flags := cmd.Flags()
	flags.SortFlags = false

	flags.StringP("irmaconf", "i", "./irma_configuration", "path to irma_configuration")
	flags.StringP("privatekeys", "k", "", "path to IRMA private keys")
	flags.StringP("jwtissuer", "j", "irmaserver", "JWT issuer")
	flags.StringP("jwtprivatekey", "w", "", "JWT private key or path to it")
	flags.IntP("port", "p", 8088, "Port at which to listen")
	flags.Bool("noauth", false, "Whether or not to authenticate requestors")
	flags.String("requestors", "", "Requestor configuration (in JSON)")

	flags.StringSlice("disclosing", nil, "Comma-separated list of attributes that all requestors may verify")
	flags.StringSlice("signing", nil, "Comma-separated list of attributes that all requestors may request in signatures")
	flags.StringSlice("issuing", nil, "Comma-separated list of attributes that all requestors may issue")
	flags.Lookup("disclosing").NoOptDefVal = "*"
	flags.Lookup("signing").NoOptDefVal = "*"
	flags.Lookup("issuing").NoOptDefVal = "*"

	return viper.BindPFlags(flags)
}

func configure() error {
	fmt.Println("Configuring")

	// Environment variables
	viper.SetEnvPrefix("IRMASERVER")
	viper.AutomaticEnv()

	// Configuration file
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AddConfigPath("/etc/irmaserver/")
	viper.AddConfigPath("$HOME/.irmaserver")
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf("No configuration file found")
	} else {
		fmt.Println("Config file: ", viper.ConfigFileUsed())
	}

	// Read configuration from flags and/or environmental variables
	conf = &irmaserver.Configuration{
		Configuration: &server.Configuration{
			IrmaConfigurationPath: viper.GetString("irmaconf"),
			IssuerPrivateKeysPath: viper.GetString("privatekeys"),
			Logger:                logrus.StandardLogger(),
		},
		Port: viper.GetInt("port"),
		DisableRequestorAuthentication: viper.GetBool("noauth"),
		Requestors:                     make(map[string]irmaserver.Requestor),
		GlobalPermissions:              irmaserver.Permissions{},
		JwtIssuer:                      viper.GetString("jwtissuer"),
		JwtPrivateKey:                  viper.GetString("jwtprivatekey"),
	}

	// Handle global permissions
	if len(viper.GetStringMap("permissions")) > 0 { // First read config file
		if err := viper.UnmarshalKey("permissions", &conf.GlobalPermissions); err != nil {
			return errors.WrapPrefix(err, "Failed to unmarshal permissions", 0)
		}
	}
	handlePermission(&conf.GlobalPermissions.Disclosing, "disclosing") // Read flag or env var
	handlePermission(&conf.GlobalPermissions.Signing, "signing")
	handlePermission(&conf.GlobalPermissions.Issuing, "issuing")

	// Handle requestors
	if len(viper.GetStringMap("requestors")) > 0 { // First read config file
		if err := viper.UnmarshalKey("requestors", &conf.Requestors); err != nil {
			return errors.WrapPrefix(err, "Failed to unmarshal requestors", 0)
		}
	}
	requestors := viper.GetString("requestors") // Read flag or env var
	if len(requestors) > 0 {
		if err := json.Unmarshal([]byte(requestors), &conf.Requestors); err != nil {
			return errors.WrapPrefix(err, "Failed to parse requestors", 0)
		}
	}

	bts, _ := json.MarshalIndent(conf, "", "   ")
	fmt.Println(string(bts))
	fmt.Println("Done configuring")

	return nil
}

func handlePermission(conf *[]string, typ string) {
	if viper.GetString(typ) == "*" {
		*conf = []string{"*"}
	}
	perms := viper.GetStringSlice(typ)
	if len(perms) > 0 {
		*conf = perms
	}
}
