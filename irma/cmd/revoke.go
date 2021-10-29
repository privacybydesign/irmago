package cmd

import (
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/spf13/cobra"
)

var revokeCmd = &cobra.Command{
	Use:   "revoke <credentialtype> <key> <url>",
	Short: "Revoke a previously issued credential identified by a given key",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		flags := cmd.Flags()
		schemespath, _ := flags.GetString("schemes-path")
		authmethod, _ := flags.GetString("auth-method")
		key, _ := flags.GetString("key")
		name, _ := flags.GetString("name")
		verbosity, _ := cmd.Flags().GetCount("verbose")
		url := args[2]

		request := &irma.RevocationRequest{
			LDContext:      irma.LDContextRevocationRequest,
			CredentialType: irma.NewCredentialTypeIdentifier(args[0]),
			Key:            args[1],
		}

		postRevocation(request, url, schemespath, authmethod, key, name, verbosity)
	},
}

func postRevocation(request *irma.RevocationRequest, url, schemespath, authmethod, key, name string, verbosity int) {
	logger.Level = server.Verbosity(verbosity)
	irma.SetLogger(logger)

	conf, err := irma.NewConfiguration(schemespath, irma.ConfigurationOptions{ReadOnly: true})
	if err != nil {
		die("failed to open irma_configuration", err)
	}
	if err = conf.ParseFolder(); err != nil {
		die("failed to parse irma_configuration", err)
	}

	credtype, known := conf.CredentialTypes[request.CredentialType]
	if !known {
		die("unknown credential type", nil)
	}
	if !credtype.RevocationSupported() {
		die("credential type does not support revocation", nil)
	}

	transport := irma.NewHTTPTransport(url, false)

	switch authmethod {
	case "none":
		err = transport.Post("revocation", nil, request)
	case "token":
		transport.SetHeader("Authorization", key)
		err = transport.Post("revocation", nil, request)
	case "hmac", "rsa":
		// Prevent that err is redeclared in the inner scope
		sk, jwtalg, errJwtKey := configureJWTKey(authmethod, key)
		if errJwtKey != nil {
			die("failed to configure JWT key", errJwtKey)
		}
		j := irma.RevocationJwt{
			ServerJwt: irma.ServerJwt{
				ServerName: name,
				IssuedAt:   irma.Timestamp(time.Now()),
			},
			Request: request,
		}
		// Prevent that err is redeclared in the inner scope
		jwtstr, errJwtSign := j.Sign(jwtalg, sk)
		if errJwtSign != nil {
			die("failed to sign JWT", errJwtSign)
		}
		err = transport.Post("revocation", nil, jwtstr)
	default:
		die("Invalid authentication method (must be none, token, hmac or rsa)", nil)
	}

	if err != nil {
		die("failed to post revocation request", err)
	}
}

func init() {
	flags := revokeCmd.Flags()
	flags.StringP("schemes-path", "s", irma.DefaultSchemesPath(), "path to irma_configuration")
	flags.StringP("auth-method", "a", "none", "Authentication method to server (none, token, rsa, hmac)")
	flags.String("key", "", "Key to sign request with")
	flags.String("name", "", "Requestor name")
	flags.CountP("verbose", "v", "verbose (repeatable)")

	issuerCmd.AddCommand(revokeCmd)
}
