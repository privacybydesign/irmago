package irmacli

import (
	"time"

	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/server"
	"github.com/privacybydesign/irmago/yivi/cli/internal/clihelpers"
	"github.com/spf13/cobra"
)

var revokeCmd = &cobra.Command{
	Use:   "revoke <credentialtype> <key> <url>",
	Short: "Revoke a previously issued credential identified by a given key",
	Args:  cobra.ExactArgs(3),
	Run: func(cmd *cobra.Command, args []string) {
		flags := cmd.Flags()
		schemesPath, _ := flags.GetString("schemes-path")
		schemesAssetsPath, _ := flags.GetString("schemes-assets-path")
		authMethod, _ := flags.GetString("auth-method")
		key, _ := flags.GetString("key")
		name, _ := flags.GetString("name")
		verbosity, _ := cmd.Flags().GetCount("verbose")
		url := args[2]

		request := &irma.RevocationRequest{
			LDContext:      irma.LDContextRevocationRequest,
			CredentialType: irma.NewCredentialTypeIdentifier(args[0]),
			Key:            args[1],
		}

		postRevocation(request, url, schemesPath, schemesAssetsPath, authMethod, key, name, verbosity)
	},
}

func postRevocation(request *irma.RevocationRequest, url, schemesPath, schemesAssetsPath, authMethod, key, name string, verbosity int) {
	Logger.Level = server.Verbosity(verbosity)
	irma.SetLogger(Logger)

	conf, err := irma.NewConfiguration(schemesPath, irma.ConfigurationOptions{ReadOnly: true, Assets: schemesAssetsPath})
	if err != nil {
		clihelpers.Die("failed to open irma_configuration", err, Logger)
	}
	if err = conf.ParseFolder(); err != nil {
		clihelpers.Die("failed to parse irma_configuration", err, Logger)
	}

	credtype, known := conf.CredentialTypes[request.CredentialType]
	if !known {
		clihelpers.Die("unknown credential type", nil, Logger)
	}
	if !credtype.RevocationSupported() {
		clihelpers.Die("credential type does not support revocation", nil, Logger)
	}

	transport := irma.NewHTTPTransport(url, false)

	switch authMethod {
	case "none":
		err = transport.Post("revocation", nil, request)
	case "token":
		transport.SetHeader("Authorization", key)
		err = transport.Post("revocation", nil, request)
	case "hmac", "rsa":
		// Prevent that err is redeclared in the inner scope
		sk, jwtalg, errJwtKey := configureJWTKey(authMethod, key)
		if errJwtKey != nil {
			clihelpers.Die("failed to configure JWT key", errJwtKey, Logger)
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
			clihelpers.Die("failed to sign JWT", errJwtSign, Logger)
		}
		err = transport.Post("revocation", nil, jwtstr)
	default:
		clihelpers.Die("Invalid authentication method (must be none, token, hmac or rsa)", nil, Logger)
	}

	if err != nil {
		clihelpers.Die("failed to post revocation request", err, Logger)
	}
}

func init() {
	flags := revokeCmd.Flags()
	flags.StringP("schemes-path", "s", irma.DefaultSchemesPath(), "path to irma_configuration")
	flags.String("schemes-assets-path", irma.DefaultSchemesAssetsPath(), "if specified, copy schemes from here into --schemes-path")
	flags.StringP("auth-method", "a", "none", "Authentication method to server (none, token, rsa, hmac)")
	flags.String("key", "", "Key to sign request with")
	flags.String("name", "", "Requestor name")
	flags.CountP("verbose", "v", "verbose (repeatable)")

	issuerCmd.AddCommand(revokeCmd)
}
