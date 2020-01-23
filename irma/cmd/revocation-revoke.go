package cmd

import (
	"time"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/spf13/cobra"
)

var revokeCmd = &cobra.Command{
	Use:   "revoke CREDENTIALTYPE KEY URL",
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
	irma.Logger = logger

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

	transport := irma.NewHTTPTransport(url)

	switch authmethod {
	case "none":
		err = transport.Post("revocation", nil, request)
	case "token":
		transport.SetHeader("Authorization", key)
		err = transport.Post("revocation", nil, request)
	case "hmac", "rsa":
		sk, jwtalg, err := configureJWTKey(authmethod, key)
		j := irma.RevocationJwt{
			ServerJwt: irma.ServerJwt{
				ServerName: name,
				IssuedAt:   irma.Timestamp(time.Now()),
			},
			Request: request,
		}
		jwtstr, err := j.Sign(jwtalg, sk)
		if err != nil {
			die("failed to sign JWT", err)
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

	revocationCmd.AddCommand(revokeCmd)
}
