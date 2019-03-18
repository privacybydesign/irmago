package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/mdp/qrterminal"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/privacybydesign/irmago/server"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// requestCmd represents the request command
var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Generate an IRMA session request",
	Run: func(cmd *cobra.Command, args []string) {
		request, _, err := configureRequest(cmd)
		if err != nil {
			die(errors.Wrap(err, 0))
		}

		flags := cmd.Flags()
		authmethod, _ := flags.GetString("authmethod")
		var output string
		if authmethod == "none" || authmethod == "token" {
			output = prettyprint(request)
		} else {
			key, _ := flags.GetString("key")
			name, _ := flags.GetString("name")
			if output, err = signRequest(request, name, authmethod, key); err != nil {
				die(errors.WrapPrefix(err, "Failed to sign request", 0))
			}
		}

		fmt.Println(output)
	},
}

func signRequest(request irma.RequestorRequest, name, authmethod, key string) (string, error) {
	var (
		err    error
		sk     interface{}
		jwtalg jwt.SigningMethod
		bts    []byte
	)
	// If the key refers to an existing file, use contents of the file as key
	if bts, err = fs.ReadKey("", key); err != nil {
		bts = []byte(key)
	}
	switch authmethod {
	case "hmac":
		jwtalg = jwt.SigningMethodHS256
		if sk, err = fs.Base64Decode(bts); err != nil {
			return "", err
		}
	case "rsa":
		jwtalg = jwt.SigningMethodRS256
		if sk, err = jwt.ParseRSAPrivateKeyFromPEM(bts); err != nil {
			return "", err
		}
	default:
		return "", errors.Errorf("Unsupported signing algorithm: '%s'", authmethod)
	}

	return irma.SignRequestorRequest(request, jwtalg, sk, name)
}

func configureRequest(cmd *cobra.Command) (irma.RequestorRequest, *irma.Configuration, error) {
	irmaconfigPath, err := cmd.Flags().GetString("schemes-path")
	if err != nil {
		return nil, nil, err
	}
	irmaconfig, err := irma.NewConfiguration(irmaconfigPath)
	if err != nil {
		return nil, nil, err
	}
	if err = irmaconfig.ParseFolder(); err != nil {
		return nil, nil, err
	}
	if len(irmaconfig.SchemeManagers) == 0 {
		if err = irmaconfig.DownloadDefaultSchemes(); err != nil {
			return nil, nil, err
		}
	}

	request, err := constructSessionRequest(cmd, irmaconfig)
	if err != nil {
		return nil, nil, err
	}

	return request, irmaconfig, nil
}

// Helper functions

// poll recursively polls the session status until a status different from initialStatus is received.
func poll(initialStatus server.Status, transport *irma.HTTPTransport, statuschan chan server.Status) {
	// First we wait
	<-time.NewTimer(pollInterval).C

	// Get session status
	var status string
	if err := transport.Get("status", &status); err != nil {
		_ = server.LogFatal(err)
	}
	status = strings.Trim(status, `"`)

	// If the status has not yet changed, schedule another poll
	if server.Status(status) == initialStatus {
		go poll(initialStatus, transport, statuschan)
	} else {
		logger.Trace("Stopped polling, new status ", status)
		statuschan <- server.Status(status)
	}
}

func constructSessionRequest(cmd *cobra.Command, conf *irma.Configuration) (irma.RequestorRequest, error) {
	disclose, _ := cmd.Flags().GetStringArray("disclose")
	issue, _ := cmd.Flags().GetStringArray("issue")
	sign, _ := cmd.Flags().GetStringArray("sign")
	message, _ := cmd.Flags().GetString("message")
	jsonrequest, _ := cmd.Flags().GetString("request")

	if len(disclose) == 0 && len(issue) == 0 && len(sign) == 0 && message == "" {
		if jsonrequest == "" {
			return nil, errors.New("Provide either a complete session request using --request or construct one using the other flags")
		}
		request, err := server.ParseSessionRequest(jsonrequest)
		if err != nil {
			return nil, err
		}
		return request, nil
	}

	if jsonrequest != "" {
		return nil, errors.New("Provide either a complete session request using --request or construct one using the other flags")
	}

	if len(sign) != 0 {
		if len(disclose) != 0 {
			return nil, errors.New("cannot combine disclosure and signature sessions, use either --disclose or --sign")
		}
		if len(issue) != 0 {
			return nil, errors.New("cannot combine issuance and signature sessions, use either --issue or --sign")
		}
		if message == "" {
			return nil, errors.New("signature sessions require a message to be signed using --message")
		}
	}

	var request irma.RequestorRequest
	if len(disclose) != 0 {
		disjunctions, err := parseDisjunctions(disclose, conf)
		if err != nil {
			return nil, err
		}
		request = &irma.ServiceProviderRequest{
			Request: &irma.DisclosureRequest{
				BaseRequest: irma.BaseRequest{Type: irma.ActionDisclosing},
				Content:     disjunctions,
			},
		}

	}
	if len(sign) != 0 {
		disjunctions, err := parseDisjunctions(sign, conf)
		if err != nil {
			return nil, err
		}
		request = &irma.SignatureRequestorRequest{
			Request: &irma.SignatureRequest{
				DisclosureRequest: irma.DisclosureRequest{
					BaseRequest: irma.BaseRequest{Type: irma.ActionSigning},
					Content:     disjunctions,
				},
				Message: message,
			},
		}
	}
	if len(issue) != 0 {
		creds, err := parseCredentials(issue, conf)
		if err != nil {
			return nil, err
		}
		disjunctions, err := parseDisjunctions(disclose, conf)
		if err != nil {
			return nil, err
		}
		request = &irma.IdentityProviderRequest{
			Request: &irma.IssuanceRequest{
				BaseRequest: irma.BaseRequest{
					Type: irma.ActionIssuing,
				},
				Credentials: creds,
				Disclose:    disjunctions,
			},
		}
	}

	return request, nil
}

func parseCredentials(credentialsStr []string, conf *irma.Configuration) ([]*irma.CredentialRequest, error) {
	list := make([]*irma.CredentialRequest, 0, len(credentialsStr))

	for _, credStr := range credentialsStr {
		parts := strings.Split(credStr, "=")
		if len(parts) != 2 {
			return nil, errors.New("--issue argument must contain exactly 1 = sign")
		}
		credIdStr, attrsStr := parts[0], parts[1]
		credtype := conf.CredentialTypes[irma.NewCredentialTypeIdentifier(credIdStr)]
		if credtype == nil {
			return nil, errors.New("unknown credential type: " + credIdStr)
		}

		attrsSlice := strings.Split(attrsStr, ",")
		if len(attrsSlice) != len(credtype.AttributeTypes) {
			return nil, errors.Errorf("%d attributes required but %d provided for %s", len(credtype.AttributeTypes), len(attrsSlice), credIdStr)
		}

		attrs := make(map[string]string, len(attrsSlice))
		for i, typ := range credtype.AttributeTypes {
			attrs[typ.ID] = attrsSlice[i]
		}
		list = append(list, &irma.CredentialRequest{
			CredentialTypeID: irma.NewCredentialTypeIdentifier(credIdStr),
			Attributes:       attrs,
		})
	}

	return list, nil
}

func parseDisjunctions(disjunctionsStr []string, conf *irma.Configuration) (irma.AttributeDisjunctionList, error) {
	list := make(irma.AttributeDisjunctionList, 0, len(disjunctionsStr))
	for _, disjunctionStr := range disjunctionsStr {
		disjunction := &irma.AttributeDisjunction{}
		attrids := strings.Split(disjunctionStr, ",")
		for _, attridStr := range attrids {
			attrid := irma.NewAttributeTypeIdentifier(attridStr)
			if conf.AttributeTypes[attrid] == nil {
				return nil, errors.New("unknown attribute: " + attridStr)
			}
			disjunction.Attributes = append(disjunction.Attributes, attrid)
		}
		disjunction.Label = disjunction.Attributes[0].Name()
		list = append(list, disjunction)
	}
	return list, nil
}

func startServer(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", irmaServer.HandlerFunc())
	httpServer = &http.Server{Addr: ":" + strconv.Itoa(port), Handler: mux}
	go func() {
		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			die(errors.WrapPrefix(err, "Failed to start server", 0))
		}
	}()
}

func printQr(qr *irma.Qr, noqr bool) error {
	qrBts, err := json.Marshal(qr)
	if err != nil {
		return err
	}
	fmt.Printf("\nQR contents: %s\n", qrBts)
	if !noqr {
		qrterminal.GenerateWithConfig(string(qrBts), qrterminal.Config{
			Level:     qrterminal.L,
			Writer:    os.Stdout,
			BlackChar: qrterminal.BLACK,
			WhiteChar: qrterminal.WHITE,
		})
	}
	return nil
}

func printSessionResult(result *server.SessionResult) {
	fmt.Println("Session result:")
	fmt.Println(prettyprint(result))
}

func init() {
	RootCmd.AddCommand(requestCmd)

	flags := requestCmd.Flags()
	flags.SortFlags = false

	addRequestFlags(flags)
}

func addRequestFlags(flags *pflag.FlagSet) {
	flags.StringP("schemes-path", "s", server.DefaultSchemesPath(), "path to irma_configuration")
	flags.StringP("authmethod", "a", "none", "Authentication method to server (none, token, rsa, hmac)")
	flags.String("key", "", "Key to sign request with")
	flags.String("name", "", "Requestor name")
	flags.StringArray("disclose", nil, "Add an attribute disjunction (comma-separated)")
	flags.StringArray("issue", nil, "Add a credential to issue")
	flags.StringArray("sign", nil, "Add an attribute disjunction to signature session")
	flags.String("message", "", "Message to sign in signature session")
}
