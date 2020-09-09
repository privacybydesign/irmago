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
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
	"github.com/sietseringers/cobra"
	sseclient "github.com/sietseringers/go-sse"
	"github.com/sietseringers/pflag"
)

// requestCmd represents the request command
var requestCmd = &cobra.Command{
	Use:   "request",
	Short: "Generate an IRMA session request",
	Run: func(cmd *cobra.Command, args []string) {
		request, _, err := configureRequest(cmd)
		if err != nil {
			die("", err)
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
				die("Failed to sign request", err)
			}
		}

		fmt.Println(output)
	},
}

func configureJWTKey(authmethod, key string) (interface{}, jwt.SigningMethod, error) {
	var (
		err    error
		sk     interface{}
		jwtalg jwt.SigningMethod
		bts    []byte
	)
	// If the key refers to an existing file, use contents of the file as key
	if bts, err = common.ReadKey("", key); err != nil {
		bts = []byte(key)
	}
	switch authmethod {
	case "hmac":
		jwtalg = jwt.SigningMethodHS256
		if sk, err = common.Base64Decode(bts); err != nil {
			return nil, nil, err
		}
	case "rsa":
		jwtalg = jwt.SigningMethodRS256
		if sk, err = jwt.ParseRSAPrivateKeyFromPEM(bts); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, errors.Errorf("Unsupported signing algorithm: '%s'", authmethod)
	}

	return sk, jwtalg, nil
}

func signRequest(request irma.RequestorRequest, name, authmethod, key string) (string, error) {
	sk, jwtalg, err := configureJWTKey(authmethod, key)
	if err != nil {
		return "", err
	}
	return irma.SignRequestorRequest(request, jwtalg, sk, name)
}

func configureRequest(cmd *cobra.Command) (irma.RequestorRequest, *irma.Configuration, error) {
	irmaconfigPath, err := cmd.Flags().GetString("schemes-path")
	if err != nil {
		return nil, nil, err
	}
	irmaconfig, err := irma.NewConfiguration(irmaconfigPath, irma.ConfigurationOptions{})
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

func wait(initialStatus server.Status, transport *irma.HTTPTransport, statuschan chan server.Status) {
	events := make(chan *sseclient.Event)

	go func() {
		for {
			if e := <-events; e != nil && e.Type != "open" {
				status := server.Status(strings.Trim(string(e.Data), `"`))
				statuschan <- status
				if status.Finished() {
					return
				}
			}
		}
	}()

	if err := sseclient.Notify(nil, transport.Server+"statusevents", true, events); err != nil {
		fmt.Println("SSE failed, fallback to polling", err)
		close(events)
		poll(initialStatus, transport, statuschan)
		return
	}
}

// poll recursively polls the session status until a final status is received.
func poll(initialStatus server.Status, transport *irma.HTTPTransport, statuschan chan server.Status) {
	// First we wait
	<-time.NewTimer(pollInterval).C

	// Get session status
	var s string
	if err := transport.Get("status", &s); err != nil {
		_ = server.LogFatal(err)
	}
	status := server.Status(strings.Trim(s, `"`))

	// report if status changed
	if status != initialStatus {
		statuschan <- status
	}

	if status.Finished() {
		return
	}
	go poll(status, transport, statuschan)
}

func constructSessionRequest(cmd *cobra.Command, conf *irma.Configuration) (irma.RequestorRequest, error) {
	disclose, _ := cmd.Flags().GetStringArray("disclose")
	issue, _ := cmd.Flags().GetStringArray("issue")
	sign, _ := cmd.Flags().GetStringArray("sign")
	message, _ := cmd.Flags().GetString("message")
	jsonrequest, _ := cmd.Flags().GetString("request")
	revocationKey, _ := cmd.Flags().GetString("revocation-key")

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
	if len(disclose) != 0 && len(issue) == 0 {
		disclose, err := parseAttrs(disclose, conf)
		if err != nil {
			return nil, err
		}
		request = &irma.ServiceProviderRequest{
			Request: irma.NewDisclosureRequest(),
		}
		request.SessionRequest().(*irma.DisclosureRequest).Disclose = disclose
	}
	if len(sign) != 0 {
		disclose, err := parseAttrs(sign, conf)
		if err != nil {
			return nil, err
		}
		request = &irma.SignatureRequestorRequest{
			Request: irma.NewSignatureRequest(message),
		}
		request.SessionRequest().(*irma.SignatureRequest).Disclose = disclose
	}
	if len(issue) != 0 {
		creds, err := parseCredentials(issue, revocationKey, conf)
		if err != nil {
			return nil, err
		}
		disclose, err := parseAttrs(disclose, conf)
		if err != nil {
			return nil, err
		}
		request = &irma.IdentityProviderRequest{
			Request: irma.NewIssuanceRequest(creds),
		}
		request.SessionRequest().(*irma.IssuanceRequest).Disclose = disclose
	}

	return request, nil
}

func parseCredentials(
	credentialsStr []string, revocationKey string, conf *irma.Configuration,
) ([]*irma.CredentialRequest, error) {
	list := make([]*irma.CredentialRequest, 0, len(credentialsStr))
	revocationUsed := false

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
		attrcount := len(credtype.AttributeTypes)
		if credtype.RevocationSupported() {
			attrcount -= 1
		}
		if len(attrsSlice) != attrcount {
			return nil, errors.Errorf("%d attributes required but %d provided for %s", attrcount, len(attrsSlice), credIdStr)
		}

		attrs := make(map[string]string, len(attrsSlice))
		i := 0
		for _, typ := range credtype.AttributeTypes {
			if typ.RevocationAttribute {
				continue
			}
			attrs[typ.ID] = attrsSlice[i]
			i++
		}
		req := &irma.CredentialRequest{
			CredentialTypeID: irma.NewCredentialTypeIdentifier(credIdStr),
			Attributes:       attrs,
		}
		if credtype.RevocationSupported() {
			if revocationKey == "" {
				return nil, errors.Errorf("revocationKey required for %s", credIdStr)
			}
			revocationUsed = true
			req.RevocationKey = revocationKey
		}
		list = append(list, req)
	}

	if !revocationUsed && revocationKey != "" {
		return nil, errors.New("revocation key specified but no credential uses revocation")
	}

	return list, nil
}

func parseAttrs(attrsStr []string, conf *irma.Configuration) (irma.AttributeConDisCon, error) {
	list := make(irma.AttributeConDisCon, 0, len(attrsStr))
	for _, disjunctionStr := range attrsStr {
		disjunction := irma.AttributeDisCon{}
		attrids := strings.Split(disjunctionStr, ",")
		for _, attridStr := range attrids {
			attrid := irma.NewAttributeTypeIdentifier(attridStr)
			if conf.AttributeTypes[attrid] == nil {
				return nil, errors.New("unknown attribute: " + attridStr)
			}
			disjunction = append(disjunction, irma.AttributeCon{irma.AttributeRequest{Type: attrid}})
		}
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
			die("Failed to start server", err)
		}
	}()
}

func printQr(qr *irma.Qr, noqr bool) error {
	qrBts, err := json.Marshal(qr)
	if err != nil {
		return err
	}
	if noqr {
		fmt.Println(string(qrBts))
	} else {
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

func authmethodAlias(f *pflag.FlagSet, name string) pflag.NormalizedName {
	switch name {
	case "authmethod":
		name = "auth-method"
		break
	}
	return pflag.NormalizedName(name)
}

func addRequestFlags(flags *pflag.FlagSet) {
	flags.StringP("schemes-path", "s", irma.DefaultSchemesPath(), "path to irma_configuration")
	flags.StringP("auth-method", "a", "none", "Authentication method to server (none, token, rsa, hmac)")
	flags.SetNormalizeFunc(authmethodAlias)
	flags.String("key", "", "Key to sign request with")
	flags.String("name", "", "Requestor name")
	flags.StringArray("disclose", nil, "Add an attribute disjunction (comma-separated)")
	flags.StringArray("issue", nil, "Add a credential to issue")
	flags.StringArray("sign", nil, "Add an attribute disjunction to signature session")
	flags.String("message", "", "Message to sign in signature session")
	flags.String("revocation-key", "", "Revocation key")
}
