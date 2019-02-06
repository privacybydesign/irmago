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
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const pollInterval = 1000 * time.Millisecond

var (
	httpServer *http.Server
	irmaServer *irmaserver.Server
	logger     *logrus.Logger
)

// sessionCmd represents the session command
var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Perform an IRMA disclosure, issuance or signature session",
	Example: `irma session --disclose irma-demo.MijnOverheid.root.BSN
irma session --sign irma-demo.MijnOverheid.root.BSN --message message
irma session --issue irma-demo.MijnOverheid.ageLower=yes,yes,yes,no --disclose irma-demo.MijnOverheid.root.BSN
irma session --request '{"type":"disclosing","content":[{"label":"BSN","attributes":["irma-demo.MijnOverheid.root.BSN"]}]}'
irma session --server http://localhost:48680 --authmethod token --key mytoken --disclose irma-demo.MijnOverheid.root.BSN`,
	Run: func(cmd *cobra.Command, args []string) {
		request, irmaconfig, err := configure(cmd)
		if err != nil {
			die("", err)
		}

		var result *server.SessionResult
		serverurl, _ := cmd.Flags().GetString("server")
		noqr, _ := cmd.Flags().GetBool("noqr")
		flags := cmd.Flags()
		if serverurl == "" {
			port, _ := flags.GetInt("port")
			privatekeysPath, _ := flags.GetString("privatekeys")
			result, err = libraryRequest(request, irmaconfig, port, privatekeysPath, noqr)
		} else {
			authmethod, _ := flags.GetString("authmethod")
			key, _ := flags.GetString("key")
			name, _ := flags.GetString("name")
			result, err = serverRequest(request, serverurl, authmethod, key, name, noqr)
		}
		if err != nil {
			die("Session failed", err)
		}

		printSessionResult(result)

		// Done!
		if httpServer != nil {
			_ = httpServer.Close()
		}
	},
}

func libraryRequest(
	request irma.RequestorRequest,
	irmaconfig *irma.Configuration,
	port int,
	privatekeysPath string,
	noqr bool,
) (*server.SessionResult, error) {
	if err := configureServer(port, privatekeysPath, irmaconfig); err != nil {
		return nil, err
	}
	startServer(port)

	// Start the session
	resultchan := make(chan *server.SessionResult)
	qr, _, err := irmaServer.StartSession(request, func(r *server.SessionResult) {
		resultchan <- r
	})
	if err != nil {
		return nil, errors.WrapPrefix(err, "IRMA session failed", 0)
	}

	// Print QR code
	if err := printQr(qr, noqr); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to print QR", 0)
	}

	// Wait for session to finish and then return session result
	return <-resultchan, nil
}

func serverRequest(
	request irma.RequestorRequest,
	serverurl, authmethod, key, name string,
	noqr bool,
) (*server.SessionResult, error) {
	logger.Debug("Server URL: ", serverurl)

	// Start session at server
	qr, transport, err := postRequest(serverurl, request, name, authmethod, key)
	if err != nil {
		return nil, err
	}

	// Print session QR
	logger.Debug("QR: ", prettyprint(qr))
	if err := printQr(qr, noqr); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to print QR", 0)
	}

	statuschan := make(chan server.Status)

	// Wait untill client connects
	go poll(server.StatusInitialized, transport, statuschan)
	status := <-statuschan
	if status != server.StatusConnected {
		return nil, errors.Errorf("Unexpected status: %s", status)
	}

	// Wait untill client finishes
	go poll(server.StatusConnected, transport, statuschan)
	status = <-statuschan
	if status != server.StatusDone {
		return nil, errors.Errorf("Unexpected status: %s", status)
	}

	// Retrieve session result
	result := &server.SessionResult{}
	if err := transport.Get("result", result); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to get session result", 0)
	}
	return result, nil
}

func postRequest(serverurl string, request irma.RequestorRequest, name, authmethod, key string) (*irma.Qr, *irma.HTTPTransport, error) {
	var (
		err       error
		sk        interface{}
		qr        = &irma.Qr{}
		transport = irma.NewHTTPTransport(serverurl)
	)

	switch authmethod {
	case "none":
		err = transport.Post("session", qr, request)
	case "token":
		transport.SetHeader("Authentication", key)
		err = transport.Post("session", qr, request)
	case "hmac", "rsa":
		var (
			jwtalg jwt.SigningMethod
			jwtstr string
			bts    []byte
		)
		// If the key refers to an existing file, use contents of the file as key
		if bts, err = fs.ReadKey("", key); err != nil {
			bts = []byte(key)
		}
		if authmethod == "hmac" {
			jwtalg = jwt.SigningMethodHS256
			if sk, err = fs.Base64Decode(bts); err != nil {
				return nil, nil, err
			}
		}
		if authmethod == "rsa" {
			jwtalg = jwt.SigningMethodRS256
			if sk, err = jwt.ParseRSAPrivateKeyFromPEM(bts); err != nil {
				return nil, nil, err
			}
		}

		if jwtstr, err = irma.SignRequestorRequest(request, jwtalg, sk, name); err != nil {
			return nil, nil, err
		}
		logger.Debug("Session request JWT: ", jwtstr)
		err = transport.Post("session", qr, jwtstr)
	default:
		return nil, nil, errors.New("Invalid authentication method (must be none, token, hmac or rsa)")
	}

	token := qr.URL[strings.LastIndex(qr.URL, "/")+1:]
	transport.Server += fmt.Sprintf("session/%s/", token)
	return qr, transport, err
}

// Configuration functions

func configureServer(port int, privatekeysPath string, irmaconfig *irma.Configuration) error {
	ip, err := server.LocalIP()
	if err != nil {
		return err
	}
	config := &server.Configuration{
		IrmaConfiguration: irmaconfig,
		Logger:            logger,
		URL:               "http://" + ip + ":" + strconv.Itoa(port),
	}
	if privatekeysPath != "" {
		config.IssuerPrivateKeysPath = privatekeysPath
	}

	irmaServer, err = irmaserver.New(config)
	return err
}

func configure(cmd *cobra.Command) (irma.RequestorRequest, *irma.Configuration, error) {
	irmaconfigPath, err := cmd.Flags().GetString("irmaconf")
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

	verbosity, _ := cmd.Flags().GetCount("verbose")
	logger = logrus.New()
	logger.Level = server.Verbosity(verbosity)
	logger.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	irma.Logger = logger
	request, err := constructSessionRequest(cmd, irmaconfig)
	if err != nil {
		return nil, nil, err
	}

	logger.Debugf("Session request: %s", prettyprint(request))

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
	mux.HandleFunc("/", irmaServer.HttpHandlerFunc())
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
	RootCmd.AddCommand(sessionCmd)

	flags := sessionCmd.Flags()
	flags.SortFlags = false
	flags.StringP("irmaconf", "i", server.DefaultSchemesPath(), "path to irma_configuration")
	flags.StringP("privatekeys", "k", "", "path to private keys")
	flags.IntP("port", "p", 48680, "port to listen at")
	flags.Bool("noqr", false, "Print JSON instead of draw QR")
	flags.CountP("verbose", "v", "verbose (repeatable)")

	flags.StringP("server", "s", "", "Server to post request to (leave blank to use builtin library)")
	flags.StringP("authmethod", "a", "none", "Authentication method to server (none, token, rsa, hmac)")
	flags.String("key", "", "Key to sign request with")
	flags.String("name", "", "Requestor name")

	flags.StringP("request", "r", "", "JSON session request")
	flags.StringArray("disclose", nil, "Add an attribute disjunction (comma-separated)")
	flags.StringArray("issue", nil, "Add a credential to issue")
	flags.StringArray("sign", nil, "Add an attribute disjunction to signature session")
	flags.String("message", "", "Message to sign in signature session")
}
