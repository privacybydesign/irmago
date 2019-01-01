package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/go-errors/errors"
	"github.com/mdp/qrterminal"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmarequestor"
	"github.com/spf13/cobra"
)

// sessionCmd represents the session command
var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Perform an IRMA disclosure, issuance or signature session",
	Example: `irma session --disclose irma-demo.MijnOverheid.root.BSN
irma session --sign irma-demo.MijnOverheid.root.BSN --message message
irma session --issue irma-demo.MijnOverheid.ageLower=yes,yes,yes,no --disclose irma-demo.MijnOverheid.root.BSN`,
	Run: func(cmd *cobra.Command, args []string) {
		request, irmaconfig, err := configure(cmd)
		if err != nil {
			die("", err)
		}

		var result *server.SessionResult
		serverurl, _ := cmd.Flags().GetString("server")
		noqr, _ := cmd.Flags().GetBool("noqr")
		if serverurl == "" {
			port, _ := cmd.Flags().GetInt("port")
			privatekeysPath, _ := cmd.Flags().GetString("privatekeys")
			result, err = libraryRequest(request, irmaconfig, port, privatekeysPath, noqr)
		} else {
			result, err = serverRequest(request, irmaconfig, serverurl, noqr)
		}
		if err != nil {
			die("Session failed", err)
		}

		printSessionResult(result)

		// Done!
		if irmaServer != nil {
			_ = irmaServer.Close()
		}
	},
}

func libraryRequest(request irma.SessionRequest, irmaconfig *irma.Configuration, port int, privatekeysPath string, noqr bool) (*server.SessionResult, error) {
	if err := configureServer(port, privatekeysPath, irmaconfig); err != nil {
		return nil, err
	}
	startServer(port)

	// Start the session
	resultchan := make(chan *server.SessionResult)
	qr, _, err := irmarequestor.StartSession(request, func(r *server.SessionResult) {
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
	request irma.SessionRequest,
	irmaconfig *irma.Configuration,
	serverurl string,
	noqr bool,
) (*server.SessionResult, error) {
	logger.Debug("Server URL: ", serverurl)
	qr := &irma.Qr{}

	// Start session at server
	transport := irma.NewHTTPTransport(serverurl)
	if err := transport.Post("session", qr, request); err != nil {
		return nil, err
	}

	// Print session QR
	logger.Debug("QR: ", prettyprint(qr))
	if err := printQr(qr, noqr); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to print QR", 0)
	}

	token := qr.URL[strings.LastIndex(qr.URL, "/")+1:]
	statuschan := make(chan server.Status)

	// Wait untill client connects
	go poll(token, server.StatusInitialized, transport, statuschan)
	status := <-statuschan
	if status != server.StatusConnected {
		return nil, errors.Errorf("Unexpected status: %s", status)
	}

	// Wait untill client finishes
	go poll(token, server.StatusConnected, transport, statuschan)
	status = <-statuschan
	if status != server.StatusDone {
		return nil, errors.Errorf("Unexpected status: %s", status)
	}

	// Retrieve session result
	result := &server.SessionResult{}
	if err := transport.Get(fmt.Sprintf("session/%s/result", token), result); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to get session result", 0)
	}
	return result, nil
}

const pollInterval = 1000 * time.Millisecond

func poll(t string, initialStatus server.Status, transport *irma.HTTPTransport, statuschan chan server.Status) {
	// First we wait
	<-time.NewTimer(pollInterval).C

	// Get session status
	var status string
	logger.Tracef("Polling %s %s", t, initialStatus)
	if err := transport.Get(fmt.Sprintf("session/%s/status", t), &status); err != nil {
		_ = server.LogFatal(err)
	}
	status = strings.Trim(status, `"`)
	logger.Trace("Status: ", status)

	// If the status has not yet changed, schedule another poll
	if server.Status(status) == initialStatus {
		go poll(t, initialStatus, transport, statuschan)
	} else {
		logger.Trace("Stopped polling, new status ", status)
		statuschan <- server.Status(status)
	}
}

func init() {
	RootCmd.AddCommand(sessionCmd)

	flags := sessionCmd.Flags()
	flags.SortFlags = false
	flags.StringP("irmaconf", "i", defaultIrmaconfPath(), "path to irma_configuration")
	flags.StringP("privatekeys", "k", "", "path to private keys")
	flags.IntP("port", "p", 48680, "port to listen at")
	flags.BoolP("noqr", "q", false, "Don't print as QR")
	flags.CountP("verbose", "v", "verbose (repeatable)")

	flags.StringP("server", "s", "", "Server to post request to (leave blank to use builtin library)")

	flags.StringArray("disclose", nil, "Add an attribute disjunction (comma-separated)")
	flags.StringArray("issue", nil, "Add a credential to issue")
	flags.StringArray("sign", nil, "Add an attribute disjunction to signature session")
	flags.String("message", "", "Message to sign in signature session")
}

var irmaServer *http.Server
var logger *logrus.Logger

func constructSessionRequest(cmd *cobra.Command, conf *irma.Configuration) (irma.SessionRequest, error) {
	disclose, _ := cmd.Flags().GetStringArray("disclose")
	issue, _ := cmd.Flags().GetStringArray("issue")
	sign, _ := cmd.Flags().GetStringArray("sign")
	message, _ := cmd.Flags().GetString("message")

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

	var request irma.SessionRequest
	if len(disclose) != 0 {
		disjunctions, err := parseDisjunctions(disclose, conf)
		if err != nil {
			return nil, err
		}
		request = &irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{
				Type: irma.ActionDisclosing,
			},
			Content: disjunctions,
		}
	}
	if len(sign) != 0 {
		disjunctions, err := parseDisjunctions(sign, conf)
		if err != nil {
			return nil, err
		}
		request = &irma.SignatureRequest{
			DisclosureRequest: irma.DisclosureRequest{
				BaseRequest: irma.BaseRequest{
					Type: irma.ActionSigning,
				},
				Content: disjunctions,
			},
			Message: message,
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
		request = &irma.IssuanceRequest{
			BaseRequest: irma.BaseRequest{
				Type: irma.ActionIssuing,
			},
			Credentials: creds,
			Disclose:    disjunctions,
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

	return irmarequestor.Initialize(config)
}

func configure(cmd *cobra.Command) (irma.SessionRequest, *irma.Configuration, error) {
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
	request, err := constructSessionRequest(cmd, irmaconfig)
	if err != nil {
		return nil, nil, err
	}

	logger.Debugf("Session request: %s", prettyprint(request))

	return request, irmaconfig, nil
}

func startServer(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", irmarequestor.HttpHandlerFunc())
	irmaServer = &http.Server{Addr: ":" + strconv.Itoa(port), Handler: mux}
	go func() {
		err := irmaServer.ListenAndServe()
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
