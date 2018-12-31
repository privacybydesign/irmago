package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

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
		request, err := configure(cmd)
		if err != nil {
			die("", err)
		}
		port, _ := cmd.Flags().GetInt("port")
		startServer(port)

		// Start the session
		resultchan := make(chan *server.SessionResult)
		qr, _, err := irmarequestor.StartSession(request, func(r *server.SessionResult) {
			resultchan <- r
		})
		if err != nil {
			die("IRMA session failed", err)
		}

		// Print QR code
		noqr, _ := cmd.Flags().GetBool("noqr")
		if err := printQr(qr, noqr); err != nil {
			die("Failed to print QR", err)
		}

		// Wait for session to finish and then print session result
		result := <-resultchan
		printSessionResult(result)

		// Done!
		_ = irmaServer.Close()
	},
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

func configure(cmd *cobra.Command) (irma.SessionRequest, error) {
	irmaconfigPath, err := cmd.Flags().GetString("irmaconf")
	if err != nil {
		return nil, err
	}
	privatekeysPath, err := cmd.Flags().GetString("privatekeys")
	if err != nil {
		return nil, err
	}
	ip, err := server.LocalIP()
	if err != nil {
		return nil, err
	}

	conf, err := irma.NewConfiguration(irmaconfigPath)
	if err != nil {
		return nil, err
	}
	if err = conf.ParseFolder(); err != nil {
		return nil, err
	}
	if len(conf.SchemeManagers) == 0 {
		if err = conf.DownloadDefaultSchemes(); err != nil {
			return nil, err
		}
	}

	verbosity, _ := cmd.Flags().GetCount("verbose")
	port, _ := cmd.Flags().GetInt("port")
	logger = logrus.New()
	logger.Level = server.Verbosity(verbosity)
	logger.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	config := &server.Configuration{
		IrmaConfiguration: conf,
		Logger:            logger,
		URL:               "http://" + ip + ":" + strconv.Itoa(port),
	}
	if privatekeysPath != "" {
		config.IssuerPrivateKeysPath = privatekeysPath
	}

	request, err := constructSessionRequest(cmd, conf)
	if err != nil {
		return nil, err
	}
	logger.Debugf("Session request: %s", prettyprint(request))

	return request, irmarequestor.Initialize(config)
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
	res, err := json.MarshalIndent(result, "", "    ")
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println("Session result:")
	fmt.Println(string(res))
}
