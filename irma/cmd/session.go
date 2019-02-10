package cmd

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/x-cray/logrus-prefixed-formatter"
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
			privatekeysPath, _ := flags.GetString("privkeys")
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
		jwtstr, err := signRequest(request, name, authmethod, key)
		if err != nil {
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
	verbosity, _ := cmd.Flags().GetCount("verbose")
	logger = logrus.New()
	logger.Level = server.Verbosity(verbosity)
	logger.Formatter = &prefixed.TextFormatter{FullTimestamp: true}
	irma.Logger = logger

	return configureRequest(cmd)
}

func init() {
	RootCmd.AddCommand(sessionCmd)

	flags := sessionCmd.Flags()
	flags.SortFlags = false
	flags.IntP("port", "p", 48680, "port to listen at")
	flags.Bool("noqr", false, "Print JSON instead of draw QR")
	flags.String("server", "", "Server to post request to (leave blank to use builtin library)")
	flags.StringP("request", "r", "", "JSON session request")
	flags.StringP("privkeys", "k", "", "path to private keys")

	addRequestFlags(flags)

	flags.CountP("verbose", "v", "verbose (repeatable)")
}
