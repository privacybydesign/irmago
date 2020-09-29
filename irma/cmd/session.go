package cmd

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"

	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sietseringers/cobra"
	"github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var (
	httpServer *http.Server
	irmaServer *irmaserver.Server
	logger     *logrus.Logger
	defaulturl string
)

// sessionCmd represents the session command
var sessionCmd = &cobra.Command{
	Use:   "session",
	Short: "Perform an IRMA disclosure, issuance or signature session",
	Long: `Perform an IRMA disclosure, issuance or signature session on the command line

Using either the builtin IRMA server library, or an external IRMA server (specify its URL
with --server), an IRMA session is started; the QR is printed in the terminal; and the session
result is printed when the session completes or fails.

A session request can either be constructed using the --disclose, --issue, and --sign together
with --message flags, or it can be specified as JSON to the --request flag.`,
	Example: `irma session --disclose irma-demo.MijnOverheid.root.BSN
irma session --sign irma-demo.MijnOverheid.root.BSN --message message
irma session --issue irma-demo.MijnOverheid.ageLower=yes,yes,yes,no --disclose irma-demo.MijnOverheid.root.BSN
irma session --request '{"type":"disclosing","content":[{"label":"BSN","attributes":["irma-demo.MijnOverheid.root.BSN"]}]}'
irma session --server http://localhost:8088 --authmethod token --key mytoken --disclose irma-demo.MijnOverheid.root.BSN`,
	Run: func(cmd *cobra.Command, args []string) {
		request, irmaconfig, err := configureSession(cmd)
		if err != nil {
			die("", err)
		}

		// Make sure we always run with latest configuration
		flags := cmd.Flags()
		disableUpdate, _ := flags.GetBool("disable-schemes-update")
		if !disableUpdate {
			if err = irmaconfig.UpdateSchemes(); err != nil {
				die("failed updating schemes", err)
			}
		}

		var result *server.SessionResult
		url, _ := cmd.Flags().GetString("url")
		serverurl, _ := cmd.Flags().GetString("server")
		noqr, _ := cmd.Flags().GetBool("noqr")
		binding, _ := cmd.Flags().GetBool("binding")

		if url != defaulturl && serverurl != "" {
			die("Failed to read configuration", errors.New("--url can't be combined with --server"))
		}

		if serverurl == "" {
			port, _ := flags.GetInt("port")
			privatekeysPath, _ := flags.GetString("privkeys")
			verbosity, _ := cmd.Flags().GetCount("verbose")
			result, err = libraryRequest(request, irmaconfig, url, port, privatekeysPath, noqr, verbosity, binding)
		} else {
			authmethod, _ := flags.GetString("authmethod")
			key, _ := flags.GetString("key")
			name, _ := flags.GetString("name")
			result, err = serverRequest(request, serverurl, authmethod, key, name, noqr, binding)
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
	url string,
	port int,
	privatekeysPath string,
	noqr bool,
	verbosity int,
	binding bool,
) (*server.SessionResult, error) {
	if err := configureSessionServer(url, port, privatekeysPath, irmaconfig, verbosity); err != nil {
		return nil, err
	}
	startServer(port)

	// Start the session
	resultchan := make(chan *server.SessionResult)
	qr, requestorToken, _, err := irmaServer.StartSession(request, func(r *server.SessionResult) {
		resultchan <- r
	})
	if err != nil {
		return nil, errors.WrapPrefix(err, "IRMA session failed", 0)
	}

	// Enable binding if necessary
	var sessionOptions *irma.SessionOptions
	if binding {
		optionsRequest := irma.NewOptionsRequest()
		optionsRequest.BindingMethod = irma.BindingMethodPin
		if sessionOptions, err = irmaServer.SetFrontendOptions(requestorToken, &optionsRequest); err != nil {
			return nil, errors.WrapPrefix(err, "IRMA enable binding failed", 0)
		}
	}

	// Print QR code
	if err := printQr(qr, noqr); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to print QR", 0)
	}

	if binding {
		// Listen for session status
		statuschan, err := irmaServer.GetSessionStatus(requestorToken)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Failed to start listening for session statuses", 0)
		}

		_, err = handleBinding(sessionOptions, statuschan, func() error {
			return irmaServer.BindingCompleted(requestorToken)
		})
		if err != nil {
			return nil, errors.WrapPrefix(err, "Failed to handle binding", 0)
		}
	}

	// Wait for session to finish and then return session result
	return <-resultchan, nil
}

func serverRequest(
	request irma.RequestorRequest,
	serverurl, authmethod, key, name string,
	noqr bool,
	binding bool,
) (*server.SessionResult, error) {
	logger.Debug("Server URL: ", serverurl)

	// Start session at server
	qr, frontendAuth, transport, err := postRequest(serverurl, request, name, authmethod, key)
	if err != nil {
		return nil, err
	}

	// Enable binding if necessary
	var frontendTransport *irma.HTTPTransport
	sessionOptions := &irma.SessionOptions{}
	if binding {
		frontendTransport = irma.NewHTTPTransport(qr.URL, false)
		frontendTransport.SetHeader(irma.AuthorizationHeader, string(frontendAuth))
		optionsRequest := irma.NewOptionsRequest()
		optionsRequest.BindingMethod = irma.BindingMethodPin
		err = frontendTransport.Post("frontend/options", sessionOptions, optionsRequest)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Failed to enable binding", 0)
		}
	}

	// Print session QR
	logger.Debug("QR: ", prettyprint(qr))
	if err := printQr(qr, noqr); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to print QR", 0)
	}

	statuschan := make(chan irma.ServerStatus)
	errorchan := make(chan error)
	var wg sync.WaitGroup

	go irma.WaitStatus(transport, irma.ServerStatusInitialized, statuschan, errorchan)
	go func() {
		err := <-errorchan
		if err != nil {
			_ = server.LogFatal(err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		var status irma.ServerStatus
		if binding {
			status, err = handleBinding(sessionOptions, statuschan, func() error {
				err = frontendTransport.Post("frontend/bindingcompleted", nil, nil)
				if err != nil {
					return errors.WrapPrefix(err, "Failed to complete binding", 0)
				}
				return nil
			})
			if err != nil {
				err = errors.WrapPrefix(err, "Failed to handle binding", 0)
				return
			}
		} else {
			// Wait until client connects if binding is disabled
			status := <-statuschan
			if status != irma.ServerStatusConnected {
				err = errors.Errorf("Unexpected status: %s", status)
				return
			}
		}

		// Wait until client finishes
		status = <-statuschan
		if status != irma.ServerStatusCancelled && status != irma.ServerStatusDone {
			err = errors.Errorf("Unexpected status: %s", status)
			return
		}
	}()

	wg.Wait()
	if err != nil {
		return nil, err
	}

	// Retrieve session result
	result := &server.SessionResult{}
	if err := transport.Get("result", result); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to get session result", 0)
	}
	return result, nil
}

func postRequest(serverurl string, request irma.RequestorRequest, name, authmethod, key string) (
	*irma.Qr, irma.FrontendAuthorization, *irma.HTTPTransport, error) {
	var (
		err       error
		pkg       = &server.SessionPackage{}
		transport = irma.NewHTTPTransport(serverurl, false)
	)

	switch authmethod {
	case "none":
		err = transport.Post("session", pkg, request)
	case "token":
		transport.SetHeader("Authorization", key)
		err = transport.Post("session", pkg, request)
	case "hmac", "rsa":
		var jwtstr string
		jwtstr, err = signRequest(request, name, authmethod, key)
		if err != nil {
			return nil, "", nil, err
		}
		logger.Debug("Session request JWT: ", jwtstr)
		err = transport.Post("session", pkg, jwtstr)
	default:
		return nil, "", nil, errors.New("Invalid authentication method (must be none, token, hmac or rsa)")
	}

	if err != nil {
		return nil, "", nil, err
	}

	requestorToken := pkg.Token
	transport.Server += fmt.Sprintf("session/%s/", requestorToken)

	return pkg.SessionPtr, pkg.FrontendAuth, transport, err
}

func handleBinding(options *irma.SessionOptions, statusChan chan irma.ServerStatus, completeBinding func() error) (
	irma.ServerStatus, error) {
	errorChan := make(chan error)
	status := irma.ServerStatusInitialized
	bindingStarted := false
	for {
		select {
		case status = <-statusChan:
			if status == irma.ServerStatusInitialized {
				continue
			} else if status == irma.ServerStatusBinding {
				bindingStarted = true
				go requestBindingPermission(options, completeBinding, errorChan)
				continue
			} else if status == irma.ServerStatusConnected && !bindingStarted {
				fmt.Println("Binding is not supported by the connected device.")
			}
			return status, nil
		case err := <-errorChan:
			return "", err
		}
	}
}

func requestBindingPermission(options *irma.SessionOptions, completeBinding func() error, errorChan chan error) {
	if options.BindingMethod == irma.BindingMethodPin {
		fmt.Println("\nBinding code:", options.BindingCode)
		fmt.Println("Press Enter to confirm your device shows the same binding code; otherwise press Ctrl-C.")
		_, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			errorChan <- err
			return
		}
		if err = completeBinding(); err != nil {
			errorChan <- err
			return
		}
		fmt.Println("Binding completed.")
		errorChan <- nil
		return
	}
	errorChan <- errors.Errorf("Binding method %s is not supported", options.BindingMethod)
}

// Configuration functions

func configureSessionServer(url string, port int, privatekeysPath string, irmaconfig *irma.Configuration, verbosity int) error {
	// Replace "port" in url with actual port
	replace := "$1:" + strconv.Itoa(port)
	url = string(regexp.MustCompile("(https?://[^/]*):port").ReplaceAll([]byte(url), []byte(replace)))

	config := &server.Configuration{
		IrmaConfiguration:    irmaconfig,
		Logger:               logger,
		URL:                  url,
		DisableSchemesUpdate: true,
		Verbose:              verbosity,
	}
	if privatekeysPath != "" {
		config.IssuerPrivateKeysPath = privatekeysPath
	}

	var err error
	irmaServer, err = irmaserver.New(config)
	return err
}

func configureSession(cmd *cobra.Command) (irma.RequestorRequest, *irma.Configuration, error) {
	verbosity, _ := cmd.Flags().GetCount("verbose")
	logger.Level = server.Verbosity(verbosity)
	irma.SetLogger(logger)

	return configureRequest(cmd)
}

func init() {
	RootCmd.AddCommand(sessionCmd)

	logger = logrus.New()
	logger.Formatter = &prefixed.TextFormatter{FullTimestamp: true}

	var err error
	defaulturl, err = server.LocalIP()
	if err != nil {
		logger.Warn("Could not determine local IP address: ", err.Error())
	} else {
		defaulturl = "http://" + defaulturl + ":port"
	}

	flags := sessionCmd.Flags()
	flags.SortFlags = false
	flags.String("server", "", "External IRMA server to post request to (leave blank to use builtin library)")
	flags.StringP("url", "u", defaulturl, "external URL to which IRMA app connects (when not using --server), \":port\" being replaced by --port value")
	flags.IntP("port", "p", 48680, "port to listen at (when not using --server)")
	flags.Bool("noqr", false, "Print JSON instead of draw QR")
	flags.Bool("binding", false, "Enable explicit binding between server and IRMA app")
	flags.StringP("request", "r", "", "JSON session request")
	flags.StringP("privkeys", "k", "", "path to private keys")
	flags.Bool("disable-schemes-update", false, "disable scheme updates")

	addRequestFlags(flags)

	flags.CountP("verbose", "v", "verbose (repeatable)")
}
