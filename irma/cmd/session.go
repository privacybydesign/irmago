package cmd

import (
	"bufio"
	"encoding/json"
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
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
)

var (
	httpServer *http.Server
	irmaServer *irmaserver.Server
	defaulturl string

	logger = logrus.New()
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
irma session --server http://localhost:8088 --authmethod token --key mytoken --disclose irma-demo.MijnOverheid.root.BSN
irma session --server http://localhost:8088 --static mystaticsession
irma session --from-package '{"sessionPtr": ... , "frontendRequest": ...}'`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			request    irma.RequestorRequest
			irmaconfig *irma.Configuration
			pkg        *server.SessionPackage
			result     *server.SessionResult
			err        error

			flags         = cmd.Flags()
			url, _        = flags.GetString("url")
			serverURL, _  = flags.GetString("server")
			noqr, _       = flags.GetBool("noqr")
			pairing, _    = flags.GetBool("pairing")
			authMethod, _ = flags.GetString("authmethod")
			key, _        = flags.GetString("key")
			jsonPkg, _    = flags.GetString("from-package")
			static, _     = flags.GetString("static")
		)
		if url != defaulturl && serverURL != "" {
			die("Failed to read configuration", errors.New("--url can't be combined with --server"))
		}

		if static != "" {
			if err = staticRequest(serverURL, static, noqr); err != nil {
				die("Failed to handle static session", err)
			}
			// Static sessions are fully handled on the phone.
			return
		}

		if jsonPkg == "" {
			request, irmaconfig, err = configureSession(cmd)
			if err != nil {
				die("", err)
			}
			if serverURL != "" {
				name, _ := flags.GetString("name")
				pkg, err = postRequest(serverURL, "session", request, name, authMethod, key)
				if err != nil {
					die("Session could not be started", err)
				}
			}
		} else {
			pkg = &server.SessionPackage{}
			err = json.Unmarshal([]byte(jsonPkg), pkg)
			if err != nil {
				die("Failed to parse session package", err)
			}
		}

		if pkg == nil {
			port, _ := flags.GetInt("port")
			privatekeysPath, _ := flags.GetString("privkeys")
			verbosity, _ := cmd.Flags().GetCount("verbose")
			result, err = libraryRequest(request, irmaconfig, url, port, privatekeysPath, noqr, verbosity, pairing)
		} else {
			err = serverRequest(pkg, noqr, pairing)
			if pkg.Token != "" {
				result = &server.SessionResult{}
				path := fmt.Sprintf("session/%s/result", pkg.Token)
				err = irma.NewHTTPTransport(serverURL, false).Get(path, result)
				if err != nil {
					die("Result could not be retrieved", err)
				}
			}
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
	pairing bool,
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

	// Enable pairing if necessary
	var sessionOptions *irma.SessionOptions
	if pairing {
		optionsRequest := irma.NewFrontendOptionsRequest()
		optionsRequest.PairingMethod = irma.PairingMethodPin
		if sessionOptions, err = irmaServer.SetFrontendOptions(requestorToken, &optionsRequest); err != nil {
			return nil, errors.WrapPrefix(err, "Failed to enable pairing", 0)
		}
	}

	// Print QR code
	if err := printQr(qr, noqr); err != nil {
		return nil, errors.WrapPrefix(err, "Failed to print QR", 0)
	}

	if pairing {
		// Listen for session status
		statuschan, err := irmaServer.SessionStatus(requestorToken)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Failed to start listening for session statuses", 0)
		}

		err = handlePairing(sessionOptions, statuschan, func() error {
			return irmaServer.PairingCompleted(requestorToken)
		})
		if err != nil {
			return nil, errors.WrapPrefix(err, "Failed to handle pairing", 0)
		}
	}

	// Wait for session to finish and then return session result
	return <-resultchan, nil
}

func serverRequest(
	pkg *server.SessionPackage,
	noqr bool,
	pairing bool,
) error {
	// Enable pairing if necessary
	var (
		qr              = pkg.SessionPtr
		frontendRequest = pkg.FrontendRequest
		transport       = irma.NewHTTPTransport(qr.URL, false)
		sessionOptions  = &irma.SessionOptions{}
		err             error
	)
	if pairing {
		transport.SetHeader(irma.AuthorizationHeader, string(frontendRequest.Authorization))
		optionsRequest := irma.NewFrontendOptionsRequest()
		optionsRequest.PairingMethod = irma.PairingMethodPin
		err = transport.Post("frontend/options", sessionOptions, optionsRequest)
		if err != nil {
			return errors.WrapPrefix(err, "Failed to enable pairing", 0)
		}
	}

	// Print session QR
	logger.Debug("QR: ", prettyprint(qr))
	if err := printQr(qr, noqr); err != nil {
		return errors.WrapPrefix(err, "Failed to print QR", 0)
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

		if pairing {
			err = handlePairing(sessionOptions, statuschan, func() error {
				err = transport.Post("frontend/pairingcompleted", nil, nil)
				if err != nil {
					return errors.WrapPrefix(err, "Failed to complete pairing", 0)
				}
				return nil
			})
			if err != nil {
				err = errors.WrapPrefix(err, "Failed to handle pairing", 0)
				return
			}
		} else {
			// Wait until client connects if pairing is disabled
			status := <-statuschan
			if status != irma.ServerStatusConnected {
				err = errors.Errorf("Unexpected status: %s", status)
				return
			}
		}

		// Wait until client finishes
		status := <-statuschan
		if status != irma.ServerStatusCancelled && status != irma.ServerStatusDone {
			err = errors.Errorf("Unexpected status: %s", status)
			return
		}
	}()

	wg.Wait()
	return err
}

func staticRequest(serverURL, name string, noqr bool) error {
	if serverURL == "" {
		return errors.New("--static must be combined with --server")
	}
	qr := &irma.Qr{
		Type: irma.ActionRedirect,
		URL:  fmt.Sprintf("%s/irma/session/%s", serverURL, name),
	}
	return printQr(qr, noqr)
}

func postRequest(serverURL, path string, request irma.RequestorRequest, name, authMethod, key string) (
	*server.SessionPackage, error) {
	var (
		err       error
		pkg       = &server.SessionPackage{}
		transport = irma.NewHTTPTransport(serverURL, false)
	)

	switch authMethod {
	case "token":
		transport.SetHeader("Authorization", key)
		fallthrough
	case "none":
		err = transport.Post(path, pkg, request)
	case "hmac", "rsa":
		var jwtstr string
		jwtstr, err = signRequest(request, name, authMethod, key)
		if err != nil {
			return nil, err
		}
		logger.Debug("Session request JWT: ", jwtstr)
		err = transport.Post(path, pkg, jwtstr)
	default:
		return nil, errors.New("Invalid authentication method (must be none, token, hmac or rsa)")
	}

	if err != nil {
		return nil, err
	}
	return pkg, err
}

func handlePairing(options *irma.SessionOptions, statusChan chan irma.ServerStatus, completePairing func() error) error {
	errorChan := make(chan error)
	pairingStarted := false
	for {
		select {
		case status := <-statusChan:
			if status == irma.ServerStatusInitialized {
				continue
			} else if status == irma.ServerStatusPairing {
				pairingStarted = true
				go requestPairingPermission(options, completePairing, errorChan)
				continue
			} else if status == irma.ServerStatusConnected && !pairingStarted {
				fmt.Println("Pairing is not supported by the connected device.")
			}
			return nil
		case err := <-errorChan:
			return err
		}
	}
}

func requestPairingPermission(options *irma.SessionOptions, completePairing func() error, errorChan chan error) {
	if options.PairingMethod == irma.PairingMethodPin {
		fmt.Println("\nPairing code:", options.PairingCode)
		fmt.Println("Press Enter to confirm your device shows the same pairing code; otherwise press Ctrl-C.")
		_, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			errorChan <- err
			return
		}
		if err = completePairing(); err != nil {
			errorChan <- err
			return
		}
		fmt.Println("Pairing completed.")
		errorChan <- nil
		return
	}
	errorChan <- errors.Errorf("Pairing method %s is not supported", options.PairingMethod)
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

	if localIPErr != nil {
		logger.Warn("Could not determine local IP address: ", localIPErr.Error())
	}

	request, irmaconfig, err := configureRequest(cmd)
	if err != nil {
		return nil, nil, err
	}

	// Make sure we always run with latest configuration
	disableUpdate, _ := cmd.Flags().GetBool("disable-schemes-update")
	if !disableUpdate {
		if err = irmaconfig.UpdateSchemes(); err != nil {
			return nil, nil, err
		}
	}

	return request, irmaconfig, nil
}

func init() {
	RootCmd.AddCommand(sessionCmd)

	logger.Formatter = &prefixed.TextFormatter{FullTimestamp: true}

	if localIP != "" {
		defaulturl = "http://" + localIP + ":port"
	}

	flags := sessionCmd.Flags()
	flags.SortFlags = false
	flags.String("server", "", "External IRMA server to post request to (leave blank to use builtin library)")
	flags.StringP("url", "u", defaulturl, "external URL to which IRMA app connects (when not using --server), \":port\" being replaced by --port value")
	flags.IntP("port", "p", 48680, "port to listen at (when not using --server)")
	flags.Bool("noqr", false, "Print JSON instead of draw QR")
	flags.Bool("pairing", false, "Let IRMA app first pair, by entering the pairing code, before it can access the session")
	flags.StringP("request", "r", "", "JSON session request")
	flags.StringP("privkeys", "k", "", "path to private keys")
	flags.Bool("disable-schemes-update", false, "disable scheme updates")

	addRequestFlags(flags)

	flags.String("static", "", "Start a static IRMA session with the given name")
	flags.String("from-package", "", "Start the IRMA session from the given session package")

	flags.CountP("verbose", "v", "verbose (repeatable)")
}
