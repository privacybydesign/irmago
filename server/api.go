package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/fs"
	"github.com/sirupsen/logrus"
)

var Logger *logrus.Logger = logrus.StandardLogger()

// Configuration contains configuration for the irmaserver library and irmad.
type Configuration struct {
	// irma_configuration. If not given, this will be popupated using SchemesPath.
	IrmaConfiguration *irma.Configuration `json:"-"`
	// Path to IRMA schemes to parse into IrmaConfiguration (only used if IrmaConfiguration == nil)
	SchemesPath string `json:"schemes_path" mapstructure:"schemes_path"`
	// If specified, schemes found here are copied into SchemesPath (only used if IrmaConfiguration == nil)
	SchemesAssetsPath string `json:"schemes_assets_path" mapstructure:"schemes_assets_path"`
	// Whether or not to download default IRMA schemes if the specified schemes path is empty
	DownloadDefaultSchemes bool `json:"schemes_download_default" mapstructure:"schemes_download_default"`
	// Update all schemes every x minutes (0 to disable)
	SchemeUpdateInterval int `json:"schemes_update" mapstructure:"schemes_update"`
	// Path to issuer private keys to parse
	IssuerPrivateKeysPath string `json:"privkeys" mapstructure:"privkeys"`
	// Issuer private keys
	IssuerPrivateKeys map[irma.IssuerIdentifier]*gabi.PrivateKey `json:"-"`
	// URL at which the IRMA app can reach this server during sessions
	URL string `json:"url" mapstructure:"url"`
	// Logging
	Logger *logrus.Logger `json:"-"`
	// (Optional) email address of server admin, for incidental notifications such as breaking API changes
	// See https://github.com/privacybydesign/irmago/tree/master/server#specifying-an-email-address
	// for more information
	Email string
}

// SessionResult contains session information such as the session status, type, possible errors,
// and disclosed attributes or attribute-based signature if appropriate to the session type.
type SessionResult struct {
	Token       string
	Status      Status
	Type        irma.Action
	ProofStatus irma.ProofStatus
	Disclosed   []*irma.DisclosedAttribute
	Signature   *irma.SignedMessage
	Err         *irma.RemoteError
}

// Status is the status of an IRMA session.
type Status string

const (
	StatusInitialized Status = "INITIALIZED" // The session has been started and is waiting for the client
	StatusConnected   Status = "CONNECTED"   // The client has retrieved the session request, we wait for its response
	StatusCancelled   Status = "CANCELLED"   // The session is cancelled, possibly due to an error
	StatusDone        Status = "DONE"        // The session has completed successfully
	StatusTimeout     Status = "TIMEOUT"     // Session timed out
)

func (conf *Configuration) PrivateKey(id irma.IssuerIdentifier) (sk *gabi.PrivateKey, err error) {
	sk = conf.IssuerPrivateKeys[id]
	if sk == nil {
		if sk, err = conf.IrmaConfiguration.PrivateKey(id); err != nil {
			return nil, err
		}
	}
	return sk, nil
}

func (conf *Configuration) HavePrivateKeys() (bool, error) {
	var err error
	var sk *gabi.PrivateKey
	for id := range conf.IrmaConfiguration.Issuers {
		sk, err = conf.PrivateKey(id)
		if err != nil {
			return false, err
		}
		if sk != nil {
			return true, nil
		}
	}
	return false, nil
}

func (status Status) Finished() bool {
	return status == StatusDone || status == StatusCancelled || status == StatusTimeout
}

// RemoteError converts an error and an explaining message to an *irma.RemoteError.
func RemoteError(err Error, message string) *irma.RemoteError {
	var stack string
	Logger.WithFields(logrus.Fields{
		"status":      err.Status,
		"description": err.Description,
		"error":       err.Type,
		"message":     message,
	}).Warnf("Sending session error")
	if Logger.IsLevelEnabled(logrus.DebugLevel) {
		stack = string(debug.Stack())
		Logger.Warn(stack)
	}
	return &irma.RemoteError{
		Status:      err.Status,
		Description: err.Description,
		ErrorName:   string(err.Type),
		Message:     message,
		Stacktrace:  stack,
	}
}

// JsonResponse JSON-marshals the specified object or error
// and returns it along with a suitable HTTP status code
func JsonResponse(v interface{}, err *irma.RemoteError) (int, []byte) {
	msg := v
	status := http.StatusOK
	if err != nil {
		msg = err
		status = err.Status
	}
	b, e := json.Marshal(msg)
	if e != nil {
		Logger.Error("Failed to serialize response:", e.Error())
		return http.StatusInternalServerError, nil
	}
	Logger.Tracef("HTTP JSON response: %d %s", status, string(b))
	return status, b
}

// WriteError writes the specified error and explaining message as JSON to the http.ResponseWriter.
func WriteError(w http.ResponseWriter, err Error, msg string) {
	WriteResponse(w, nil, RemoteError(err, msg))
}

// WriteJson writes the specified object as JSON to the http.ResponseWriter.
func WriteJson(w http.ResponseWriter, object interface{}) {
	WriteResponse(w, object, nil)
}

// WriteResponse writes the specified object or error as JSON to the http.ResponseWriter.
func WriteResponse(w http.ResponseWriter, object interface{}, rerr *irma.RemoteError) {
	status, bts := JsonResponse(object, rerr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(bts)
}

// WriteString writes the specified string to the http.ResponseWriter.
func WriteString(w http.ResponseWriter, str string) {
	Logger.Trace("HTTP text/plain response: ", str)
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(str))
}

func ParseSessionRequest(request interface{}) (irma.RequestorRequest, error) {
	switch r := request.(type) {
	case irma.RequestorRequest:
		return r, nil
	case irma.SessionRequest:
		return wrapSessionRequest(r)
	case string:
		return ParseSessionRequest([]byte(r))
	case []byte:
		var attempts = []irma.Validator{&irma.ServiceProviderRequest{}, &irma.SignatureRequestorRequest{}, &irma.IdentityProviderRequest{}}
		t, err := tryUnmarshalJson(r, attempts)
		if err == nil {
			return t.(irma.RequestorRequest), nil
		}
		attempts = []irma.Validator{&irma.DisclosureRequest{}, &irma.SignatureRequest{}, &irma.IssuanceRequest{}}
		t, err = tryUnmarshalJson(r, attempts)
		if err == nil {
			return wrapSessionRequest(t.(irma.SessionRequest))
		}
		return nil, errors.New("Failed to JSON unmarshal request bytes")
	default:
		return nil, errors.New("Invalid request type")
	}
}

func wrapSessionRequest(request irma.SessionRequest) (irma.RequestorRequest, error) {
	switch r := request.(type) {
	case *irma.DisclosureRequest:
		return &irma.ServiceProviderRequest{Request: r}, nil
	case *irma.SignatureRequest:
		return &irma.SignatureRequestorRequest{Request: r}, nil
	case *irma.IssuanceRequest:
		return &irma.IdentityProviderRequest{Request: r}, nil
	default:
		return nil, errors.New("Invalid session type")
	}
}

func tryUnmarshalJson(bts []byte, attempts []irma.Validator) (irma.Validator, error) {
	for _, a := range attempts {
		if err := irma.UnmarshalValidate(bts, a); err == nil {
			return a, nil
		}
	}
	return nil, errors.New("")
}

func LocalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("No IP found")
}

func DefaultSchemesPath() string {
	candidates := make([]string, 0, 2)
	if runtime.GOOS != "windows" {
		candidates = append(candidates, "/var/tmp/irma/irma_configuration")
	}
	candidates = append(candidates, filepath.Join(os.TempDir(), "irma", "irma_configuration"))
	return firstWritablePath(candidates)
}

func firstWritablePath(paths []string) string {
	for _, path := range paths {
		if err := fs.EnsureDirectoryExists(path); err != nil {
			continue
		}
		return path
	}
	return ""
}

func Verbosity(level int) logrus.Level {
	switch {
	case level == 1:
		return logrus.DebugLevel
	case level > 1:
		return logrus.TraceLevel
	default:
		return logrus.InfoLevel
	}
}

func TypeString(x interface{}) string {
	return reflect.TypeOf(x).String()
}

func log(level logrus.Level, err error) error {
	writer := Logger.WithFields(logrus.Fields{"err": TypeString(err)}).WriterLevel(level)
	if e, ok := err.(*errors.Error); ok && Logger.IsLevelEnabled(logrus.DebugLevel) {
		_, _ = writer.Write([]byte(e.ErrorStack()))
	} else {
		_, _ = writer.Write([]byte(fmt.Sprintf("%s", err.Error())))
	}
	return err
}

func LogFatal(err error) error {
	logger := Logger.WithFields(logrus.Fields{"err": TypeString(err)})
	// using log() for this doesn't seem to do anything
	if e, ok := err.(*errors.Error); ok && Logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.Fatal(e.ErrorStack())
	} else {
		logger.Fatalf("%s", err.Error())
	}
	return err
}

func LogError(err error) error {
	return log(logrus.ErrorLevel, err)
}

func LogWarning(err error) error {
	return log(logrus.WarnLevel, err)
}

func ToJson(o interface{}) string {
	bts, _ := json.Marshal(o)
	return string(bts)
}
