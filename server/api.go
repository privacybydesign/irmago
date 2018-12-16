package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"runtime/debug"

	"github.com/Sirupsen/logrus"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
)

var Logger *logrus.Logger = logrus.StandardLogger()

type Configuration struct {
	IrmaConfigurationPath string                                     `json:"irmaconf" mapstructure:"irmaconf"`
	IssuerPrivateKeysPath string                                     `json:"privatekeys" mapstructure:"privatekeys"`
	Url                   string                                     `json:"url" mapstructure:"url"`
	Logger                *logrus.Logger                             `json:"-"`
	IssuerPrivateKeys     map[irma.IssuerIdentifier]*gabi.PrivateKey `json:"-"`
	IrmaConfiguration     *irma.Configuration                        `json:"-"`
}

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

func RemoteError(err Error, message string) *irma.RemoteError {
	stack := string(debug.Stack())
	Logger.Errorf("Error: %d %s %s\n%s", err.Status, err.Type, message, stack)
	return &irma.RemoteError{
		Status:      err.Status,
		Description: err.Description,
		ErrorName:   string(err.Type),
		Message:     message,
		Stacktrace:  stack,
	}
}

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
	return status, b
}

func WriteError(w http.ResponseWriter, err Error, msg string) {
	WriteResponse(w, nil, RemoteError(err, msg))
}

func WriteJson(w http.ResponseWriter, object interface{}) {
	WriteResponse(w, object, nil)
}

func WriteResponse(w http.ResponseWriter, object interface{}, rerr *irma.RemoteError) {
	status, bts := JsonResponse(object, rerr)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(bts)
}

func WriteString(w http.ResponseWriter, str string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(str))
}

func ParseSessionRequest(bts []byte) (request irma.SessionRequest, err error) {
	request = &irma.DisclosureRequest{}
	if err = irma.UnmarshalValidate(bts, request); err == nil {
		return request, nil
	}
	request = &irma.SignatureRequest{}
	if err = irma.UnmarshalValidate(bts, request); err == nil {
		return request, nil
	}
	request = &irma.IssuanceRequest{}
	if err = irma.UnmarshalValidate(bts, request); err == nil {
		return request, nil
	}
	return nil, errors.New("Invalid or disabled session type")
}
