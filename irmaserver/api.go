package irmaserver

import (
	"github.com/Sirupsen/logrus"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
)

type Configuration struct {
	IrmaConfigurationPath string
	PrivateKeysPath       string

	Logger *logrus.Logger

	PrivateKeys       map[irma.IssuerIdentifier]*gabi.PrivateKey
	IrmaConfiguration *irma.Configuration
}

type SessionResult struct {
	Token       string
	Status      Status
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
