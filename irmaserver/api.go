package irmaserver

import (
	"github.com/Sirupsen/logrus"
	"github.com/mhe/gabi"
	"github.com/privacybydesign/irmago"
)

type Configuration struct {
	IrmaConfigurationPath string

	PrivateKeys       map[irma.IssuerIdentifier]*gabi.PrivateKey
	IrmaConfiguration *irma.Configuration
	Logger            *logrus.Logger
}

type SessionResult struct {
	Token     string
	Status    irma.ProofStatus
	Disclosed []*irma.DisclosedAttribute
	Signature *irma.SignedMessage
	Err       *irma.RemoteError
}

type Status string

const (
	StatusInitialized Status = "INITIALIZED"
	StatusConnected   Status = "CONNECTED"
	StatusCancelled   Status = "CANCELLED"
	StatusDone        Status = "DONE"
)
