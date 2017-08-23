package protocol

import (
	"fmt"
	"strconv"
	"time"

	"math/big"

	"github.com/credentials/irmago"
)

// Timestamp is a time.Time that marshals to Unix timestamps.
type Timestamp time.Time

// Status encodes the status of an IRMA session (e.g., connected).
type Status string

// Action encodes the session type of an IRMA session (e.g., disclosing).
type Action string

// Version encodes the IRMA protocol version of an IRMA session.
type Version string

// SessionError are session errors.
type SessionError string

// Statuses
const (
	StatusConnected     = Status("connected")
	StatusCommunicating = Status("communicating")
	StatusDone          = Status("done")
)

// Actions
const (
	ActionDisclosing = Action("disclosing")
	ActionSigning    = Action("signing")
	ActionIssuing    = Action("issuing")
	ActionUnknown    = Action("unknown")
)

// Protocol errors
const (
	ErrorProtocolVersionNotSupported = SessionError("versionNotSupported")
	ErrorInvalidURL                  = SessionError("invalidUrl")
	ErrorTransport                   = SessionError("httpError")
	ErrorInvalidJWT                  = SessionError("invalidJwt")
	ErrorUnknownAction               = SessionError("unknownAction")
)

// Qr contains the data of an IRMA session QR.
type Qr struct {
	URL                string `json:"u"`
	ProtocolVersion    string `json:"v"`
	ProtocolMaxVersion string `json:"vmax"`
	Type               Action `json:"irmaqr"`
}

// A SessionInfo is the first message in the IRMA protocol.
type SessionInfo struct {
	Jwt     string                          `json:"jwt"`
	Nonce   *big.Int                        `json:"nonce"`
	Context *big.Int                        `json:"context"`
	Keys    map[irmago.IssuerIdentifier]int `json:"keys"`
}

// A DisclosureChoice contains the attributes chosen to be disclosed.
type DisclosureChoice struct {
	Attributes []*irmago.AttributeIdentifier
}

// MarshalJSON marshals a timestamp.
func (t *Timestamp) MarshalJSON() ([]byte, error) {
	ts := time.Time(*t).Unix()
	stamp := fmt.Sprint(ts)
	return []byte(stamp), nil
}

// UnmarshalJSON unmarshals a timestamp.
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	ts, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}
	*t = Timestamp(time.Unix(int64(ts), 0))
	return nil
}
