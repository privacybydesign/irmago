package protocol

import (
	"fmt"
	"strconv"
	"time"

	"github.com/credentials/irmago"
)

// Session types.
const (
	DISCLOSING = SessionType("disclosing")
	ISSUING    = SessionType("issuing")
	SIGNING    = SessionType("signing")
)

// Timestamp is a time.Time that marshals to Unix timestamps.
type Timestamp time.Time

// SessionType is a session type (DISCLOSING, ISSUING or SIGNING).
type SessionType string

// Qr contains the data of an IRMA session QR.
type Qr struct {
	URL                string      `json:"u"`
	ProtocolVersion    string      `json:"v"`
	ProtocolMaxVersion string      `json:"vmax"`
	Type               SessionType `json:"irmaqr"`
}

// A DisclosureChoice contains the attributes chosen to be disclosed.
type DisclosureChoice struct {
	Request    SessionRequest
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
