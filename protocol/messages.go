package protocol

import (
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/credentials/irmago"
)

// Status encodes the status of an IRMA session (e.g., connected).
type Status string

// Action encodes the session type of an IRMA session (e.g., disclosing).
type Action string

// Version encodes the IRMA protocol version of an IRMA session.
type Version string

// ErrorCode are session errors.
type ErrorCode string

type Error struct {
	ErrorCode
	error
	info string
	*ApiError
}

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
	// Protocol version not supported
	ErrorProtocolVersionNotSupported = ErrorCode("versionNotSupported")
	// Server URL invalid
	ErrorInvalidURL = ErrorCode("invalidUrl")
	// Error in HTTP communication
	ErrorTransport = ErrorCode("httpError")
	// Invalid client JWT in first IRMA message
	ErrorInvalidJWT = ErrorCode("invalidJwt")
	// Unkown session type (not disclosing, signing, or issuing)
	ErrorUnknownAction = ErrorCode("unknownAction")
	// Crypto error during calculation of our response (second IRMA message)
	ErrorCrypto = ErrorCode("cryptoResponseError")
	// Server rejected our response (second IRMA message)
	ErrorRejected = ErrorCode("rejectedByServer")
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

func (e *Error) Error() string {
	if e.error != nil {
		return fmt.Sprintf("%s: %s", string(e.ErrorCode), e.error.Error())
	} else {
		return string(e.ErrorCode)
	}
}

/*
So apparently, in the old Java implementation we forgot to write a (de)serialization for the Java
equivalent of the type IssuerIdentifier. This means a Java IssuerIdentifier does not serialize to
a string, but to e.g. `{"identifier":"irma-demo.RU"}`.
This is a complex data type, so not suitable to act as keys in a JSON map. Consequentially,
Gson serializes the `json:"keys"` field not as a map, but as a list consisting of pairs where
the first item of the pair is a serialized IssuerIdentifier as above, and the second item
of the pair is the corresponding key counter from the original map.
This is a bit of a mess to have to deserialize. See below. In a future version of the protocol,
this will have to be fixed both in the Java world and here in Go.
*/

type jsonSessionInfo struct {
	Jwt     string          `json:"jwt"`
	Nonce   *big.Int        `json:"nonce"`
	Context *big.Int        `json:"context"`
	Keys    [][]interface{} `json:"keys"`
}

func (si *SessionInfo) UnmarshalJSON(b []byte) error {
	temp := &jsonSessionInfo{}
	err := json.Unmarshal(b, temp)
	if err != nil {
		return err
	}

	si.Jwt = temp.Jwt
	si.Nonce = temp.Nonce
	si.Context = temp.Context
	si.Keys = make(map[irmago.IssuerIdentifier]int, len(temp.Keys))
	for _, item := range temp.Keys {
		idmap := item[0].(map[string]interface{})
		id := irmago.NewIssuerIdentifier(idmap["identifier"].(string))
		si.Keys[id] = int(item[1].(float64))
	}
	return nil
}
