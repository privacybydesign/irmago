package irmago

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Action encodes the session type of an IRMA session (e.g., disclosing).
type Action string

// ErrorCode are session errors.
type ErrorCode string

// Error is a protocol error.
type Error struct {
	Err error
	ErrorCode
	*ApiError
	Info   string
	Status int
}

// ApiError is an error message returned by the API server on errors.
type ApiError struct {
	Status      int    `json:"status"`
	ErrorName   string `json:"error"`
	Description string `json:"description"`
	Message     string `json:"message"`
	Stacktrace  string `json:"stacktrace"`
}

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
	// (De)serializing of a message failed
	ErrorSerialization   = ErrorCode("serializationError")
	ErrorKeyshare        = ErrorCode("keyshare")
	ErrorKeyshareBlocked = ErrorCode("keyshareBlocked")
)

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s", string(e.ErrorCode), e.Err.Error())
	}
	return string(e.ErrorCode)
}

func JwtDecode(jwt string, body interface{}) (string, error) {
	jwtparts := strings.Split(jwt, ".")
	if jwtparts == nil || len(jwtparts) < 2 {
		return "", errors.New("Not a JWT")
	}
	headerbytes, err := base64.RawStdEncoding.DecodeString(jwtparts[0])
	if err != nil {
		return "", err
	}
	var header struct {
		Issuer string `json:"iss"`
	}
	err = json.Unmarshal([]byte(headerbytes), &header)
	if err != nil {
		return "", err
	}

	bodybytes, err := base64.RawStdEncoding.DecodeString(jwtparts[1])
	if err != nil {
		return "", err
	}
	return header.Issuer, json.Unmarshal(bodybytes, body)
}
