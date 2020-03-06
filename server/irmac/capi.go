// Required to be main when building a shared library
package main

// typedef struct StartSessionReturn {
//     char *irmaQr;
//     char *token;
//     char *error;
// } StartSessionReturn;
//
// typedef struct HttpHeaders {
//     char **headerKeys;
//     char **headerValues;
//     int length;
// } HttpHeaders;
//
// typedef struct HandleProtocolMessageReturn {
//     int status;
//     char *body;
//     char *SessionResult;
// } HandleProtocolMessageReturn;
import "C"

import (
	"encoding/json"
	"unsafe"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/internal/servercore"
	"github.com/privacybydesign/irmago/server"
)

var s *servercore.Server

//export Initialize
func Initialize(IrmaConfiguration *C.char) *C.char {
	if IrmaConfiguration == nil {
		return C.CString("Missing IrmaConfiguration.")
	}

	// Build the configuration structure
	conf := new(server.Configuration)
	err := json.Unmarshal([]byte(C.GoString(IrmaConfiguration)), conf)
	if err != nil {
		return C.CString(err.Error())
	}

	// Run the actual core function
	s, err = servercore.New(conf, nil)

	// And properly return any errors
	if err == nil {
		return nil
	} else {
		return C.CString(err.Error())
	}
}

//export StartSession
func StartSession(requestString *C.char) C.struct_StartSessionReturn {
	// Create struct for return information
	var result C.struct_StartSessionReturn

	// Check that we have required input
	if requestString == nil {
		result.irmaQr = nil
		result.token = nil
		result.error = C.CString("Missing request string.")
		return result
	}

	// Run the actual core function
	qr, token, err := s.StartSession(C.GoString(requestString), nil)

	// And properly return the result
	if err != nil {
		// return the core error
		result.irmaQr = nil
		result.token = nil
		result.error = C.CString(err.Error())
		return result
	}
	qrJson, err := json.Marshal(qr)
	if err != nil {
		// return encoding error
		result.irmaQr = nil
		result.token = nil
		result.error = C.CString(err.Error())
		return result
	}
	// return actual results
	result.irmaQr = C.CString(string(qrJson))
	result.token = C.CString(token)
	result.error = nil
	return result
}

//export GetSessionResult
func GetSessionResult(token *C.char) *C.char {
	// Check that we have required input
	if token == nil {
		return nil
	}

	// Run the actual core function
	result := s.GetSessionResult(C.GoString(token))

	// And properly return results
	if result == nil {
		return nil
	}
	resultJson, err := json.Marshal(result)
	if err != nil {
		// encoding error, should never occur
		panic(err)
	}
	return C.CString(string(resultJson))
}

//export GetRequest
func GetRequest(token *C.char) *C.char {
	// Check that we have required input
	if token == nil {
		return nil
	}

	// Run the core function
	result := s.GetRequest(C.GoString(token))

	// And properly return results
	if result == nil {
		return nil
	}
	resultJson, err := json.Marshal(result)
	if err != nil {
		// encoding error, should never occur
		panic(err)
	}
	return C.CString(string(resultJson))
}

//export CancelSession
func CancelSession(token *C.char) *C.char {
	// Check that we have required input
	if token == nil {
		return C.CString("Missing token.")
	}

	// Run the core function
	err := s.CancelSession(C.GoString(token))

	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

func convertHeaders(headers C.struct_HttpHeaders) (map[string][]string, error) {
	// Make the two arrays accessible via slices (https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices)
	headerKeys := (*[1 << 30]*C.char)(unsafe.Pointer(headers.headerKeys))[:headers.length:headers.length]
	headerValues := (*[1 << 30]*C.char)(unsafe.Pointer(headers.headerValues))[:headers.length:headers.length]

	// Check and convert the input
	result := map[string][]string{}
	for i := 0; i < int(headers.length); i++ {
		if headerKeys[i] == nil || headerValues[i] == nil {
			return map[string][]string{}, errors.New("Missing header key or value")
		}
		key := C.GoString(headerKeys[i])
		value := C.GoString(headerValues[i])
		result[key] = append(result[key], value)
	}

	return result, nil
}

//export HandleProtocolMessage
func HandleProtocolMessage(path *C.char, method *C.char, headers C.struct_HttpHeaders, message *C.char) C.struct_HandleProtocolMessageReturn {
	// Space for result
	var result C.struct_HandleProtocolMessageReturn

	// Check input
	if path == nil || method == nil || message == nil {
		result.status = 500
		result.body = C.CString("")
		result.SessionResult = nil
		return result
	}

	// Extract headers
	headerMap, err := convertHeaders(headers)
	if err != nil {
		result.status = 500
		result.body = C.CString(err.Error())
		result.SessionResult = nil
		return result
	}

	// Prepare return values
	status, body, _, session := s.HandleProtocolMessage(C.GoString(path), C.GoString(method), headerMap, []byte(C.GoString(message)))
	if session == nil {
		result.SessionResult = nil
	} else {
		// Convert SessionResult to JSON for return
		sessionJson, err := json.Marshal(session)
		if err != nil {
			result.status = 500
			result.body = C.CString(err.Error())
			result.SessionResult = nil
			return result
		}
		result.SessionResult = C.CString(string(sessionJson))
	}
	result.status = C.int(status)
	result.body = C.CString(string(body))
	return result
}

// Required to build a shared library
func main() {}
