// Required to be main when building a shared library
package main

import "C"

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	irma "github.com/privacybydesign/irmago"
	"io/ioutil"
	"net/http"
	"net/http/httptest"

	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

var s *irmaserver.Server

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
	if conf.EnableSSE {
		return C.CString("SSE is not supported")
	}

	// Run the actual core function
	s, err = irmaserver.New(conf)

	// And properly return any errors
	if err == nil {
		return nil
	} else {
		return C.CString(err.Error())
	}
}

//export StartSession
func StartSession(requestString *C.char) (r *C.char) {
	// Create struct for return information
	result := struct {
		IrmaQr         string
		RequestorToken string
		FrontendToken  string
		Error          string
	}{}
	defer func() {
		j, _ := json.Marshal(result)
		r = C.CString(string(j))
	}()

	// Check that we have required input
	if requestString == nil {
		result.Error = "Missing request string."
		return
	}

	// Run the actual core function
	qr, requestorToken, frontendToken, err := s.StartSession(C.GoString(requestString), nil)

	// And properly return the result
	if err != nil {
		result.Error = err.Error() // return the core error
		return
	}
	qrJson, err := json.Marshal(qr)
	if err != nil {
		result.Error = err.Error() // return encoding error
		return
	}
	// return actual results
	result.IrmaQr = string(qrJson)
	result.RequestorToken = string(requestorToken)
	result.FrontendToken = string(frontendToken)
	return
}

//export GetSessionResult
func GetSessionResult(token *C.char) *C.char {
	// Check that we have required input
	if token == nil {
		return nil
	}

	// Run the actual core function
	result := s.GetSessionResult(irma.RequestorToken(C.GoString(token)))

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
	result := s.GetRequest(irma.RequestorToken(C.GoString(token)))

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
	err := s.CancelSession(irma.RequestorToken(C.GoString(token)))

	if err != nil {
		return C.CString(err.Error())
	}
	return nil
}

//export HandleProtocolMessage
func HandleProtocolMessage(path *C.char, method *C.char, headers *C.char, message *C.char) (r *C.char) {
	// Space for result
	result := struct {
		Status        int
		Body          string
		Headers       map[string][]string
		SessionResult *server.SessionResult
	}{}
	defer func() {
		j, _ := json.Marshal(result)
		r = C.CString(string(j))
	}()

	// Check input
	if path == nil || method == nil || message == nil {
		result.Status = 500
		return
	}

	// Extract headers
	var headerMap map[string][]string
	err := json.Unmarshal([]byte(C.GoString(headers)), &headerMap)
	if err != nil {
		result.Status = 500
		result.Body = err.Error()
		return
	}

	// Prepare return values
	status, body, returnheaders, sesresult, err := handle(C.GoString(path), C.GoString(method), headerMap, []byte(C.GoString(message)))

	if err != nil {
		result.Status = 500
		result.Body = err.Error()
		return
	}

	if returnheaders.Get("Content-Type") != "application/json" {
		body = []byte(base64.StdEncoding.EncodeToString(body))
	}

	result.Status = status
	result.Body = string(body)
	result.Headers = returnheaders
	result.SessionResult = sesresult

	return
}

func handle(
	url string,
	method string,
	headers map[string][]string,
	message []byte,
) (int, []byte, http.Header, *server.SessionResult, error) {
	// construct request
	r := httptest.NewRequest(method, url, bytes.NewReader(message))
	for key, hs := range headers {
		for _, h := range hs {
			r.Header.Add(key, h)
		}
	}
	result := &server.SessionResult{}
	ctx := context.WithValue(r.Context(), "sessionresult", result)

	// perform request
	w := httptest.NewRecorder()
	s.HandlerFunc().ServeHTTP(w, r.WithContext(ctx))

	// read response body
	b, err := ioutil.ReadAll(w.Result().Body)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	if result.Token == "" {
		result = nil
	}
	return w.Code, b, w.Header(), result, nil
}

// Required to build a shared library
func main() {}
