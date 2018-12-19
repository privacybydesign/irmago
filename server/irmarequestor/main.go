package irmarequestor

import (
	"io/ioutil"
	"net/http"

	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/backend"
)

// SessionHandler is a function that can handle a session result
// once an IRMA session has completed.
type SessionHandler func(*server.SessionResult)

var handlers = make(map[string]SessionHandler)

// Initialize sets configuration.
func Initialize(configuration *server.Configuration) error {
	return backend.Initialize(configuration)
}

// StartSession starts an IRMA session, running the handler on completion, if specified.
// The session token (the second return parameter) can be used in GetSessionResult()
// and CancelSession().
func StartSession(request irma.SessionRequest, handler SessionHandler) (*irma.Qr, string, error) {
	qr, token, err := backend.StartSession(request)
	if err != nil {
		return nil, "", err
	}
	if handler != nil {
		handlers[token] = handler
	}
	return qr, token, nil
}

// GetSessionResult retrieves the result of the specified IRMA session.
func GetSessionResult(token string) *server.SessionResult {
	return backend.GetSessionResult(token)
}

// CancelSession cancels the specified IRMA session.
func CancelSession(token string) error {
	return backend.CancelSession(token)
}

// HttpHandlerFunc returns a http.HandlerFunc that handles the IRMA protocol
// with IRMA apps. Initialize() must be called before this.
//
// Example usage:
//   http.HandleFunc("/irma/", irmarequestor.HttpHandlerFunc())
//
// The IRMA app can then perform IRMA sessions at https://example.com/irma.
func HttpHandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var message []byte
		message, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		status, response, result := backend.HandleProtocolMessage(r.URL.Path, r.Method, r.Header, message)
		w.WriteHeader(status)
		w.Write(response)
		if result != nil {
			if handler, ok := handlers[result.Token]; ok {
				go handler(result)
			}
		}
	}
}
