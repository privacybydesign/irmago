// Package irmaserver is a library that allows IRMA verifiers, issuers or attribute-based signature
// applications to perform IRMA sessions with irmaclient instances (i.e. the IRMA app). It exposes
// functions for handling IRMA sessions and a HTTP handler that handles the sessions with the
// irmaclient.
package irmaserver

import (
	"io/ioutil"
	"net/http"

	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/servercore"
	"github.com/privacybydesign/irmago/server"
)

// Server is an irmaserver instance.
type Server struct {
	*servercore.Server
	handlers map[string]SessionHandler
}

// SessionHandler is a function that can handle a session result
// once an IRMA session has completed.
type SessionHandler func(*server.SessionResult)

// Default server instance
var s *Server

// Initialize the default server instance with the specified configuration using New().
func Initialize(conf *server.Configuration) (err error) {
	s, err = New(conf)
	return
}

// New creates a new Server instance with the specified configuration.
func New(conf *server.Configuration) (*Server, error) {
	s, err := servercore.New(conf)
	if err != nil {
		return nil, err
	}
	return &Server{
		Server:   s,
		handlers: make(map[string]SessionHandler),
	}, nil
}

// StartSession starts an IRMA session, running the handler on completion, if specified.
// The session token (the second return parameter) can be used in GetSessionResult()
// and CancelSession().
func StartSession(request interface{}, handler SessionHandler) (*irma.Qr, string, error) {
	return s.StartSession(request, handler)
}
func (s *Server) StartSession(request interface{}, handler SessionHandler) (*irma.Qr, string, error) {
	qr, token, err := s.Server.StartSession(request)
	if err != nil {
		return nil, "", err
	}
	if handler != nil {
		s.handlers[token] = handler
	}
	return qr, token, nil
}

// GetSessionResult retrieves the result of the specified IRMA session.
func GetSessionResult(token string) *server.SessionResult {
	return s.GetSessionResult(token)
}
func (s *Server) GetSessionResult(token string) *server.SessionResult {
	return s.Server.GetSessionResult(token)
}

// GetRequest retrieves the request submitted by the requestor that started the specified IRMA session.
func GetRequest(token string) irma.RequestorRequest {
	return s.GetRequest(token)
}
func (s *Server) GetRequest(token string) irma.RequestorRequest {
	return s.Server.GetRequest(token)
}

// CancelSession cancels the specified IRMA session.
func CancelSession(token string) error {
	return s.CancelSession(token)
}
func (s *Server) CancelSession(token string) error {
	return s.Server.CancelSession(token)
}

// SubscribeServerSentEvents subscribes the HTTP client to server sent events on status updates
// of the specified IRMA session.
func SubscribeServerSentEvents(w http.ResponseWriter, r *http.Request, token string) error {
	return s.SubscribeServerSentEvents(w, r, token)
}
func (s *Server) SubscribeServerSentEvents(w http.ResponseWriter, r *http.Request, token string) error {
	return s.Server.SubscribeServerSentEvents(w, r, token)
}

// HandlerFunc returns a http.HandlerFunc that handles the IRMA protocol
// with IRMA apps.
//
// Example usage:
//   http.HandleFunc("/irma/", irmaserver.HandlerFunc())
//
// The IRMA app can then perform IRMA sessions at https://example.com/irma.
func HandlerFunc() http.HandlerFunc {
	return s.HandlerFunc()
}
func (s *Server) HandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var message []byte
		var err error
		if r.Method == http.MethodPost {
			if message, err = ioutil.ReadAll(r.Body); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		token, noun, err := servercore.ParsePath(r.URL.Path)
		if err == nil && noun == "statusevents" { // if err != nil we let it be handled by HandleProtocolMessage below
			if err = s.SubscribeServerSentEvents(w, r, token); err != nil {
				server.WriteError(w, server.ErrorUnexpectedRequest, err.Error())
			}
			return
		}

		status, response, result := s.HandleProtocolMessage(r.URL.Path, r.Method, r.Header, message)
		w.WriteHeader(status)
		_, err = w.Write(response)
		if err != nil {
			_ = server.LogError(errors.WrapPrefix(err, "http.ResponseWriter.Write() returned error", 0))
		}
		if result != nil && result.Status.Finished() {
			if handler := s.handlers[result.Token]; handler != nil {
				go handler(result)
			}
		}
	}
}
