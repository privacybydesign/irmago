// Package irmaserver is a library that allows IRMA verifiers, issuers or attribute-based signature
// applications to perform IRMA sessions with irmaclient instances (i.e. the IRMA app). It exposes
// functions for handling IRMA sessions and a HTTP handler that handles the sessions with the
// irmaclient.
package irmaserver

import (
	"log"
	"net/http"
	"time"

	"github.com/alexandrevicenzi/go-sse"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/servercore"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

// Server is an irmaserver instance.
type Server struct {
	*servercore.Server
	conf             *server.Configuration
	serverSentEvents *sse.Server
}

// Default server instance
var s *Server

// Initialize the default server instance with the specified configuration using New().
func Initialize(conf *server.Configuration) (err error) {
	s, err = New(conf)
	return
}

// New creates a new Server instance with the specified configuration.
func New(conf *server.Configuration) (*Server, error) {
	var e *sse.Server
	if conf.EnableSSE {
		e = eventServer(conf)
	}

	s, err := servercore.New(conf, e)
	if err != nil {
		return nil, err
	}

	conf.IrmaConfiguration.Revocation.ServerSentEvents = e
	return &Server{
		Server:           s,
		conf:             conf,
		serverSentEvents: e,
	}, nil
}

// Stop the server.
func Stop() {
	s.Stop()
}

// StartSession starts an IRMA session, running the handler on completion, if specified.
// The session token (the second return parameter) can be used in GetSessionResult()
// and CancelSession().
// The request parameter can be an irma.RequestorRequest, or an irma.SessionRequest, or a
// ([]byte or string) JSON representation of one of those (for more details, see server.ParseSessionRequest().)
func StartSession(request interface{}, handler server.SessionHandler) (*irma.Qr, string, error) {
	return s.StartSession(request, handler)
}

// GetSessionResult retrieves the result of the specified IRMA session.
func GetSessionResult(token string) *server.SessionResult {
	return s.GetSessionResult(token)
}

// GetRequest retrieves the request submitted by the requestor that started the specified IRMA session.
func GetRequest(token string) irma.RequestorRequest {
	return s.GetRequest(token)
}

// CancelSession cancels the specified IRMA session.
func CancelSession(token string) error {
	return s.CancelSession(token)
}

// Revoke revokes the earlier issued credential specified by key. (Can only be used if this server
// is the revocation server for the specified credential type and if the corresponding
// issuer private key is present in the server configuration.)
func Revoke(credid irma.CredentialTypeIdentifier, key string, issued time.Time) error {
	return s.Revoke(credid, key, issued)
}

// SubscribeServerSentEvents subscribes the HTTP client to server sent events on status updates
// of the specified IRMA session.
func SubscribeServerSentEvents(w http.ResponseWriter, r *http.Request, token string, requestor bool) error {
	return s.SubscribeServerSentEvents(w, r, token, requestor)
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
	return s.Handler().ServeHTTP
}

func eventServer(conf *server.Configuration) *sse.Server {
	return sse.NewServer(&sse.Options{
		ChannelNameFunc: func(r *http.Request) string {
			sseCtx := r.Context().Value("sse")
			if sseCtx == nil {
				return ""
			}
			switch sseCtx.(servercore.SSECtx).Component {
			case server.ComponentSession:
				return "session/" + sseCtx.(servercore.SSECtx).Arg
			case server.ComponentRevocation:
				return "revocation/" + sseCtx.(servercore.SSECtx).Arg
			default:
				return ""
			}
		},
		Headers: map[string]string{
			"Access-Control-Allow-Origin":  "*",
			"Access-Control-Allow-Methods": "GET, OPTIONS",
			"Access-Control-Allow-Headers": "Keep-Alive,X-Requested-With,Cache-Control,Content-Type,Last-Event-ID",
		},
		Logger: log.New(conf.Logger.WithField("type", "sse").WriterLevel(logrus.DebugLevel), "", 0),
	})
}
