// Package irmaserver is a library that allows IRMA verifiers, issuers or attribute-based signature
// applications to perform IRMA sessions with irmaclient instances (i.e. the IRMA app). It exposes
// functions for handling IRMA sessions and a HTTP handler that handles the sessions with the
// irmaclient.
package irmaserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-co-op/gocron"

	"github.com/privacybydesign/irmago/internal/common"

	"github.com/alexandrevicenzi/go-sse"
	"github.com/go-chi/chi/v5"
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

// AllowIssuingExpiredCredentials indicates whether or not expired credentials can be issued.
var AllowIssuingExpiredCredentials = false

type Server struct {
	conf                   *server.Configuration
	router                 *chi.Mux
	sessions               sessionStore
	scheduler              *gocron.Scheduler
	serverSentEvents       *sse.Server
	activeSSEHandlers      map[irma.RequestorToken]bool
	activeSSEHandlersMutex sync.Mutex
}

// Default server instance
var s *Server

// Initialize the default server instance with the specified configuration using New().
func Initialize(conf *server.Configuration) (err error) {
	s, err = New(conf)
	return
}
func New(conf *server.Configuration) (*Server, error) {
	if err := conf.Check(); err != nil {
		return nil, err
	}

	var e *sse.Server
	if conf.EnableSSE {
		e = eventServer(conf)
	}
	conf.IrmaConfiguration.Revocation.ServerSentEvents = e

	s := &Server{
		conf:              conf,
		scheduler:         gocron.NewScheduler(time.UTC),
		serverSentEvents:  e,
		activeSSEHandlers: make(map[irma.RequestorToken]bool),
	}

	switch conf.StoreType {
	case "":
		fallthrough // no specification defaults to the memory session store
	case "memory":
		s.sessions = &memorySessionStore{
			conf:           conf,
			requestor:      make(map[irma.RequestorToken]*memorySessionData),
			client:         make(map[irma.ClientToken]*memorySessionData),
			statusChannels: make(map[irma.RequestorToken][]chan statusChange),
		}

		if _, err := s.scheduler.Every(10).Seconds().Do(func() {
			s.sessions.(*memorySessionStore).deleteExpired()
		}); err != nil {
			return nil, err
		}
	case "redis":
		cl, err := conf.RedisClient()
		if err != nil {
			return nil, err
		}
		s.sessions = &redisSessionStore{
			client: cl,
			conf:   conf,
		}
	default:
		return nil, errors.New("storeType not known")
	}

	if _, err := s.scheduler.Every(irma.RevocationParameters.RequestorUpdateInterval).Seconds().Do(func() {
		for credid, settings := range s.conf.RevocationSettings {
			if settings.Authority {
				continue
			}
			if err := s.conf.IrmaConfiguration.Revocation.SyncIfOld(credid, settings.Tolerance/2); err != nil {
				s.conf.Logger.Errorf("failed to update revocation database for %s", credid.String())
				_ = server.LogError(err)
			}
		}
	}); err != nil {
		return nil, err
	}

	gocron.SetPanicHandler(server.GocronPanicHandler(s.conf.Logger))
	s.scheduler.StartAsync()

	return s, nil
}

// HandlerFunc returns a http.HandlerFunc that handles the IRMA protocol
// with IRMA apps.
//
// Example usage:
//
//	http.HandleFunc("/irma/", irmaserver.HandlerFunc())
//
// The IRMA app can then perform IRMA sessions at https://example.com/irma.
func HandlerFunc() http.HandlerFunc {
	return s.HandlerFunc()
}
func (s *Server) HandlerFunc() http.HandlerFunc {
	if s.router != nil {
		return s.router.ServeHTTP
	}

	r := chi.NewRouter()
	s.router = r

	r.Use(server.RecoverMiddleware)

	opts := server.LogOptions{Response: true, Headers: true, From: false, EncodeBinary: true}
	r.Use(server.LogMiddleware("client", opts))

	r.Use(server.SizeLimitMiddleware)
	r.Use(server.TimeoutMiddleware([]string{"/statusevents", "/updateevents"}, server.WriteTimeout))

	notfound := &irma.RemoteError{Status: 404, ErrorName: string(server.ErrorInvalidRequest.Type)}
	notallowed := &irma.RemoteError{Status: 405, ErrorName: string(server.ErrorInvalidRequest.Type)}
	r.NotFound(errorWriter(notfound, server.WriteResponse))
	r.MethodNotAllowed(errorWriter(notallowed, server.WriteResponse))

	r.Route("/session/{clientToken}", func(r chi.Router) {
		r.Use(s.sessionMiddleware)
		r.Delete("/", s.handleSessionDelete)
		r.Get("/status", s.handleSessionStatus)
		r.Get("/statusevents", s.handleSessionStatusEvents)
		r.Route("/frontend", func(r chi.Router) {
			r.Use(s.frontendMiddleware)
			r.Get("/status", s.handleFrontendStatus)
			r.Get("/statusevents", s.handleFrontendStatusEvents)
			r.Post("/options", s.handleFrontendOptionsPost)
			r.Post("/pairingcompleted", s.handleFrontendPairingCompleted)
		})
		r.Group(func(r chi.Router) {
			r.Use(s.cacheMiddleware)
			r.Get("/", s.handleSessionGet)
			r.Group(func(r chi.Router) {
				r.Use(s.pairingMiddleware)
				r.Get("/request", s.handleSessionGetRequest)
				r.Post("/commitments", s.handleSessionCommitments)
				r.Post("/proofs", s.handleSessionProofs)
			})
		})
	})
	r.Post("/session/{name}", s.handleStaticMessage)

	r.Route("/revocation/{id}", func(r chi.Router) {
		r.NotFound(errorWriter(notfound, server.WriteBinaryResponse))
		r.MethodNotAllowed(errorWriter(notallowed, server.WriteBinaryResponse))
		r.Get("/events/{counter:\\d+}/{min:\\d+}/{max:\\d+}", s.handleRevocationGetEvents)
		r.Get("/updateevents", s.handleRevocationUpdateEvents)
		r.Get("/update/{count:\\d+}", s.handleRevocationGetUpdateLatest)
		r.Get("/update/{count:\\d+}/{counter:\\d+}", s.handleRevocationGetUpdateLatest)
		r.Post("/issuancerecord/{counter:\\d+}", s.handleRevocationPostIssuanceRecord)
	})

	return s.router.ServeHTTP
}

// Stop the server.
func Stop() {
	s.Stop()
}
func (s *Server) Stop() {
	if err := s.conf.IrmaConfiguration.Revocation.Close(); err != nil {
		_ = server.LogWarning(err)
	}
	s.scheduler.Stop()
	s.sessions.stop()
}

// StartSession starts an IRMA session, running the handler on completion, if specified.
// The session requestorToken (the second return parameter) can be used in GetSessionResult()
// and CancelSession(). The session's frontendAuth (the third return parameter) is needed
// by frontend clients (i.e. browser libraries) to POST to the '/frontend' endpoints of the IRMA protocol.
// The request parameter can be an irma.RequestorRequest, or an irma.SessionRequest, or a
// ([]byte or string) JSON representation of one of those (for more details, see server.ParseSessionRequest().)
func StartSession(request interface{}, handler server.SessionHandler,
) (*irma.Qr, irma.RequestorToken, *irma.FrontendSessionRequest, error) {
	return s.StartSession(request, handler)
}
func (s *Server) StartSession(req interface{}, handler server.SessionHandler,
) (*irma.Qr, irma.RequestorToken, *irma.FrontendSessionRequest, error) {
	return s.startNextSession(req, handler, nil, "")
}
func (s *Server) startNextSession(
	req interface{}, handler server.SessionHandler, disclosed irma.AttributeConDisCon, FrontendAuth irma.FrontendAuthorization,
) (*irma.Qr, irma.RequestorToken, *irma.FrontendSessionRequest, error) {
	if s.conf.StoreType == "redis" && handler != nil {
		return nil, "", nil, errors.New("Handlers cannot be used in combination with Redis.")
	}
	rrequest, err := server.ParseSessionRequest(req)
	if err != nil {
		return nil, "", nil, err
	}

	request := rrequest.SessionRequest()
	action := request.Action()

	if err := s.validateRequest(request); err != nil {
		return nil, "", nil, err
	}
	if action == irma.ActionIssuing {
		// Include the AttributeTypeIdentifiers of random blind attributes to each CredentialRequest.
		// This way, the client can check prematurely, i.e., before the session,
		// if it has the same random blind attributes in it's configuration.
		for _, cred := range request.(*irma.IssuanceRequest).Credentials {
			cred.RandomBlindAttributeTypeIDs = s.conf.IrmaConfiguration.CredentialTypes[cred.CredentialTypeID].RandomBlindAttributeNames()
		}

		if err := s.validateIssuanceRequest(request.(*irma.IssuanceRequest)); err != nil {
			return nil, "", nil, err
		}
	}

	pairingRecommended := false
	if rrequest.Base().NextSession != nil && rrequest.Base().NextSession.URL != "" {
		pairingRecommended = true
	} else if action == irma.ActionDisclosing {
		err := request.Disclosure().Disclose.Iterate(func(attr *irma.AttributeRequest) error {
			if attr.Value != nil {
				pairingRecommended = true
			}
			return nil
		})
		if err != nil {
			return nil, "", nil, err
		}
	} else {
		// For issuing and signing actions, we always recommend pairing.
		pairingRecommended = true
	}

	request.Base().DevelopmentMode = !s.conf.Production
	ses, err := s.newSession(action, rrequest, disclosed, FrontendAuth)
	if err != nil {
		return nil, "", nil, err
	}
	s.conf.Logger.WithFields(logrus.Fields{"action": action, "session": ses.RequestorToken}).Infof("Session started")
	if s.conf.Logger.IsLevelEnabled(logrus.DebugLevel) {
		s.conf.Logger.
			WithFields(logrus.Fields{"session": ses.RequestorToken, "clienttoken": ses.ClientToken}).
			Info("Session request: ", server.ToJson(rrequest))
	} else {
		s.conf.Logger.
			WithFields(logrus.Fields{"session": ses.RequestorToken}).
			Info("Session request (purged of attribute values): ", server.ToJson(purgeRequest(rrequest)))
	}

	if handler != nil {
		go func() {
			statusChangeChan, err := s.sessions.subscribeStatusChanges(ses.RequestorToken)
			if err != nil {
				s.conf.Logger.WithError(err).Error("Failed to subscribe to session status changes for handler")
				return
			}
			for change := range statusChangeChan {
				if change.Status.Finished() {
					s.sessions.transaction(ses.RequestorToken, func(ses *sessionData) error {
						handler(ses.Result)
						return nil
					})
					return
				}
			}
		}()
	}

	url, err := url.Parse(s.conf.URL)
	if err != nil {
		return nil, "", nil, err
	}
	url = url.JoinPath("session", string(ses.ClientToken))
	if request.Base().Host != "" {
		url.Host = request.Base().Host
	}

	return &irma.Qr{
			Type: action,
			URL:  url.String(),
		},
		ses.RequestorToken,
		&irma.FrontendSessionRequest{
			Authorization:      ses.FrontendAuth,
			PairingRecommended: pairingRecommended,
			MinProtocolVersion: minFrontendProtocolVersion,
			MaxProtocolVersion: maxFrontendProtocolVersion,
		},
		nil
}

// GetSessionResult retrieves the result of the specified IRMA session.
func GetSessionResult(requestorToken irma.RequestorToken) (*server.SessionResult, error) {
	return s.GetSessionResult(requestorToken)
}
func (s *Server) GetSessionResult(requestorToken irma.RequestorToken) (res *server.SessionResult, err error) {
	err = s.sessions.transaction(requestorToken, func(session *sessionData) error {
		res = session.Result
		return nil
	})
	return
}

// GetRequest retrieves the request submitted by the requestor that started the specified IRMA session.
func GetRequest(requestorToken irma.RequestorToken) (irma.RequestorRequest, error) {
	return s.GetRequest(requestorToken)
}
func (s *Server) GetRequest(requestorToken irma.RequestorToken) (req irma.RequestorRequest, err error) {
	err = s.sessions.transaction(requestorToken, func(session *sessionData) error {
		req = session.Rrequest
		return nil
	})
	return
}

// CancelSession cancels the specified IRMA session.
func CancelSession(requestorToken irma.RequestorToken) error {
	return s.CancelSession(requestorToken)
}
func (s *Server) CancelSession(requestorToken irma.RequestorToken) (err error) {
	err = s.sessions.transaction(requestorToken, func(session *sessionData) error {
		session.handleDelete(s.conf)
		return nil
	})
	return
}

// SetFrontendOptions requests a change of the session frontend options at the server.
// Returns the updated session options struct. Frontend options can only be
// changed when the client is not connected yet. Otherwise an error is returned.
// Options that are not specified in the request, keep their old value.
func SetFrontendOptions(requestorToken irma.RequestorToken, request *irma.FrontendOptionsRequest) (*irma.SessionOptions, error) {
	return s.SetFrontendOptions(requestorToken, request)
}
func (s *Server) SetFrontendOptions(requestorToken irma.RequestorToken, request *irma.FrontendOptionsRequest) (o *irma.SessionOptions, err error) {
	err = s.sessions.transaction(requestorToken, func(session *sessionData) error {
		o, err = session.updateFrontendOptions(request)
		return err
	})
	return
}

// PairingCompleted completes pairing between the irma client and the frontend. Returns
// an error when no client is actually connected.
func PairingCompleted(requestorToken irma.RequestorToken) error {
	return s.PairingCompleted(requestorToken)
}
func (s *Server) PairingCompleted(requestorToken irma.RequestorToken) error {
	return s.sessions.transaction(requestorToken, func(session *sessionData) error {
		return session.pairingCompleted(s.conf)
	})
}

// Revoke revokes the earlier issued credential specified by key. (Can only be used if this server
// is the revocation server for the specified credential type and if the corresponding
// issuer private key is present in the server configuration.)
func Revoke(credid irma.CredentialTypeIdentifier, key string, issued time.Time) error {
	return s.Revoke(credid, key, issued)
}
func (s *Server) Revoke(credid irma.CredentialTypeIdentifier, key string, issued time.Time) error {
	return s.conf.IrmaConfiguration.Revocation.Revoke(credid, key, issued)
}

// SubscribeServerSentEvents subscribes the HTTP client to server sent events on status updates
// of the specified IRMA session.
func (s *Server) SubscribeServerSentEvents(w http.ResponseWriter, r *http.Request, token irma.RequestorToken) error {
	r = r.WithContext(context.WithValue(r.Context(), "sse", common.SSECtx{
		Component: server.ComponentSession,
		Arg:       string(token),
	}))
	return s.sessions.transaction(token, func(session *sessionData) error {
		return s.subscribeServerSentEvents(w, r, session, true)
	})
}

func (s *Server) subscribeServerSentEvents(w http.ResponseWriter, r *http.Request, session *sessionData, requestor bool) error {
	if !s.conf.EnableSSE {
		server.WriteResponse(w, nil, &irma.RemoteError{
			Status:      http.StatusInternalServerError,
			Description: "Server sent events disabled",
			ErrorName:   "SSE_DISABLED",
		})
		s.conf.Logger.Info("GET /statusevents: endpoint disabled (see --sse in irma server -h)")
		return nil
	}

	if session.Status.Finished() {
		server.WriteError(w, server.ErrorUnexpectedRequest, "Can't subscribe to server sent events of finished session")
		return nil
	}

	activeHandler := false
	s.activeSSEHandlersMutex.Lock()
	if active := s.activeSSEHandlers[session.RequestorToken]; active {
		activeHandler = true
	} else {
		s.activeSSEHandlers[session.RequestorToken] = true
	}
	s.activeSSEHandlersMutex.Unlock()

	if !activeHandler {
		statusChangeChan, err := s.sessions.subscribeStatusChanges(session.RequestorToken)
		if err != nil {
			return err
		}
		go func() {
			s.serverSentEventsHandler(session, statusChangeChan)
			s.activeSSEHandlersMutex.Lock()
			defer s.activeSSEHandlersMutex.Unlock()
			delete(s.activeSSEHandlers, session.RequestorToken)
		}()
	}

	// The EventSource.onopen Javascript callback is not consistently called across browsers (Chrome yes, Firefox+Safari no).
	// However, when the SSE connection has been opened the webclient needs some signal so that it can early detect SSE failures.
	// So we manually send an "open" event. Unfortunately:
	// - we need to give the webclient that connected just now some time, otherwise it will miss the "open" event
	// - the "open" event also goes to all other webclients currently listening, as we have no way to send this
	//   event to just the webclient currently listening. (Thus the handler of this "open" event must be idempotent.)
	go func() {
		time.Sleep(200 * time.Millisecond)
		token := string(session.ClientToken)
		if requestor {
			token = string(session.RequestorToken)
		}
		s.serverSentEvents.SendMessage("session/"+token, sse.NewMessage("", "", "open"))
		s.serverSentEvents.SendMessage("frontendsession/"+token, sse.NewMessage("", "", "open"))
	}()

	s.serverSentEvents.ServeHTTP(w, r)
	return nil
}

func (s *Server) serverSentEventsHandler(session *sessionData, statusChangeChan chan statusChange) {
	timeoutTime := time.Now().Add(session.timeout(s.conf))

	// Close the channels when this function returns.
	defer func() {
		s.serverSentEvents.CloseChannel("session/" + string(session.RequestorToken))
		s.serverSentEvents.CloseChannel("session/" + string(session.ClientToken))
		s.serverSentEvents.CloseChannel("frontendsession/" + string(session.ClientToken))
	}()

	for {
		select {
		case change, ok := <-statusChangeChan:
			if !ok {
				return
			}

			frontendStatusBytes, err := json.Marshal(change.FrontendSessionStatus)
			if err != nil {
				s.conf.Logger.Error(err)
				return
			}

			s.serverSentEvents.SendMessage("session/"+string(session.RequestorToken),
				sse.SimpleMessage(fmt.Sprintf(`"%s"`, change.Status)),
			)
			s.serverSentEvents.SendMessage("session/"+string(session.ClientToken),
				sse.SimpleMessage(fmt.Sprintf(`"%s"`, change.Status)),
			)
			s.serverSentEvents.SendMessage("frontendsession/"+string(session.ClientToken),
				sse.SimpleMessage(string(frontendStatusBytes)),
			)
			if change.Status.Finished() {
				return
			}
			timeoutTime = time.Now().Add(change.Timeout)
		case <-time.After(time.Until(timeoutTime)):
			frontendStatus := irma.FrontendSessionStatus{
				Status: irma.ServerStatusTimeout,
			}
			frontendStatusBytes, err := json.Marshal(frontendStatus)
			if err != nil {
				s.conf.Logger.Error(err)
				return
			}

			s.serverSentEvents.SendMessage("session/"+string(session.RequestorToken),
				sse.SimpleMessage(fmt.Sprintf(`"%s"`, frontendStatus.Status)),
			)
			s.serverSentEvents.SendMessage("session/"+string(session.ClientToken),
				sse.SimpleMessage(fmt.Sprintf(`"%s"`, frontendStatus.Status)),
			)
			s.serverSentEvents.SendMessage("frontendsession/"+string(session.ClientToken),
				sse.SimpleMessage(string(frontendStatusBytes)),
			)
			return
		}
	}
}

// SessionStatus retrieves a channel on which the current session status of the specified
// IRMA session can be retrieved.
func SessionStatus(requestorToken irma.RequestorToken) (chan irma.ServerStatus, error) {
	return s.SessionStatus(requestorToken)
}
func (s *Server) SessionStatus(requestorToken irma.RequestorToken) (statusChan chan irma.ServerStatus, err error) {
	if s.conf.StoreType != "memory" {
		return nil, errors.New("SessionStatus cannot be used in combination with Redis/etcd.")
	}

	statusChangeChan, err := s.sessions.subscribeStatusChanges(requestorToken)
	if err != nil {
		return nil, err
	}
	var timeoutTime time.Time
	s.sessions.transaction(requestorToken, func(session *sessionData) error {
		timeoutTime = time.Now().Add(session.timeout(s.conf))
		return nil
	})

	statusChan = make(chan irma.ServerStatus, 4)
	go func() {
		for {
			select {
			case change, ok := <-statusChangeChan:
				if !ok {
					close(statusChan)
					return
				}
				statusChan <- change.Status

				if change.Status.Finished() {
					close(statusChan)
					return
				}
				timeoutTime = time.Now().Add(change.Timeout)
			case <-time.After(time.Until(timeoutTime)):
				statusChan <- irma.ServerStatusTimeout
				close(statusChan)
				return
			}
		}
	}()

	return statusChan, nil
}
