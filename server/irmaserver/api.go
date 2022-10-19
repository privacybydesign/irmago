// Package irmaserver is a library that allows IRMA verifiers, issuers or attribute-based signature
// applications to perform IRMA sessions with irmaclient instances (i.e. the IRMA app). It exposes
// functions for handling IRMA sessions and a HTTP handler that handles the sessions with the
// irmaclient.
package irmaserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"

	"github.com/go-co-op/gocron"

	"github.com/bsm/redislock"
	"github.com/go-redis/redis/v8"
	"github.com/privacybydesign/irmago/internal/common"

	"github.com/alexandrevicenzi/go-sse"
	"github.com/go-chi/chi/v5"
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

type Server struct {
	conf             *server.Configuration
	router           *chi.Mux
	sessions         sessionStore
	scheduler        *gocron.Scheduler
	serverSentEvents *sse.Server
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
		conf:             conf,
		scheduler:        gocron.NewScheduler(time.UTC),
		serverSentEvents: e,
	}

	switch conf.StoreType {
	case "":
		fallthrough // no specification defaults to the memory session store
	case "memory":
		s.sessions = &memorySessionStore{
			requestor: make(map[irma.RequestorToken]*session),
			client:    make(map[irma.ClientToken]*session),
			conf:      conf,
		}

		if _, err := s.scheduler.Every(10).Seconds().Do(func() {
			s.sessions.(*memorySessionStore).deleteExpired()
		}); err != nil {
			return nil, err
		}
	case "redis":
		// Configure Redis TLS. If Redis TLS is disabled, tlsConfig becomes nil and the redis client will not use TLS.
		tlsConfig, err := redisTLSConfig(conf)
		if err != nil {
			return nil, err
		}

		// setup client
		cl := redis.NewClient(&redis.Options{
			Addr:      conf.RedisSettings.Addr,
			Password:  conf.RedisSettings.Password,
			DB:        conf.RedisSettings.DB,
			TLSConfig: tlsConfig,
		})
		if err := cl.Ping(context.Background()).Err(); err != nil {
			return nil, errors.WrapPrefix(err, "failed to connect to Redis", 0)
		}

		s.sessions = &redisSessionStore{
			client: cl,
			conf:   conf,
			locker: redislock.New(cl),
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

	s.scheduler.StartAsync()

	return s, nil
}

func redisTLSConfig(conf *server.Configuration) (*tls.Config, error) {
	if conf.RedisSettings.DisableTLS {
		if conf.RedisSettings.TLSCertificate != "" || conf.RedisSettings.TLSCertificateFile != "" {
			err := errors.New("Redis TLS cannot be disabled when a Redis TLS certificate is specified.")
			return nil, errors.WrapPrefix(err, "Redis TLS config failed", 0)
		}
		return nil, nil
	}

	if conf.RedisSettings.TLSCertificate != "" || conf.RedisSettings.TLSCertificateFile != "" {
		cert, err := common.ReadKey(conf.RedisSettings.TLSCertificate, conf.RedisSettings.TLSCertificateFile)
		if err != nil {
			return nil, errors.WrapPrefix(err, "Redis TLS config failed", 0)
		}
		tlsConfig := &tls.Config{
			RootCAs: x509.NewCertPool(),
		}
		tlsConfig.RootCAs.AppendCertsFromPEM(cert)
		return tlsConfig, nil
	}

	// By default, the certificate pool of the system is used
	systemCerts, err := x509.SystemCertPool()
	if err != nil {
		return nil, errors.WrapPrefix(err, "Redis TLS config failed", 0)
	}
	tlsConfig := &tls.Config{
		RootCAs: systemCerts,
	}
	return tlsConfig, nil
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
	session, err := s.newSession(action, rrequest, disclosed, FrontendAuth)
	if err != nil {
		return nil, "", nil, err
	}
	s.conf.Logger.WithFields(logrus.Fields{"action": action, "session": session.RequestorToken}).Infof("Session started")
	if s.conf.Logger.IsLevelEnabled(logrus.DebugLevel) {
		s.conf.Logger.
			WithFields(logrus.Fields{"session": session.RequestorToken, "clienttoken": session.ClientToken}).
			Info("Session request: ", server.ToJson(rrequest))
	} else {
		s.conf.Logger.
			WithFields(logrus.Fields{"session": session.RequestorToken}).
			Info("Session request (purged of attribute values): ", server.ToJson(purgeRequest(rrequest)))
	}
	session.handler = handler
	return &irma.Qr{
			Type: action,
			URL:  s.conf.URL + "session/" + string(session.ClientToken),
		},
		session.RequestorToken,
		&irma.FrontendSessionRequest{
			Authorization:      session.FrontendAuth,
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
	session, err := s.sessions.get(requestorToken)
	defer func() { err = updateAndUnlock(session, err) }()
	if err != nil {
		return
	}

	res = session.Result
	return
}

// GetRequest retrieves the request submitted by the requestor that started the specified IRMA session.
func GetRequest(requestorToken irma.RequestorToken) (irma.RequestorRequest, error) {
	return s.GetRequest(requestorToken)
}
func (s *Server) GetRequest(requestorToken irma.RequestorToken) (req irma.RequestorRequest, err error) {
	session, err := s.sessions.get(requestorToken)
	defer func() { err = updateAndUnlock(session, err) }()
	if err != nil {
		return
	}

	req = session.Rrequest
	return
}

// CancelSession cancels the specified IRMA session.
func CancelSession(requestorToken irma.RequestorToken) error {
	return s.CancelSession(requestorToken)
}
func (s *Server) CancelSession(requestorToken irma.RequestorToken) (err error) {
	session, err := s.sessions.get(requestorToken)
	defer func() { err = updateAndUnlock(session, err) }()
	if err != nil {
		return
	}

	session.handleDelete()
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
	session, err := s.sessions.get(requestorToken)
	defer func() { err = updateAndUnlock(session, err) }()
	if err != nil {
		return
	}
	o, err = session.updateFrontendOptions(request)

	return
}

// PairingCompleted completes pairing between the irma client and the frontend. Returns
// an error when no client is actually connected.
func PairingCompleted(requestorToken irma.RequestorToken) error {
	return s.PairingCompleted(requestorToken)
}
func (s *Server) PairingCompleted(requestorToken irma.RequestorToken) (err error) {
	session, err := s.sessions.get(requestorToken)
	defer func() { err = updateAndUnlock(session, err) }()
	if err != nil {
		return
	}

	err = session.pairingCompleted()
	return
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
func (s *Server) SubscribeServerSentEvents(w http.ResponseWriter, r *http.Request, token irma.RequestorToken) (err error) {
	if !s.conf.EnableSSE {
		server.WriteResponse(w, nil, &irma.RemoteError{
			Status:      500,
			Description: "Server sent events disabled",
			ErrorName:   "SSE_DISABLED",
		})
		s.conf.Logger.Info("GET /statusevents: endpoint disabled (see --sse in irma server -h)")
		return nil
	}
	session, err := s.sessions.get(token)
	err = updateAndUnlock(session, err)
	if err != nil {
		if _, ok := err.(*RedisError); ok {
			// In no flow, you should end up with an storeError. If you do, be alarmed!
			// Only the Redis session store implementation actively uses these errors. As the Redis session store
			// currently cannot be used in combination with SSE, there should be no storeError here.
			// Furthermore, the specific storeError is already logged in `session.go` and does not have
			// to be logged again.
			err = server.LogError(errors.Errorf("unexpectedly triggered error when trying to receive session %s", token))
			return
		} else {
			return
		}
	}

	err = s.subscribeServerSentEvents(w, r, session, true)
	return
}

func (s *Server) subscribeServerSentEvents(w http.ResponseWriter, r *http.Request, session *session, requestor bool) error {
	if !s.conf.EnableSSE {
		server.WriteResponse(w, nil, &irma.RemoteError{
			Status:      500,
			Description: "Server sent events disabled",
			ErrorName:   "SSE_DISABLED",
		})
		s.conf.Logger.Info("GET /statusevents: endpoint disabled (see --sse in irma server -h)")
		return nil
	}

	var token string
	if requestor {
		token = string(session.RequestorToken)
	} else {
		token = string(session.ClientToken)
	}

	if session.Status.Finished() {
		return server.LogError(errors.Errorf("can't subscribe to server sent events of finished session %s", token))
	}

	// The EventSource.onopen Javascript callback is not consistently called across browsers (Chrome yes, Firefox+Safari no).
	// However, when the SSE connection has been opened the webclient needs some signal so that it can early detect SSE failures.
	// So we manually send an "open" event. Unfortunately:
	// - we need to give the webclient that connected just now some time, otherwise it will miss the "open" event
	// - the "open" event also goes to all other webclients currently listening, as we have no way to send this
	//   event to just the webclient currently listening. (Thus the handler of this "open" event must be idempotent.)
	go func() {
		time.Sleep(200 * time.Millisecond)
		s.serverSentEvents.SendMessage("session/"+token, sse.NewMessage("", "", "open"))
		s.serverSentEvents.SendMessage("frontendsession/"+token, sse.NewMessage("", "", "open"))
	}()
	s.serverSentEvents.ServeHTTP(w, r)
	return nil
}

// SessionStatus retrieves a channel on which the current session status of the specified
// IRMA session can be retrieved.
func SessionStatus(requestorToken irma.RequestorToken) (chan irma.ServerStatus, error) {
	return s.SessionStatus(requestorToken)
}
func (s *Server) SessionStatus(requestorToken irma.RequestorToken) (statusChan chan irma.ServerStatus, err error) {
	if s.conf.StoreType == "redis" {
		return nil, errors.New("SessionStatus cannot be used in combination with Redis.")
	}

	session, err := s.sessions.get(requestorToken)
	err = updateAndUnlock(session, err)
	if err != nil {
		return
	}

	statusChan = make(chan irma.ServerStatus, 4)
	statusChan <- session.Status
	session.statusChannels = append(session.statusChannels, statusChan)
	return
}

// updateAndUnlock is a helper function that is mainly used in defer functions to make sure a session
// is updated and unlocked eventually. Each session gets locked automatically in the session store's
// `get` and `getClient` methods.
// If the passed error is not nil it is always returned, as this first error is more important for
// the eventual response. Otherwise, the return value of ses.updateAndUnlock() is returned.
func updateAndUnlock(ses *session, err error) error {
	if ses == nil {
		return err
	}
	e := ses.updateAndUnlock()
	if err != nil {
		return err
	}
	return e
}
