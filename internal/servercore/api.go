// Package servercore is the core of the IRMA server library, allowing IRMA verifiers, issuers
// or attribute-based signature applications to perform IRMA sessions with irmaclient instances
// (i.e. the IRMA app). It exposes a small interface to expose to other programming languages
// through cgo. It is used by the irmaserver package but otherwise not meant for use in Go.
package servercore

import (
	"net/http"
	"time"

	"github.com/alexandrevicenzi/go-sse"
	"github.com/go-chi/chi"
	"github.com/go-errors/errors"
	"github.com/jasonlvhit/gocron"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

type Server struct {
	conf             *server.Configuration
	sessions         sessionStore
	scheduler        *gocron.Scheduler
	stopScheduler    chan bool
	handlers         map[string]server.SessionHandler
	serverSentEvents *sse.Server
}

func New(conf *server.Configuration, eventServer *sse.Server) (*Server, error) {
	if err := conf.Check(); err != nil {
		return nil, err
	}

	s := &Server{
		conf:      conf,
		scheduler: gocron.NewScheduler(),
		sessions: &memorySessionStore{
			requestor: make(map[string]*session),
			client:    make(map[string]*session),
			conf:      conf,
		},
		handlers:         make(map[string]server.SessionHandler),
		serverSentEvents: eventServer,
	}

	s.scheduler.Every(10).Seconds().Do(func() {
		s.sessions.deleteExpired()
	})

	s.scheduler.Every(irma.RevocationParameters.RequestorUpdateInterval).Seconds().Do(func() {
		for credid, settings := range s.conf.RevocationSettings {
			if settings.Authority {
				continue
			}
			if err := s.conf.IrmaConfiguration.Revocation.SyncIfOld(credid, settings.Tolerance/2); err != nil {
				s.conf.Logger.Errorf("failed to update revocation database for %s", credid.String())
				_ = server.LogError(err)
			}
		}
	})

	s.stopScheduler = s.scheduler.Start()

	return s, nil
}

func (s *Server) Stop() {
	if err := s.conf.IrmaConfiguration.Revocation.Close(); err != nil {
		_ = server.LogWarning(err)
	}
	s.stopScheduler <- true
	s.sessions.stop()
}

func (s *Server) validateRequest(request irma.SessionRequest) error {
	if _, err := s.conf.IrmaConfiguration.Download(request); err != nil {
		return err
	}
	if err := request.Base().Validate(s.conf.IrmaConfiguration); err != nil {
		return err
	}
	return request.Disclosure().Disclose.Validate(s.conf.IrmaConfiguration)
}

func (s *Server) StartSession(req interface{}, handler server.SessionHandler) (*irma.Qr, string, error) {
	rrequest, err := server.ParseSessionRequest(req)
	if err != nil {
		return nil, "", err
	}

	request := rrequest.SessionRequest()
	action := request.Action()

	if err := s.validateRequest(request); err != nil {
		return nil, "", err
	}

	if action == irma.ActionIssuing {
		if err := s.validateIssuanceRequest(request.(*irma.IssuanceRequest)); err != nil {
			return nil, "", err
		}
	}

	session := s.newSession(action, rrequest)
	s.conf.Logger.WithFields(logrus.Fields{"action": action, "session": session.token}).Infof("Session started")
	if s.conf.Logger.IsLevelEnabled(logrus.DebugLevel) {
		s.conf.Logger.WithFields(logrus.Fields{"session": session.token, "clienttoken": session.clientToken}).Info("Session request: ", server.ToJson(rrequest))
	} else {
		s.conf.Logger.WithFields(logrus.Fields{"session": session.token}).Info("Session request (purged of attribute values): ", server.ToJson(purgeRequest(rrequest)))
	}
	if handler != nil {
		s.handlers[session.token] = handler
	}
	return &irma.Qr{
		Type: action,
		URL:  s.conf.URL + "session/" + session.clientToken,
	}, session.token, nil
}

func (s *Server) GetSessionResult(token string) *server.SessionResult {
	session := s.sessions.get(token)
	if session == nil {
		s.conf.Logger.Warn("Session result requested of unknown session ", token)
		return nil
	}
	return session.result
}

func (s *Server) GetRequest(token string) irma.RequestorRequest {
	session := s.sessions.get(token)
	if session == nil {
		s.conf.Logger.Warn("Session request requested of unknown session ", token)
		return nil
	}
	return session.rrequest
}

func (s *Server) CancelSession(token string) error {
	session := s.sessions.get(token)
	if session == nil {
		return server.LogError(errors.Errorf("can't cancel unknown session %s", token))
	}
	session.handleDelete()
	return nil
}

func (s *Server) Revoke(credid irma.CredentialTypeIdentifier, key string, issued time.Time) error {
	return s.conf.IrmaConfiguration.Revocation.Revoke(credid, key, issued)
}

func (s *Server) SubscribeServerSentEvents(w http.ResponseWriter, r *http.Request, token string, requestor bool) error {
	if !s.conf.EnableSSE {
		return errors.New("Server sent events disabled")
	}

	var session *session
	if requestor {
		session = s.sessions.get(token)
	} else {
		session = s.sessions.clientGet(token)
	}
	if session == nil {
		return server.LogError(errors.Errorf("can't subscribe to server sent events of unknown session %s", token))
	}
	if session.status.Finished() {
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
	}()
	s.serverSentEvents.ServeHTTP(w, r)
	return nil
}

type SSECtx struct {
	Component, Arg string
}

func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	if s.conf.Verbose >= 2 {
		r.Use(server.LogMiddleware("client", true, true, false))
	}

	r.Route("/session/{token}", func(r chi.Router) {
		r.Use(s.sessionMiddleware)
		r.Delete("/", s.handleSessionDelete)
		r.Get("/status", s.handleSessionStatus)
		r.Get("/statusevents", s.handleSessionStatusEvents)
		r.Group(func(r chi.Router) {
			r.Use(s.cacheMiddleware)
			r.Get("/", s.handleSessionGet)
			r.Post("/commitments", s.handleSessionCommitments)
			r.Post("/proofs", s.handleSessionProofs)
		})
	})
	r.Post("/session/{name}", s.handleStaticMessage)

	r.Route("/revocation/", func(r chi.Router) {
		r.Get("/events/{id}/{counter:\\d+}/{min:\\d+}/{max:\\d+}", s.handleRevocationGetEvents)
		r.Get("/updateevents/{id}", s.handleRevocationUpdateEvents)
		r.Get("/update/{id}/{count:\\d+}", s.handleRevocationGetUpdateLatest)
		r.Get("/update/{id}/{count:\\d+}/{counter:\\d+}", s.handleRevocationGetUpdateLatest)
		r.Post("/issuancerecord/{id}/{counter:\\d+}", s.handleRevocationPostIssuanceRecord)
	})

	return r
}
