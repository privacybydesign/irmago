package myirmaserver

import (
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/jasonlvhit/gocron"
	"github.com/privacybydesign/irmago/server"

	irma "github.com/privacybydesign/irmago"

	"github.com/privacybydesign/irmago/server/irmaserver"
)

type Server struct {
	conf *Configuration

	sessionserver *irmaserver.Server
	store         SessionStore
	db            MyirmaDB
	scheduler     *gocron.Scheduler
	schedulerStop chan<- bool
}

func New(conf *Configuration) (*Server, error) {
	err := processConfiguration(conf)
	if err != nil {
		return nil, err
	}

	sessionserver, err := irmaserver.New(conf.ServerConfiguration)
	if err != nil {
		return nil, err
	}
	s := &Server{
		conf:          conf,
		sessionserver: sessionserver,
		store:         NewMemorySessionStore(time.Duration(conf.SessionLifetime) * time.Second),
		db:            conf.DB,
		scheduler:     gocron.NewScheduler(),
	}

	s.scheduler.Every(10).Seconds().Do(s.store.flush)
	s.schedulerStop = s.scheduler.Start()

	return s, nil
}

func (s *Server) Stop() {
	s.sessionserver.Stop()
	s.schedulerStop <- true
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Post("/checksession", s.handleCheckSession)
	router.Post("/login/irma", s.handleIrmaLogin)
	router.Mount("/irma/", s.sessionserver.HandlerFunc())

	if s.conf.StaticPath != "" {
		router.Mount(s.conf.StaticPrefix, s.StaticFilesHandler())
	}
	return router
}

func (s *Server) handleCheckSession(w http.ResponseWriter, r *http.Request) {
	token, err := r.Cookie("session")
	if err != nil {
		server.WriteString(w, "expired")
		return
	}

	session := s.store.get(token.Value)
	if session == nil {
		server.WriteString(w, "expired")
		return
	}

	session.Lock()
	defer session.Unlock()
	if session.pendingError != nil {
		server.WriteError(w, *session.pendingError, session.pendingErrorMessage)
		session.pendingError = nil
		session.pendingErrorMessage = ""
	} else if session == nil || session.userID == nil {
		server.WriteString(w, "expired")
	} else {
		server.WriteString(w, "ok")
	}
}

func (s *Server) handleIrmaLogin(w http.ResponseWriter, r *http.Request) {
	session := s.store.create()
	sessiontoken := session.token

	qr, _, err := s.sessionserver.StartSession(irma.NewDisclosureRequest(s.conf.KeyshareAttributes...),
		func(result *server.SessionResult) {
			session := s.store.get(sessiontoken)
			session.Lock()
			defer session.Unlock()

			if result.Status != server.StatusDone {
				// Ignore incomplete attempts, frontend handles these.
				return
			}

			username := *result.Disclosed[0][0].RawValue
			id, err := s.db.GetUserID(username)
			if err == ErrUserNotFound {
				session.pendingError = &server.ErrorUserNotRegistered
				session.pendingErrorMessage = ""
				return
			} else if err != nil {
				session.pendingError = &server.ErrorInternal
				session.pendingErrorMessage = err.Error()
				return
			}

			session.userID = new(int64)
			*session.userID = id
		})

	if err != nil {
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessiontoken,
		MaxAge:   s.conf.SessionLifetime,
		Secure:   s.conf.Production,
		Path:     "/",
		HttpOnly: true,
	})
	server.WriteJson(w, qr)
}

func (s *Server) StaticFilesHandler() http.Handler {
	return http.StripPrefix(s.conf.StaticPrefix, http.FileServer(http.Dir(s.conf.StaticPath)))
}
