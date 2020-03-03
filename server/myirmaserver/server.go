package myirmaserver

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi"
	"github.com/privacybydesign/irmago/server"

	irma "github.com/privacybydesign/irmago"

	"github.com/privacybydesign/irmago/server/irmaserver"
)

type Server struct {
	conf *Configuration

	sessionserver *irmaserver.Server
	store         SessionStore
	db            MyirmaDB
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
	return &Server{
		sessionserver: sessionserver,
		store:         NewMemorySessionStore(time.Duration(conf.SessionLifetime) * time.Second),
		db:            conf.DB,
	}, nil
}

func (s *Server) Stop() {
	s.sessionserver.Stop()
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Post("/checksession", s.handleCheckSession)
	router.Post("/irmalogin", s.handleDoIrmaLogin)
	router.Mount("/irma/", s.sessionserver.HandlerFunc())
	return router
}

func (s *Server) handleCheckSession(w http.ResponseWriter, r *http.Request) {
	token, err := r.Cookie("session")
	if err != nil {
		fmt.Println("err here")
		server.WriteString(w, "expired")
		return
	}

	session := s.store.get(token.Value)
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

func (s *Server) handleDoIrmaLogin(w http.ResponseWriter, r *http.Request) {
	session := s.store.create()
	sessiontoken := session.token

	qr, _, err := s.sessionserver.StartSession(irma.NewDisclosureRequest(irma.NewAttributeTypeIdentifier("pbdf.sidn-pbdf.irma.pseudonym")),
		func(result *server.SessionResult) {
			session := s.store.get(sessiontoken)
			session.Lock()
			defer session.Unlock()

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
		Secure:   true,
		HttpOnly: true,
	})
	server.WriteJson(w, qr)
}
