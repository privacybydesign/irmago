package myirmaserver

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
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
	// Session management
	router.Post("/checksession", s.handleCheckSession)
	router.Post("/login/irma", s.handleIrmaLogin)
	router.Post("/login/email", s.handleEmailLogin)
	router.Post("/login/token/candidates", s.handleGetCandidates)
	router.Post("/login/token", s.handleTokenLogin)
	router.Post("/logout", s.handleLogout)

	// User account data
	router.Get("/user", s.handleUserInfo)
	router.Get("/user/logs/{offset}", s.handleGetLogs)
	router.Post("/user/delete", s.handleDeleteUser)

	// Email address management
	router.Post("/email/add", s.handleAddEmail)
	router.Post("/email/remove", s.handleRemoveEmail)

	// Irma session server
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

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	token, err := r.Cookie("session")
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: missing session")
		server.WriteError(w, server.ErrorInvalidRequest, "Missing session")
		return
	}

	session := s.store.get(token.Value)
	if session == nil {
		s.conf.Logger.Info("Malformed request: session expired")
		server.WriteError(w, server.ErrorInvalidRequest, "session expired")
		return
	}

	session.Lock()
	defer session.Unlock()
	if session.userID == nil {
		s.conf.Logger.Info("Malformed request: not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "not logged in")
		return
	}

	err = s.db.RemoveUser(*session.userID)

	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Problem removing user")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Secure:   s.conf.Production,
		Path:     "/",
		HttpOnly: true,
	})

	w.WriteHeader(http.StatusNoContent)
}

type EmailLoginRequest struct {
	Email    string `json:"email"`
	Language string `json:"language"`
}

func (s *Server) handleEmailLogin(w http.ResponseWriter, r *http.Request) {
	if s.conf.EmailServer == "" {
		server.WriteError(w, server.ErrorInternal, "not enabled in configuration")
		return
	}

	requestData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read request body")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	var request EmailLoginRequest
	err = json.Unmarshal(requestData, &request)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not parse request body")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	token := server.NewSessionToken()
	err = s.db.AddEmailLoginToken(request.Email, token)
	if err == ErrUserNotFound {
		server.WriteError(w, server.ErrorUserNotRegistered, "")
		return
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error adding login token to database")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	template, ok := s.conf.LoginEmailTemplates[request.Language]
	if !ok {
		template = s.conf.LoginEmailTemplates[s.conf.DefaultLanguage]
	}
	subject, ok := s.conf.LoginEmailSubject[request.Language]
	if !ok {
		subject = s.conf.LoginEmailSubject[s.conf.DefaultLanguage]
	}
	baseURL, ok := s.conf.LoginEmailBaseURL[request.Language]
	if !ok {
		baseURL = s.conf.LoginEmailBaseURL[s.conf.DefaultLanguage]
	}
	var emsg bytes.Buffer
	err = template.Execute(&emsg, map[string]string{"TokenURL": baseURL + token})
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not generate login mail from template")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	err = server.SendHTMLMail(
		s.conf.EmailServer,
		s.conf.EmailAuth,
		s.conf.EmailFrom,
		request.Email,
		subject,
		emsg.Bytes())

	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not send login mail")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent) // No need for content.
}

func (s *Server) handleGetCandidates(w http.ResponseWriter, r *http.Request) {
	requestData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read body")
		server.WriteError(w, server.ErrorInvalidRequest, "could not read request body")
		return
	}

	token := string(requestData)

	candidates, err := s.db.LoginTokenGetCandidates(token)
	if err == ErrUserNotFound {
		server.WriteError(w, server.ErrorInvalidRequest, "token invalid")
		return
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not retrieve candidates for token")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteJson(w, candidates)
}

type TokenLoginRequest struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

func (s *Server) handleTokenLogin(w http.ResponseWriter, r *http.Request) {
	requestData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read body")
		server.WriteError(w, server.ErrorInvalidRequest, "could not read request body")
		return
	}

	var request TokenLoginRequest
	err = json.Unmarshal(requestData, &request)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not parse request body")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	ok, err := s.db.TryUserLoginToken(request.Token, request.Username)
	if err == ErrUserNotFound {
		server.WriteError(w, server.ErrorInvalidRequest, "Invalid login request")
		return
	}
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not login user using token")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	if !ok {
		server.WriteError(w, server.ErrorInvalidRequest, "Invalid login request")
		return
	}

	session := s.store.create()
	session.userID = new(int64)
	*session.userID, err = s.db.GetUserID(request.Username) // username is trusted, since it was validated by s.db.TryUserLoginToken
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not fetch userid for username validated in earlier step")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	token := session.token

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		MaxAge:   s.conf.SessionLifetime,
		Secure:   s.conf.Production,
		Path:     "/",
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleIrmaLogin(w http.ResponseWriter, r *http.Request) {
	session := s.store.create()
	sessiontoken := session.token

	qr, _, err := s.sessionserver.StartSession(irma.NewDisclosureRequest(s.conf.KeyshareAttributes...),
		func(result *server.SessionResult) {
			session := s.store.get(sessiontoken)
			if session == nil {
				s.conf.Logger.Info("User session expired during irma session")
				return
			}
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
				s.conf.Logger.WithField("error", err).Error("Error during processing of login irma session result")
				session.pendingError = &server.ErrorInternal
				session.pendingErrorMessage = err.Error()
				return
			}

			session.userID = new(int64)
			*session.userID = id
		})

	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error during startup of irma session for login")
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

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Secure:   s.conf.Production,
		Path:     "/",
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	token, err := r.Cookie("session")
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: missing session")
		server.WriteError(w, server.ErrorInvalidRequest, "Missing session")
		return
	}

	session := s.store.get(token.Value)
	if session == nil {
		s.conf.Logger.Info("Malformed request: expired session")
		server.WriteError(w, server.ErrorInvalidRequest, "Expired session")
		return
	}

	session.Lock()
	defer session.Unlock()

	if session.userID == nil {
		s.conf.Logger.Info("Malformed request: not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "Not logged in")
		return
	}

	userinfo, err := s.db.GetUserInformation(*session.userID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Problem fetching user information from database")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteJson(w, userinfo)
}

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	offsetS := chi.URLParam(r, "offset")
	offset, err := strconv.Atoi(offsetS)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed offset")
		w.WriteHeader(http.StatusNotFound)
		return
	}

	token, err := r.Cookie("session")
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: missing session")
		server.WriteError(w, server.ErrorInvalidRequest, "Missing session")
		return
	}

	session := s.store.get(token.Value)
	if session == nil {
		s.conf.Logger.Info("Malformed request: expired session")
		server.WriteError(w, server.ErrorInvalidRequest, "Expired session")
		return
	}

	session.Lock()
	defer session.Unlock()

	if session.userID == nil {
		s.conf.Logger.Info("Malformed request: user not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "Not logged in")
		return
	}

	entries, err := s.db.GetLogs(*session.userID, offset, 10)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not load log entries")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteJson(w, entries)
}

func (s *Server) handleRemoveEmail(w http.ResponseWriter, r *http.Request) {
	email, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read body")
		server.WriteError(w, server.ErrorInvalidRequest, "Could not parse request body")
		return
	}

	token, err := r.Cookie("session")
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: missing session")
		server.WriteError(w, server.ErrorInvalidRequest, "Missing session")
		return
	}

	session := s.store.get(token.Value)
	if session == nil {
		s.conf.Logger.Info("Malformed request: expired session")
		server.WriteError(w, server.ErrorInvalidRequest, "Expired session")
		return
	}

	session.Lock()
	defer session.Unlock()

	if session.userID == nil {
		s.conf.Logger.Info("Malformed request: user not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "Not logged in")
		return
	}

	err = s.db.RemoveEmail(*session.userID, string(email))
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error removing user email address")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddEmail(w http.ResponseWriter, r *http.Request) {
	token, err := r.Cookie("session")
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: missing session")
		server.WriteError(w, server.ErrorInvalidRequest, "Missing session")
		return
	}

	session := s.store.get(token.Value)
	if session == nil {
		s.conf.Logger.Info("Malformed request: expired session")
		server.WriteError(w, server.ErrorInvalidRequest, "Expired session")
		return
	}

	session.Lock()
	defer session.Unlock()

	if session.userID == nil {
		s.conf.Logger.Info("Malformed request: user not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "Not logged in")
		return
	}

	sessiontoken := token.Value
	qr, _, err := s.sessionserver.StartSession(irma.NewDisclosureRequest(s.conf.EmailAttributes...),
		func(result *server.SessionResult) {
			session := s.store.get(sessiontoken)
			if session == nil {
				s.conf.Logger.Info("User session expired during irma session")
				return
			}
			session.Lock()
			defer session.Unlock()

			if session.userID == nil {
				s.conf.Logger.Error("Unexpected logged out session during email address add")
				return
			}

			if result.Status != server.StatusDone {
				// Ignore incomplete attempts, frontend does that
				return
			}

			email := *result.Disclosed[0][0].RawValue
			err := s.db.AddEmail(*session.userID, email)
			if err != nil {
				s.conf.Logger.WithField("error", err).Error("Could not add email address to user")
				session.pendingError = &server.ErrorInternal
				session.pendingErrorMessage = err.Error()
			}
		})

	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error during startup of irma session for adding email address")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteJson(w, qr)
}

func (s *Server) StaticFilesHandler() http.Handler {
	return http.StripPrefix(s.conf.StaticPrefix, http.FileServer(http.Dir(s.conf.StaticPath)))
}
