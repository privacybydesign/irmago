package myirmaserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi"
	"github.com/go-errors/errors"
	"github.com/jasonlvhit/gocron"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"

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

var ErrInvalidEmail = errors.New("Email not associated with account")

func New(conf *Configuration) (*Server, error) {
	sessionserver, err := irmaserver.New(conf.Configuration)
	if err != nil {
		return nil, err
	}
	err = processConfiguration(conf)
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

	if s.conf.Verbose >= 2 {
		opts := server.LogOptions{Response: true, Headers: true, From: false, EncodeBinary: true}
		router.Use(server.LogMiddleware("keyshare-myirma", opts))
	}

	// Login/logout
	router.Post("/login/irma", s.handleIrmaLogin)
	router.Post("/login/email", s.handleEmailLogin)
	router.Post("/login/token/candidates", s.handleGetCandidates)
	router.Post("/login/token", s.handleTokenLogin)
	router.Post("/logout", s.handleLogout)

	// Email verification
	router.Post("/verify", s.handleVerifyEmail)

	router.Group(func(router chi.Router) {
		router.Use(s.sessionMiddleware)

		// Session management
		router.Post("/checksession", s.handleCheckSession)

		// User account data
		router.Get("/user", s.handleUserInfo)
		router.Get("/user/logs/{offset}", s.handleGetLogs)
		router.Post("/user/delete", s.handleDeleteUser)

		// Email address management
		router.Post("/email/add", s.handleAddEmail)
		router.Post("/email/remove", s.handleRemoveEmail)
	})

	// IRMA session server
	router.Mount("/irma/", s.sessionserver.HandlerFunc())

	if s.conf.StaticPath != "" {
		router.Mount(s.conf.StaticPrefix, s.StaticFilesHandler())
	}
	return router
}

func (s *Server) handleCheckSession(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Sessiondata)

	if session == nil {
		server.WriteString(w, "expired")
	} else if session.pendingError != nil {
		server.WriteError(w, *session.pendingError, session.pendingErrorMessage)
		session.pendingError = nil
		session.pendingErrorMessage = ""
	} else if session.userID == nil {
		// Errors matter more than expired status if we have them
		server.WriteString(w, "expired")
	} else {
		server.WriteString(w, "ok")
	}
}

func (s *Server) sendDeleteEmails(session *Sessiondata) error {
	userData, err := s.db.UserInformation(*session.userID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not fetch user information")
		return err
	}

	template, ok := s.conf.deleteAccountTemplates[userData.language]
	if !ok {
		template = s.conf.deleteAccountTemplates[s.conf.DefaultLanguage]
	}
	subject, ok := s.conf.DeleteAccountSubject[userData.language]
	if !ok {
		subject = s.conf.DeleteAccountSubject[s.conf.DefaultLanguage]
	}
	var emsg bytes.Buffer
	err = template.Execute(&emsg, map[string]string{"Username": userData.Username})
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not render account deletion email")
		return err
	}
	for _, email := range userData.Emails {
		err = server.SendHTMLMail(
			s.conf.EmailServer,
			s.conf.EmailAuth,
			s.conf.EmailFrom,
			email.Email,
			subject,
			emsg.Bytes())
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not send account deletion email")
			return err
		}
	}

	return nil
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Sessiondata)
	if session == nil || session.userID == nil {
		s.conf.Logger.Info("Malformed request: not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "not logged in")
		return
	}

	// First, send emails
	if s.conf.EmailServer != "" {
		err := s.sendDeleteEmails(session)
		if err != nil {
			//already logged
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}
	}

	// Then remove user
	err := s.db.RemoveUser(*session.userID, 24*time.Hour*time.Duration(s.conf.DeleteDelay))
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

func (s *Server) sendLoginEmail(request EmailLoginRequest) error {
	token := common.NewSessionToken()
	err := s.db.AddEmailLoginToken(request.Email, token)
	if err == ErrEmailNotFound {
		return err
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error adding login token to database")
		return err
	}

	template, ok := s.conf.loginEmailTemplates[request.Language]
	if !ok {
		template = s.conf.loginEmailTemplates[s.conf.DefaultLanguage]
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
		return err
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
		return err
	}

	return nil
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

	err = s.sendLoginEmail(request)
	if err == ErrEmailNotFound {
		server.WriteError(w, server.ErrorUserNotRegistered, "")
		return
	}
	if err != nil {
		// already logged
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

	candidates, err := s.db.LoginTokenCandidates(token)
	if err == keyshare.ErrUserNotFound {
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

func (s *Server) processTokenLogin(request TokenLoginRequest) (string, error) {
	ok, err := s.db.TryUserLoginToken(request.Token, request.Username)
	if err != nil && err != keyshare.ErrUserNotFound {
		s.conf.Logger.WithField("error", err).Error("Could not login user using token")
		return "", err
	}
	if !ok || err == keyshare.ErrUserNotFound {
		return "", keyshare.ErrUserNotFound
	}

	session := s.store.create()
	session.userID = new(int64)
	*session.userID, err = s.db.UserID(request.Username) // username is trusted, since it was validated by s.db.TryUserLoginToken
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not fetch userid for username validated in earlier step")
		return "", err
	}
	token := session.token

	err = s.db.SetSeen(*session.userID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not update users last seen date/time")
		// not relevant for frontend, so ignore beyond log.
	}

	return token, nil
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

	token, err := s.processTokenLogin(request)

	if err == keyshare.ErrUserNotFound {
		server.WriteError(w, server.ErrorInvalidRequest, "Invalid login request")
		return
	}
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

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

func (s *Server) processLoginIrmaSessionResult(sessiontoken string, result *server.SessionResult) {
	session := s.store.get(sessiontoken)
	if session == nil {
		s.conf.Logger.Info("User session expired during IRMA session")
		return
	}
	session.Lock()
	defer session.Unlock()

	if result.Status != server.StatusDone {
		// Ignore incomplete attempts, frontend handles these.
		return
	}

	username := *result.Disclosed[0][0].RawValue
	id, err := s.db.UserID(username)
	if err == keyshare.ErrUserNotFound {
		session.pendingError = &server.ErrorUserNotRegistered
		session.pendingErrorMessage = ""
		return
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error during processing of login IRMA session result")
		session.pendingError = &server.ErrorInternal
		session.pendingErrorMessage = err.Error()
		return
	}

	session.userID = new(int64)
	*session.userID = id

	err = s.db.SetSeen(id)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not update users last seen time/date")
		// not relevant for frontend, so ignore beyond log.
	}
}

func (s *Server) handleIrmaLogin(w http.ResponseWriter, r *http.Request) {
	session := s.store.create()
	sessiontoken := session.token

	qr, _, err := s.sessionserver.StartSession(irma.NewDisclosureRequest(s.conf.KeyshareAttributes...),
		func(result *server.SessionResult) {
			s.processLoginIrmaSessionResult(sessiontoken, result)
		})

	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error during startup of IRMA session for login")
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

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	requestData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read body")
		server.WriteError(w, server.ErrorInvalidRequest, "could not read request body")
		return
	}

	token := string(requestData)

	id, err := s.db.VerifyEmailToken(token)
	if err == keyshare.ErrUserNotFound {
		s.conf.Logger.Info("Trying to reuse token")
		server.WriteError(w, server.ErrorInvalidRequest, "Token already used")
		return
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Info("Could not verify email token")
		server.WriteError(w, server.ErrorInvalidRequest, "could not verify email token")
		return
	}

	session := s.store.create()
	session.userID = &id

	err = s.db.SetSeen(id)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not update users last seen time/date")
		// not relevant for frontend, so ignore beyond log.
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    session.token,
		MaxAge:   s.conf.SessionLifetime,
		Secure:   s.conf.Production,
		Path:     "/",
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusNoContent)
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
	session := r.Context().Value("session").(*Sessiondata)
	if session == nil || session.userID == nil {
		s.conf.Logger.Info("Malformed request: not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "Not logged in")
		return
	}

	userinfo, err := s.db.UserInformation(*session.userID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Problem fetching user information from database")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	if userinfo.Emails == nil {
		userinfo.Emails = []UserEmail{}
	} // Ensure we never send nil in place of an empty list
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

	session := r.Context().Value("session").(*Sessiondata)
	if session == nil || session.userID == nil {
		s.conf.Logger.Info("Malformed request: user not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "Not logged in")
		return
	}

	entries, err := s.db.Logs(*session.userID, offset, 11)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not load log entries")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	if entries == nil {
		entries = []LogEntry{}
	} // Ensure we never send an nil as empty list
	server.WriteJson(w, entries)
}

func (s *Server) sendEmailRemovalEmail(info UserInformation, email string) error {
	template, ok := s.conf.deleteEmailTemplates[info.language]
	if !ok {
		template = s.conf.deleteEmailTemplates[s.conf.DefaultLanguage]
	}
	subject, ok := s.conf.DeleteEmailSubject[info.language]
	if !ok {
		subject = s.conf.DeleteEmailSubject[s.conf.DefaultLanguage]
	}

	var emsg bytes.Buffer
	err := template.Execute(&emsg, map[string]string{"Username": info.Username})
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not generate email removal mail from template")
		return err
	}

	err = server.SendHTMLMail(
		s.conf.EmailServer,
		s.conf.EmailAuth,
		s.conf.EmailFrom,
		email,
		subject,
		emsg.Bytes())

	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not send email removal mail")
		return err
	}

	return nil
}

func (s *Server) processRemoveEmail(session *Sessiondata, email string) error {
	info, err := s.db.UserInformation(*session.userID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error checking whether email address can be removed")
		return err
	}
	validEmail := false
	for _, emailL := range info.Emails {
		if email == emailL.Email {
			validEmail = true
		}
	}
	if !validEmail {
		s.conf.Logger.Info("Malformed request: invalid email address to delete")
		return ErrInvalidEmail
	}

	if s.conf.EmailServer != "" {
		err = s.sendEmailRemovalEmail(info, string(email))
		if err != nil {
			// already logged
			return err
		}
	}

	err = s.db.RemoveEmail(*session.userID, string(email), 24*time.Hour*time.Duration(s.conf.DeleteDelay))
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error removing user email address")
		return err
	}

	return nil
}

func (s *Server) handleRemoveEmail(w http.ResponseWriter, r *http.Request) {
	email, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read body")
		server.WriteError(w, server.ErrorInvalidRequest, "Could not parse request body")
		return
	}

	session := r.Context().Value("session").(*Sessiondata)
	if session == nil || session.userID == nil {
		s.conf.Logger.Info("Malformed request: user not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "Not logged in")
		return
	}

	err = s.processRemoveEmail(session, string(email))
	if err == ErrInvalidEmail {
		server.WriteError(w, server.ErrorInvalidRequest, "Not a valid email address for user")
		return
	}
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) processAddEmailIrmaSessionResult(sessiontoken string, result *server.SessionResult) {
	session := s.store.get(sessiontoken)
	if session == nil {
		s.conf.Logger.Info("User session expired during IRMA session")
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
}

func (s *Server) handleAddEmail(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*Sessiondata)
	if session == nil || session.userID == nil {
		s.conf.Logger.Info("Malformed request: user not logged in")
		server.WriteError(w, server.ErrorInvalidRequest, "Not logged in")
		return
	}

	sessiontoken := session.token
	qr, _, err := s.sessionserver.StartSession(irma.NewDisclosureRequest(s.conf.EmailAttributes...),
		func(result *server.SessionResult) {
			s.processAddEmailIrmaSessionResult(sessiontoken, result)
		})

	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error during startup of IRMA session for adding email address")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteJson(w, qr)
}

func (s *Server) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("session")
		if err != nil {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "session", (*Sessiondata)(nil))))
			return
		}

		session := s.store.get(token.Value)
		if session != nil {
			session.Lock()
			defer session.Unlock()
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "session", session)))
	})
}

func (s *Server) StaticFilesHandler() http.Handler {
	return http.StripPrefix(s.conf.StaticPrefix, http.FileServer(http.Dir(s.conf.StaticPath)))
}
