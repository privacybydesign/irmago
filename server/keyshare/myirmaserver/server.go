package myirmaserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/mail"
	"strconv"
	"time"

	"github.com/go-co-op/gocron"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"

	irma "github.com/privacybydesign/irmago"

	"github.com/privacybydesign/irmago/server/irmaserver"
)

type Server struct {
	conf *Configuration

	irmaserv  *irmaserver.Server
	store     sessionStore
	db        db
	scheduler *gocron.Scheduler
}

var errUnknownEmail = errors.New("Email not associated with account")

func New(conf *Configuration) (*Server, error) {
	irmaserv, err := irmaserver.New(conf.Configuration)
	if err != nil {
		return nil, err
	}
	err = processConfiguration(conf)
	if err != nil {
		return nil, err
	}

	s := &Server{
		conf:      conf,
		irmaserv:  irmaserv,
		store:     newMemorySessionStore(time.Duration(conf.SessionLifetime) * time.Second),
		db:        conf.DB,
		scheduler: gocron.NewScheduler(time.UTC),
	}

	if _, err := s.scheduler.Every(10).Seconds().Do(s.store.flush); err != nil {
		return nil, err
	}
	gocron.SetPanicHandler(server.GocronPanicHandler(s.conf.Logger))
	s.scheduler.StartAsync()

	if s.conf.LogJSON {
		s.conf.Logger.WithField("configuration", s.conf).Debug("Configuration")
	} else {
		bts, _ := json.MarshalIndent(s.conf, "", "   ")
		s.conf.Logger.Debug("Configuration: ", string(bts), "\n")
	}

	return s, nil
}

func (s *Server) Stop() {
	s.irmaserv.Stop()
	s.scheduler.Stop()
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()

	router.Use(cors.New(cors.Options{
		AllowedOrigins:   s.conf.CORSAllowedOrigins,
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "Cache-Control"},
		AllowedMethods:   []string{http.MethodGet, http.MethodPost, http.MethodDelete},
		AllowCredentials: true,
	}).Handler)

	router.Group(func(router chi.Router) {
		router.Use(server.RecoverMiddleware)

		router.Use(server.SizeLimitMiddleware)
		router.Use(server.TimeoutMiddleware(nil, server.WriteTimeout))

		opts := server.LogOptions{Response: true, Headers: true, From: false, EncodeBinary: false}
		router.Use(server.LogMiddleware("keyshare-myirma", opts))

		// Login/logout
		router.Post("/login/irma", s.handleIrmaLogin)
		router.Post("/login/email", s.handleEmailLogin)
		router.Post("/login/token/candidates", s.handleGetCandidates)
		router.Post("/login/token", s.handleTokenLogin)
		router.Post("/logout", s.handleLogout)

		// Email verification
		router.Post("/verify", s.handleVerifyEmail)

		// Session management
		router.Post("/checksession", s.handleCheckSession)

		router.Group(func(router chi.Router) {
			router.Use(s.sessionMiddleware)

			// User account data
			router.Get("/user", s.handleUserInfo)
			router.Get("/user/logs/{offset}", s.handleGetLogs)
			router.Post("/user/delete", s.handleDeleteUser)

			// Email address management
			router.Post("/email/add", s.handleAddEmail)
			router.Post("/email/remove", s.handleRemoveEmail)
		})
	})

	// IRMA session server
	router.Mount("/irma/", s.irmaserv.HandlerFunc())

	if s.conf.StaticPath != "" {
		router.Mount(s.conf.StaticPrefix, s.staticFilesHandler())
	}
	return router
}

func (s *Server) handleCheckSession(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromCookie(r)
	if session == nil {
		server.WriteString(w, "expired")
		return
	}

	session.Lock()
	defer session.Unlock()

	var (
		err server.Error
		msg string
	)
	if session.loginSessionToken != "" {
		err, msg = s.processLoginIrmaSessionResult(r.Context(), session)
	}

	if err != (server.Error{}) {
		server.WriteError(w, err, msg)
	} else if session.userID == nil {
		// Errors matter more than expired status if we have them
		server.WriteString(w, "expired")
	} else {
		server.WriteString(w, "ok")
	}
}

func (s *Server) sendDeleteEmails(ctx context.Context, session *session) error {
	user, err := s.db.user(ctx, *session.userID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not fetch user information")
		return err
	}

	for _, email := range user.Emails {
		// The error gets already logged in the SendEmail method. We can still proceed with deleting
		// the user account, even if one or more notification mails could not be sent.
		_ = s.conf.SendEmail(
			s.conf.deleteAccountTemplates,
			s.conf.DeleteAccountSubjects,
			map[string]string{"Username": user.Username, "Email": email.Email, "Delay": strconv.Itoa(s.conf.DeleteDelay)},
			email.Email,
			user.language,
		)
	}

	return nil
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*session)

	// First, send emails
	if s.conf.EmailServer != "" {
		err := s.sendDeleteEmails(r.Context(), session)
		if err != nil {
			// already logged
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}
	}

	// Then remove user
	err := s.db.scheduleUserRemoval(r.Context(), *session.userID, 24*time.Hour*time.Duration(s.conf.DeleteDelay))
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Problem removing user")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	s.logoutUser(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setCookie(w http.ResponseWriter, token string, maxage int) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxage,
		Secure:   s.conf.Production,
		Path:     "/",
		HttpOnly: true,
	})
}

type emailLoginRequest struct {
	Email    string `json:"email"`
	Language string `json:"language"`
}

func (s *Server) sendLoginEmail(ctx context.Context, request emailLoginRequest) error {
	// Early detect input error of s.conf.SendEmail to prevent a database lookup with unvalidated user input.
	_, err := mail.ParseAddress(request.Email)
	if err != nil {
		return keyshare.ErrInvalidEmail
	}

	token := common.NewSessionToken()
	err = s.db.addLoginToken(ctx, request.Email, token)
	if err == errEmailNotFound || err == errTooManyTokens {
		return err
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error adding login token to database")
		return err
	}

	baseURL := s.conf.TranslateString(s.conf.LoginURL, request.Language)
	return s.conf.SendEmail(
		s.conf.loginEmailTemplates,
		s.conf.LoginEmailSubjects,
		map[string]string{"TokenURL": baseURL + token},
		request.Email,
		request.Language,
	)
}

func (s *Server) handleEmailLogin(w http.ResponseWriter, r *http.Request) {
	if s.conf.EmailServer == "" {
		server.WriteError(w, server.ErrorInternal, "not enabled in configuration")
		return
	}

	var request emailLoginRequest
	if err := server.ParseBody(r, &request); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	err := s.sendLoginEmail(r.Context(), request)
	if err == keyshare.ErrInvalidEmail {
		server.WriteError(w, server.ErrorInvalidEmail, "")
		return
	}
	// In case of errEmailNotFound or errTooManyRequests, we should not write an error.
	// Otherwise, we would leak information about our user base.
	if err != nil && err != errEmailNotFound && err != errTooManyTokens {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	w.WriteHeader(http.StatusNoContent) // No need for content.
}

func (s *Server) handleGetCandidates(w http.ResponseWriter, r *http.Request) {
	var token string
	if err := server.ParseBody(r, &token); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	candidates, err := s.db.loginUserCandidates(r.Context(), token)
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

type tokenLoginRequest struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

func (s *Server) processTokenLogin(ctx context.Context, request tokenLoginRequest) (string, error) {
	id, err := s.db.verifyLoginToken(ctx, request.Token, request.Username)
	if err == keyshare.ErrUserNotFound {
		return "", err
	}
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not login user using token")
		return "", err
	}

	session := s.store.create()
	session.userID = &id

	err = s.db.setSeen(ctx, id)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not update users last seen date/time")
		// not relevant for frontend, so ignore beyond log.
	}

	return session.token, nil
}

func (s *Server) handleTokenLogin(w http.ResponseWriter, r *http.Request) {
	var request tokenLoginRequest
	if err := server.ParseBody(r, &request); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	token, err := s.processTokenLogin(r.Context(), request)

	if err == keyshare.ErrUserNotFound {
		server.WriteError(w, server.ErrorInvalidRequest, "Invalid login request")
		return
	}
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	s.setCookie(w, token, s.conf.SessionLifetime)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) processLoginIrmaSessionResult(ctx context.Context, session *session) (server.Error, string) {
	result, err := s.irmaserv.GetSessionResult(session.loginSessionToken)
	if err != nil {
		return server.ErrorInternal, ""
	}
	if result == nil {
		session.loginSessionToken = ""
		return server.ErrorInternal, "unknown login session"
	}

	if result.Status != irma.ServerStatusDone {
		// Ignore incomplete attempts, frontend handles these.
		return server.Error{}, ""
	}

	session.loginSessionToken = ""

	if result.ProofStatus != irma.ProofStatusValid {
		s.conf.Logger.Info("received invalid login attribute")
		return server.ErrorInvalidProofs, ""
	}

	username := *result.Disclosed[0][0].RawValue
	id, err := s.db.userIDByUsername(ctx, username)
	if err == keyshare.ErrUserNotFound {
		return server.ErrorUserNotRegistered, ""
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error during processing of login IRMA session result")
		return server.ErrorInternal, err.Error()
	}

	session.userID = &id

	err = s.db.setSeen(ctx, id)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not update users last seen time/date")
		// not relevant for frontend, so ignore beyond log.
	}
	return server.Error{}, ""
}

func (s *Server) handleIrmaLogin(w http.ResponseWriter, _ *http.Request) {
	session := s.store.create()
	sessiontoken := session.token

	qr, loginToken, frontendRequest, err := s.irmaserv.StartSession(
		newIrmaDisclosureRequest(s.conf.KeyshareAttributes),
		nil,
	)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error during startup of IRMA session for login")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	session.loginSessionToken = loginToken
	s.setCookie(w, sessiontoken, s.conf.SessionLifetime)
	server.WriteJson(w, server.SessionPackage{
		SessionPtr:      qr,
		FrontendRequest: frontendRequest,
	})
}

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var token string
	if err := server.ParseBody(r, &token); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	id, err := s.db.verifyEmailToken(r.Context(), token)
	if err == errTokenNotFound {
		s.conf.Logger.Info("Unknown email verification token")
		server.WriteError(w, server.ErrorInvalidToken, "Unknown email verification token")
		return
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not verify email token")
		server.WriteError(w, server.ErrorInvalidRequest, "could not verify email token")
		return
	}

	session := s.store.create()
	session.userID = &id

	err = s.db.setSeen(r.Context(), id)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not update users last seen time/date")
		// not relevant for frontend, so ignore beyond log.
	}

	s.setCookie(w, session.token, s.conf.SessionLifetime)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logoutUser(w http.ResponseWriter, r *http.Request) {
	session := s.sessionFromCookie(r)
	if session != nil {
		session.userID = nil // expire session
	}
	s.setCookie(w, "", -1)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.logoutUser(w, r)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*session)

	// Handle finished IRMA session used for adding email address, if any
	if session.emailSessionToken != "" {
		e, msg := s.processAddEmailIrmaSessionResult(r.Context(), session)
		if e != (server.Error{}) {
			server.WriteError(w, e, msg)
			return
		}
	}

	user, err := s.db.user(r.Context(), *session.userID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Problem fetching user information from database")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	session.expiry = time.Now().Add(time.Duration(s.conf.SessionLifetime) * time.Second)
	s.setCookie(w, session.token, s.conf.SessionLifetime)

	if user.Emails == nil {
		user.Emails = []userEmail{}
	} // Ensure we never send nil in place of an empty list
	server.WriteJson(w, user)
}

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	offsetS := chi.URLParam(r, "offset")
	offset, err := strconv.Atoi(offsetS)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed offset")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	session := r.Context().Value("session").(*session)
	entries, err := s.db.logs(r.Context(), *session.userID, offset, 11)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not load log entries")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	session.expiry = time.Now().Add(time.Duration(s.conf.SessionLifetime) * time.Second)
	s.setCookie(w, session.token, s.conf.SessionLifetime)

	if entries == nil {
		entries = []logEntry{}
	} // Ensure we never send an nil as empty list
	server.WriteJson(w, entries)
}

func (s *Server) processRemoveEmail(ctx context.Context, session *session, email string) error {
	user, err := s.db.user(ctx, *session.userID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error checking whether email address can be removed")
		return err
	}
	validEmail := false
	for _, e := range user.Emails {
		if email == e.Email {
			validEmail = true
		}
	}
	if !validEmail {
		s.conf.Logger.Info("Malformed request: invalid email address to delete")
		return errUnknownEmail
	}

	if s.conf.EmailServer != "" {
		err = s.conf.SendEmail(
			s.conf.deleteEmailTemplates,
			s.conf.DeleteEmailSubjects,
			map[string]string{"Username": user.Username, "Delay": strconv.Itoa(s.conf.DeleteDelay)},
			email,
			user.language,
		)
		if err != nil {
			// already logged
			return err
		}
	}

	err = s.db.scheduleEmailRemoval(ctx, *session.userID, email, 24*time.Hour*time.Duration(s.conf.DeleteDelay))
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error removing user email address")
		return err
	}

	return nil
}

func (s *Server) handleRemoveEmail(w http.ResponseWriter, r *http.Request) {
	var email string
	if err := server.ParseBody(r, &email); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	session := r.Context().Value("session").(*session)
	err := s.processRemoveEmail(r.Context(), session, email)
	if err == errUnknownEmail || err == keyshare.ErrInvalidEmail {
		server.WriteError(w, server.ErrorInvalidRequest, "Not a valid email address for user")
		return
	}
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	session.expiry = time.Now().Add(time.Duration(s.conf.SessionLifetime) * time.Second)
	s.setCookie(w, session.token, s.conf.SessionLifetime)

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) processAddEmailIrmaSessionResult(ctx context.Context, session *session) (server.Error, string) {
	result, err := s.irmaserv.GetSessionResult(session.emailSessionToken)
	if err != nil {
		return server.ErrorInternal, ""
	}
	if result == nil {
		session.emailSessionToken = ""
		return server.ErrorInternal, "unknown login session"
	}

	if result.Status != irma.ServerStatusDone {
		// Ignore incomplete attempts, frontend does that
		return server.Error{}, ""
	}

	session.emailSessionToken = ""

	if result.ProofStatus != irma.ProofStatusValid {
		s.conf.Logger.Info("received invalid email attribute")
		return server.ErrorInvalidProofs, ""
	}

	email := *result.Disclosed[0][0].RawValue
	err = s.db.addEmail(ctx, *session.userID, email)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not add email address to user")
		return server.ErrorInternal, err.Error()
	}

	return server.Error{}, ""
}

func (s *Server) handleAddEmail(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*session)

	qr, emailToken, frontendRequest, err := s.irmaserv.StartSession(
		newIrmaDisclosureRequest(s.conf.EmailAttributes),
		nil,
	)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Error during startup of IRMA session for adding email address")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	session.emailSessionToken = emailToken
	session.expiry = time.Now().Add(time.Duration(s.conf.SessionLifetime) * time.Second)
	s.setCookie(w, session.token, s.conf.SessionLifetime)

	server.WriteJson(w, server.SessionPackage{
		SessionPtr:      qr,
		FrontendRequest: frontendRequest,
	})
}

func (s *Server) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := s.sessionFromCookie(r)
		if session == nil || session.userID == nil {
			s.conf.Logger.Info("Malformed request: user not logged in")
			server.WriteError(w, server.ErrorInvalidRequest, "not logged in")
			return
		}

		session.Lock()
		defer session.Unlock()
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "session", session)))
	})
}

func (s *Server) staticFilesHandler() http.Handler {
	return http.StripPrefix(s.conf.StaticPrefix, http.FileServer(http.Dir(s.conf.StaticPath)))
}

func (s *Server) sessionFromCookie(r *http.Request) *session {
	token, err := r.Cookie("session")
	if err != nil { // only happens if cookie is not present
		return nil
	}
	return s.store.get(token.Value)
}

// newIrmaDisclosureRequest composes an irma.DisclosureRequest with one attribute disjunction
// containing every given attribute type identifier as an option in that disjunction.
func newIrmaDisclosureRequest(attrs []irma.AttributeTypeIdentifier) *irma.DisclosureRequest {
	discon := irma.AttributeDisCon{}
	for _, attr := range attrs {
		discon = append(discon, irma.AttributeCon{irma.NewAttributeRequest(attr.String())})
	}
	request := irma.NewDisclosureRequest()
	request.Disclose = irma.AttributeConDisCon{discon}
	return request
}
