package keyshareserver

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-errors/errors"
	"github.com/hashicorp/go-multierror"
	"github.com/jasonlvhit/gocron"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/go-chi/chi"
)

type SessionData struct {
	LastKeyID    irma.PublicKeyIdentifier // last used key, used in signing the issuance message
	LastCommitID uint64
	expiry       time.Time
}

type Server struct {
	// configuration
	conf *Configuration

	// external components
	core          *keysharecore.Core
	sessionserver *irmaserver.Server
	db            KeyshareDB

	// Scheduler used to clean sessions
	scheduler     *gocron.Scheduler
	stopScheduler chan<- bool

	// Session data, keeping track of current keyshare protocol session state for each user
	sessions    map[string]*SessionData
	sessionLock sync.Mutex
}

func New(conf *Configuration) (*Server, error) {
	var err error
	s := &Server{
		conf:      conf,
		sessions:  map[string]*SessionData{},
		scheduler: gocron.NewScheduler(),
	}

	// Setup IRMA session server
	s.sessionserver, err = irmaserver.New(conf.Configuration)
	if err != nil {
		return nil, err
	}

	// Process configuration and create keyshare core
	s.core, err = processConfiguration(conf)
	if err != nil {
		return nil, err
	}

	// Load neccessary idemix keys into core, and ensure that future updates
	// to them are processed
	if err = s.LoadIdemixKeys(conf.IrmaConfiguration); err != nil {
		return nil, err
	}
	conf.IrmaConfiguration.UpdateListeners = append(conf.IrmaConfiguration.UpdateListeners, func(conf *irma.Configuration) {
		if err := s.LoadIdemixKeys(conf); err != nil {
			// run periodically; can only log the error here
			_ = server.LogError(err)
		}
	})

	// Setup DB
	s.db = conf.DB

	// Setup session cache clearing
	s.scheduler.Every(10).Seconds().Do(s.clearSessions)
	s.stopScheduler = s.scheduler.Start()

	return s, nil
}

func (s *Server) Stop() {
	s.stopScheduler <- true
	s.sessionserver.Stop()
}

// clean up any expired sessions
func (s *Server) clearSessions() {
	now := time.Now()
	s.sessionLock.Lock()
	defer s.sessionLock.Unlock()
	for k, v := range s.sessions {
		if now.After(v.expiry) {
			delete(s.sessions, k)
		}
	}
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()

	if s.conf.Verbose >= 2 {
		opts := server.LogOptions{Response: true, Headers: true, From: false, EncodeBinary: true}
		router.Use(server.LogMiddleware("keyshareserver", opts))
	}

	// Registration
	router.Post("/client/register", s.handleRegister)

	// Pin logic
	router.Post("/users/verify/pin", s.handleVerifyPin)
	router.Post("/users/change/pin", s.handleChangePin)

	// Keyshare sessions
	router.Group(func(router chi.Router) {
		router.Use(s.userMiddleware)
		router.Use(s.authorizationMiddleware)
		router.Post("/users/isAuthorized", s.handleValidate)
		router.Post("/prove/getCommitments", s.handleCommitments)
		router.Post("/prove/getResponse", s.handleResponse)
	})

	// IRMA server for issuing myirma credential during registration
	router.Mount("/irma/", s.sessionserver.HandlerFunc())
	return router
}

// On configuration changes, inform the keyshare core of any
// new IRMA issuer public keys.
func (s *Server) LoadIdemixKeys(conf *irma.Configuration) error {
	errs := multierror.Error{}
	for _, issuer := range conf.Issuers {
		keyIDs, err := conf.PublicKeyIndices(issuer.Identifier())
		if err != nil {
			errs.Errors = append(errs.Errors, errors.Errorf("issuer %v: could not find key IDs: %v", issuer, err))
			continue
		}
		for _, id := range keyIDs {
			key, err := conf.PublicKey(issuer.Identifier(), id)
			if err != nil {
				errs.Errors = append(errs.Errors, server.LogError(errors.Errorf("key %v-%v: could not fetch public key: %v", issuer, id, err)))
				continue
			}
			s.core.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: issuer.Identifier(), Counter: id}, key)
		}
	}
	return errs.ErrorOrNil()
}

// /prove/getCommitments
func (s *Server) handleCommitments(w http.ResponseWriter, r *http.Request) {
	// Fetch from context
	user := r.Context().Value("user").(*KeyshareUser)
	authorization := r.Context().Value("authorization").(string)

	// Read keys
	var keys []irma.PublicKeyIdentifier
	if err := server.ParseBody(w, r, &keys); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	if len(keys) == 0 {
		s.conf.Logger.Info("Malformed request: no keys over which to commit specified")
		server.WriteError(w, server.ErrorInvalidRequest, "No key specified")
		return
	}

	commitments, err := s.generateCommitments(user, authorization, keys)
	if err != nil && (err == keysharecore.ErrInvalidChallenge || err == keysharecore.ErrInvalidJWT) {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteJson(w, commitments)
}

func (s *Server) generateCommitments(user *KeyshareUser, authorization string, keys []irma.PublicKeyIdentifier) (*irma.ProofPCommitmentMap, error) {
	// Generate commitments
	commitments, commitID, err := s.core.GenerateCommitments(user.Coredata, authorization, keys)
	if err != nil {
		s.conf.Logger.WithField("error", err).Warn("Could not generate commitments for request")
		return nil, err
	}

	// Prepare output message format
	mappedCommitments := map[irma.PublicKeyIdentifier]*gabi.ProofPCommitment{}
	for i, keyID := range keys {
		mappedCommitments[keyID] = commitments[i]
	}

	// Store needed data for later requests.
	username := user.Username
	s.sessionLock.Lock()
	session, ok := s.sessions[username]
	if !ok {
		session = &SessionData{}
		s.sessions[username] = session
	}
	// Of all keys involved in the current session, store the ID of the first one to be used when
	// the user comes back later to retrieve her response. gabi.ProofP.P will depend on this public
	// key, which is used only during issuance. Thus, this assumes that during issuance, the user
	// puts the key ID of the credential(s) being issued at index 0.
	session.LastKeyID = keys[0]
	session.LastCommitID = commitID
	session.expiry = time.Now().Add(10 * time.Second)
	s.sessionLock.Unlock()

	// And send response
	return &irma.ProofPCommitmentMap{Commitments: mappedCommitments}, nil
}

// /prove/getResponse
func (s *Server) handleResponse(w http.ResponseWriter, r *http.Request) {
	// Fetch from context
	user := r.Context().Value("user").(*KeyshareUser)
	authorization := r.Context().Value("authorization").(string)

	// Read challenge
	challenge := new(big.Int)
	if err := server.ParseBody(w, r, challenge); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// verify access (avoids leaking whether there is a session ongoing to unauthorized callers)
	if !r.Context().Value("hasValidAuthorization").(bool) {
		s.conf.Logger.Warn("Could not generate keyshare response due to invalid authorization")
		server.WriteError(w, server.ErrorInvalidRequest, "Invalid authorization")
		return
	}

	// Get data from session
	s.sessionLock.Lock()
	sessionData, ok := s.sessions[user.Username]
	s.sessionLock.Unlock()
	if !ok {
		s.conf.Logger.Warn("Request for response without previous call to get commitments")
		server.WriteError(w, server.ErrorInvalidRequest, "Missing previous call to getCommitments")
		return
	}

	// And do the actual responding
	proofResponse, err := s.doGenerateResponses(user, authorization, challenge, sessionData.LastCommitID, sessionData.LastKeyID)
	if err != nil && (err == keysharecore.ErrInvalidChallenge || err == keysharecore.ErrInvalidJWT) {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteString(w, proofResponse)
}

func (s *Server) doGenerateResponses(user *KeyshareUser, authorization string, challenge *big.Int, commitID uint64, keyID irma.PublicKeyIdentifier) (string, error) {
	// Indicate activity on user account
	err := s.db.SetSeen(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not mark user as seen recently")
		// Do not send to user
	}

	// Make log entry
	err = s.db.AddLog(user, IrmaSession, nil)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
		return "", err
	}

	proofResponse, err := s.core.GenerateResponse(user.Coredata, authorization, commitID, challenge, keyID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not generate response for request")
		return "", err
	}

	return proofResponse, nil
}

// /users/isAuthorized
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	if r.Context().Value("hasValidAuthorization").(bool) {
		server.WriteJson(w, &irma.KeyshareAuthorization{Status: "authorized", Candidates: []string{"pin"}})
	} else {
		server.WriteJson(w, &irma.KeyshareAuthorization{Status: "expired", Candidates: []string{"pin"}})
	}
}

// /users/verify/pin
func (s *Server) handleVerifyPin(w http.ResponseWriter, r *http.Request) {
	// Extract request
	var msg irma.KeysharePinMessage
	if err := server.ParseBody(w, r, &msg); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Fetch user
	user, err := s.db.User(msg.Username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": msg.Username, "error": err}).Warn("Could not find user in db")
		server.WriteError(w, server.ErrorUserNotRegistered, "")
		return
	}

	// and verify pin
	result, err := s.doVerifyPin(user, msg.Username, msg.Pin)
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteJson(w, result)
}

func (s *Server) doVerifyPin(user *KeyshareUser, username, pin string) (irma.KeysharePinStatus, error) {
	// Check whether pin check is currently allowed
	ok, tries, wait, err := s.reservePinCheck(user, pin)
	if err != nil {
		return irma.KeysharePinStatus{}, err
	}
	if !ok {
		return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
	}

	// At this point, we are allowed to do an actual check (we have successfully reserved a spot for it), so do it.
	jwtt, err := s.core.ValidatePin(user.Coredata, pin, username)
	if err != nil && err != keysharecore.ErrInvalidPin {
		// Errors other than invalid pin are real errors
		s.conf.Logger.WithField("error", err).Error("Could not validate pin")
		return irma.KeysharePinStatus{}, err
	}

	if err == keysharecore.ErrInvalidPin {
		// Handle invalid pin
		err = s.db.AddLog(user, PinCheckFailed, tries)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
			return irma.KeysharePinStatus{}, err
		}
		if tries == 0 {
			err = s.db.AddLog(user, PinCheckBlocked, wait)
			if err != nil {
				s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
				return irma.KeysharePinStatus{}, err
			}
			return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
		} else {
			return irma.KeysharePinStatus{Status: "failure", Message: fmt.Sprintf("%v", tries)}, nil
		}
	}

	// Handle success
	err = s.db.ClearPincheck(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reset users pin check logic")
		// Do not send to user
	}
	err = s.db.SetSeen(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not indicate user activity")
		// Do not send to user
	}
	err = s.db.AddLog(user, PinCheckSuccess, nil)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
		return irma.KeysharePinStatus{}, err
	}

	return irma.KeysharePinStatus{Status: "success", Message: jwtt}, err
}

// /users/change/pin
func (s *Server) handleChangePin(w http.ResponseWriter, r *http.Request) {
	// Extract request
	var msg irma.KeyshareChangePin
	if err := server.ParseBody(w, r, &msg); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Fetch user
	user, err := s.db.User(msg.Username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": msg.Username, "error": err}).Warn("Could not find user in db")
		server.WriteError(w, server.ErrorUserNotRegistered, "")
		return
	}

	result, err := s.doUpdatePin(user, msg.OldPin, msg.NewPin)
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	server.WriteJson(w, result)
}

func (s *Server) doUpdatePin(user *KeyshareUser, oldPin, newPin string) (irma.KeysharePinStatus, error) {
	// Check whether pin check is currently allowed
	ok, tries, wait, err := s.reservePinCheck(user, oldPin)
	if err != nil {
		return irma.KeysharePinStatus{}, err
	}
	if !ok {
		return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
	}

	// Try to do the update
	user.Coredata, err = s.core.ChangePin(user.Coredata, oldPin, newPin)
	if err == keysharecore.ErrInvalidPin {
		if tries == 0 {
			return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
		} else {
			return irma.KeysharePinStatus{Status: "failure", Message: fmt.Sprintf("%v", tries)}, nil
		}
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not change pin")
		return irma.KeysharePinStatus{}, err
	}

	// Mark pincheck as success, resetting users wait and count
	err = s.db.ClearPincheck(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reset users pin check logic")
		// Do not send to user
	}

	// Write user back
	err = s.db.UpdateUser(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not write updated user to database")
		return irma.KeysharePinStatus{}, err
	}

	return irma.KeysharePinStatus{Status: "success"}, nil
}

// /client/register
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Extract request
	var msg irma.KeyshareEnrollment
	if err := server.ParseBody(w, r, &msg); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	sessionptr, err := s.doRegistration(msg)
	if err != nil && err == keysharecore.ErrPinTooLong {
		// Too long pin is not an internal error
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	if err != nil {
		// Already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	server.WriteJson(w, sessionptr)
}

func (s *Server) doRegistration(msg irma.KeyshareEnrollment) (*irma.Qr, error) {
	// Generate keyshare server account
	username := common.NewSessionToken() // TODO use newRandomString() for this when shoulder-surf is merged
	username = username[:12]

	coredata, err := s.core.GenerateKeyshareSecret(msg.Pin)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not register user")
		return nil, err
	}
	user := &KeyshareUser{Username: username, Language: msg.Language, Coredata: coredata}
	err = s.db.NewUser(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not store new user in database")
		return nil, err
	}

	// Send email if user specified email address
	if msg.Email != nil && *msg.Email != "" && s.conf.EmailServer != "" {
		err = s.sendRegistrationEmail(user, msg.Language, *msg.Email)
		if err != nil {
			// already logged in sendRegistrationEmail
			return nil, err
		}
	}

	// Setup and return issuance session for keyshare credential.
	request := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: s.conf.KeyshareAttribute.CredentialTypeIdentifier(),
			Attributes: map[string]string{
				s.conf.KeyshareAttribute.Name(): username,
			},
		}})
	sessionptr, _, err := s.sessionserver.StartSession(request, nil)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not start keyshare credential issuance sessions")
		return nil, err
	}
	return sessionptr, nil
}

func (s *Server) sendRegistrationEmail(user *KeyshareUser, language, email string) error {
	// Fetch template and configuration data for users language, falling back if needed
	template := s.conf.TranslateTemplate(s.conf.registrationEmailTemplates, language)
	verificationBaseURL := s.conf.TranslateString(s.conf.VerificationURL, language)
	subject := s.conf.TranslateString(s.conf.RegistrationEmailSubject, language)

	// Generate token
	token := common.NewSessionToken()

	// Add it to the database
	err := s.db.AddEmailVerification(user, email, token)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not generate email verification mail record")
		return err
	}

	// Build message
	var msg bytes.Buffer
	err = template.Execute(&msg, map[string]string{"VerificationURL": verificationBaseURL + token})
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not generate email verification mail")
		return err
	}

	// And send it
	err = server.SendHTMLMail(
		s.conf.EmailServer,
		s.conf.EmailAuth,
		s.conf.EmailFrom,
		email,
		subject,
		msg.Bytes())

	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not send email verification mail")
		return err
	}

	return nil
}

func (s *Server) userMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract username from request
		username := r.Header.Get("X-IRMA-Keyshare-Username")

		// and fetch its information
		user, err := s.db.User(username)
		if err != nil {
			s.conf.Logger.WithFields(logrus.Fields{"username": username, "error": err}).Warn("Could not find user in db")
			server.WriteError(w, server.ErrorUserNotRegistered, err.Error())
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "user", user)))
	})
}

func (s *Server) authorizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract authorization from request
		authorization := r.Header.Get("Authorization")
		if strings.HasPrefix(authorization, "Bearer ") {
			authorization = authorization[7:]
		}

		// verify access
		ctx := r.Context()
		err := s.core.ValidateJWT(ctx.Value("user").(*KeyshareUser).Coredata, authorization)
		hasValidAuthorization := err == nil

		// Construct new context with both authorization and its validity
		nextContext := context.WithValue(
			context.WithValue(ctx, "authorization", authorization),
			"hasValidAuthorization", hasValidAuthorization)

		next.ServeHTTP(w, r.WithContext(nextContext))
	})
}

func (s *Server) reservePinCheck(user *KeyshareUser, pin string) (bool, int, int64, error) {
	ok, tries, wait, err := s.db.ReservePincheck(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reserve pin check slot")
		return false, 0, 0, err
	}
	if !ok {
		err = s.db.AddLog(user, PinCheckRefused, nil)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
			return false, 0, 0, err
		}
		return false, tries, wait, nil
	}
	return true, tries, wait, nil
}
