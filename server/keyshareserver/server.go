package keyshareserver

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

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

	// Do initial processing of configuration and create keyshare core
	s.core, err = processConfiguration(conf)
	if err != nil {
		return nil, err
	}

	// Load neccessary idemix keys into core, and ensure that future updates
	// to them are processed
	s.LoadIdemixKeys(conf.ServerConfiguration.IrmaConfiguration)
	conf.ServerConfiguration.IrmaConfiguration.UpdateListeners = append(
		conf.ServerConfiguration.IrmaConfiguration.UpdateListeners,
		s.LoadIdemixKeys)

	// Setup IRMA session server
	s.sessionserver, err = irmaserver.New(conf.ServerConfiguration)
	if err != nil {
		return nil, err
	}

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
		router.Use(server.LogMiddleware("keyshare-app", opts))
	}

	// Registration
	router.Post("/client/register", s.handleRegister)

	// Pin and login
	router.Post("/users/isAuthorized", s.handleValidate)
	router.Post("/users/verify/pin", s.handleVerifyPin)
	router.Post("/users/change/pin", s.handleChangePin)

	// Keyshare sessions
	router.Post("/prove/getCommitments", s.handleCommitments)
	router.Post("/prove/getResponse", s.handleResponse)

	// IRMA server for issuing myirma credential during registration
	router.Mount("/irma/", s.sessionserver.HandlerFunc())
	return router
}

// On configuration changes, inform the keyshare core of any
// new IRMA issuer public keys.
func (s *Server) LoadIdemixKeys(conf *irma.Configuration) {
	for _, issuer := range conf.Issuers {
		keyIDs, err := conf.PublicKeyIndices(issuer.Identifier())
		if err != nil {
			s.conf.Logger.WithFields(logrus.Fields{"issuer": issuer, "error": err}).Warn("Could not find keyIDs for issuer")
			continue
		}
		for _, id := range keyIDs {
			key, err := conf.PublicKey(issuer.Identifier(), id)
			if err != nil {
				s.conf.Logger.WithFields(logrus.Fields{"keyID": id, "error": err}).Warn("Could not fetch public key for issuer")
				continue
			}
			s.core.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: issuer.Identifier(), Counter: uint(id)}, key)
		}
	}
}

// /prove/getCommitments
func (s *Server) handleCommitments(w http.ResponseWriter, r *http.Request) {
	// Read keys
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read request body")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	var keys []irma.PublicKeyIdentifier
	err = json.Unmarshal(body, &keys)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not parse request body")
		s.conf.Logger.WithField("body", body).Debug("Malformed request data")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	if len(keys) == 0 {
		s.conf.Logger.Info("Malformed request: no keys over which to commit specified")
		server.WriteError(w, server.ErrorInvalidRequest, "No key specified")
		return
	}

	// Extract username and authorization from request
	username := r.Header.Get("X-IRMA-Keyshare-Username")
	authorization := r.Header.Get("Authorization")
	if strings.HasPrefix(authorization, "Bearer ") {
		authorization = authorization[7:]
	}

	user, err := s.db.User(username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": username, "error": err}).Warn("User not found in db")
		server.WriteError(w, server.ErrorUserNotRegistered, err.Error())
		return
	}

	// Generate commitments
	commitments, commitID, err := s.core.GenerateCommitments(user.Data().Coredata, authorization, keys)
	if err != nil {
		s.conf.Logger.WithField("error", err).Warn("Could not generate commitments for request")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Prepare output message format
	mappedCommitments := map[string]*gabi.ProofPCommitment{}
	for i, keyID := range keys {
		keyIDV, err := keyID.MarshalText()
		if err != nil {
			s.conf.Logger.WithFields(logrus.Fields{"keyid": keyID, "error": err}).Error("Could not convert key identifier to string")
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}
		mappedCommitments[string(keyIDV)] = commitments[i]
	}

	// Store needed data for later requests.
	s.sessionLock.Lock()
	if _, ok := s.sessions[username]; !ok {
		s.sessions[username] = &SessionData{}
	}
	s.sessions[username].LastCommitID = commitID
	s.sessions[username].LastKeyID = keys[0]
	s.sessions[username].expiry = time.Now().Add(10 * time.Second)
	s.sessionLock.Unlock()

	// And send response
	server.WriteJson(w, proofPCommitmentMap{Commitments: mappedCommitments})
}

// /prove/getResponse
func (s *Server) handleResponse(w http.ResponseWriter, r *http.Request) {
	// Read challenge
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read request body")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	challenge := new(big.Int)
	err = json.Unmarshal(body, challenge)
	if err != nil {
		s.conf.Logger.Info("Malformed request: could not parse challenge")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Extract username and authorization from request
	username := r.Header.Get("X-IRMA-Keyshare-Username")
	authorization := r.Header.Get("Authorization")
	if strings.HasPrefix(authorization, "Bearer ") {
		authorization = authorization[7:]
	}

	// Fetch user
	user, err := s.db.User(username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": username, "error": err}).Warn("Could not find user in db")
		server.WriteError(w, server.ErrorUserNotRegistered, err.Error())
		return
	}

	// verify access (avoids leaking information to unauthorized callers)
	err = s.core.ValidateJWT(user.Data().Coredata, authorization)
	if err != nil {
		s.conf.Logger.WithField("error", err).Warn("Could not generate keyshare response")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Indicate activity on user account
	err = s.db.SetSeen(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not mark user as seen recently")
		// Do not send to user
	}

	// Get data from session
	s.sessionLock.Lock()
	sessionData, ok := s.sessions[username]
	s.sessionLock.Unlock()
	if !ok {
		s.conf.Logger.Warn("Request for response without previous call to get commitments")
		server.WriteError(w, server.ErrorInvalidRequest, "Missing previous call to getCommitments")
		return
	}

	// Make log entry
	err = s.db.AddLog(user, IrmaSession, nil)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	proofResponse, err := s.core.GenerateResponse(user.Data().Coredata, authorization, sessionData.LastCommitID, challenge, sessionData.LastKeyID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not generate response for request")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	server.WriteString(w, proofResponse)
}

// /users/isAuthorized
func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	// Extract username and authorization from request
	username := r.Header.Get("X-IRMA-Keyshare-Username")
	authorization := r.Header.Get("Authorization")
	if strings.HasPrefix(authorization, "Bearer ") {
		authorization = authorization[7:]
	}

	// Fetch user
	user, err := s.db.User(username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": username, "error": err}).Warn("Could not find user in db")
		server.WriteError(w, server.ErrorUserNotRegistered, err.Error())
		return
	}

	// Validate jwt
	err = s.core.ValidateJWT(user.Data().Coredata, authorization)
	if err != nil {
		server.WriteJson(w, &keyshareAuthorization{Status: "expired", Candidates: []string{"pin"}})
	} else {
		server.WriteJson(w, &keyshareAuthorization{Status: "authorized", Candidates: []string{"pin"}})
	}
}

// /users/verify/pin
func (s *Server) handleVerifyPin(w http.ResponseWriter, r *http.Request) {
	// Extract request
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read request body")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	var msg keysharePinMessage
	err = json.Unmarshal(body, &msg)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"error": err}).Info("Malformed request: could not parse request body")
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

	// And verify pin (checking that we are allowed to do this)
	ok, tries, wait, err := s.db.ReservePincheck(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reserve pin check slot")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	if !ok {
		err = s.db.AddLog(user, PinCheckRefused, nil)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}
		server.WriteJson(w, keysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)})
		return
	}
	jwtt, err := s.core.ValidatePin(user.Data().Coredata, msg.Pin, msg.Username)
	if err == keysharecore.ErrInvalidPin {
		err = s.db.AddLog(user, PinCheckFailed, tries)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}
		if tries == 0 {
			err = s.db.AddLog(user, PinCheckBlocked, wait)
			if err != nil {
				s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
				server.WriteError(w, server.ErrorInternal, err.Error())
				return
			}
			server.WriteJson(w, keysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)})
		} else {
			server.WriteJson(w, keysharePinStatus{Status: "failure", Message: fmt.Sprintf("%v", tries)})
		}
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not validate pin")
		server.WriteError(w, server.ErrorInternal, err.Error())
	} else {
		err = s.db.ClearPincheck(user)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not reset users pin check logic")
			// Do not send to user
		}

		// Indicate activity on user account
		err = s.db.SetSeen(user)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not indicate user activity")
			// Do not send to user
		}

		err = s.db.AddLog(user, PinCheckSuccess, nil)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}

		server.WriteJson(w, keysharePinStatus{Status: "success", Message: jwtt})
	}
}

// /users/change/pin
func (s *Server) handleChangePin(w http.ResponseWriter, r *http.Request) {
	// Extract request
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read request body")
		server.WriteError(w, server.ErrorInvalidRequest, "could not read request body")
		return
	}
	var msg keyshareChangePin
	err = json.Unmarshal(body, &msg)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not parse request body")
		server.WriteError(w, server.ErrorInvalidRequest, "Invalid request")
		return
	}

	// Fetch user
	user, err := s.db.User(msg.Username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": msg.Username, "error": err}).Warn("Could not find user in db")
		server.WriteError(w, server.ErrorUserNotRegistered, "")
		return
	}

	// And change pin, checking that we are allowed to do this
	ok, tries, wait, err := s.db.ReservePincheck(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reserve pin check slot")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	if !ok {
		server.WriteJson(w, keysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)})
		return
	}
	user.Data().Coredata, err = s.core.ChangePin(user.Data().Coredata, msg.OldPin, msg.NewPin)
	if err == keysharecore.ErrInvalidPin {
		if tries == 0 {
			server.WriteJson(w, keysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)})
		} else {
			server.WriteJson(w, keysharePinStatus{Status: "failure", Message: fmt.Sprintf("%v", tries)})
		}
		return
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not change pin")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	err = s.db.ClearPincheck(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reset users pin check logic")
		// Do not send to user
	}

	// Write user back
	err = s.db.UpdateUser(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not write updated user to database")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	// And return success
	server.WriteJson(w, keysharePinStatus{Status: "success"})
}

// /client/register
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// Extract request
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read request body")
		server.WriteError(w, server.ErrorInvalidRequest, "could not read request body")
		return
	}
	var msg keyshareEnrollment
	err = json.Unmarshal(body, &msg)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not parse request body")
		server.WriteError(w, server.ErrorInvalidRequest, "Invalid request")
		return
	}

	// Generate keyshare server account
	username := generateUsername()
	coredata, err := s.core.GenerateKeyshareSecret(msg.Pin)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not register user")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	user, err := s.db.NewUser(KeyshareUserData{Username: username, Language: msg.Language, Coredata: coredata})
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not store new user in database")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	// Send email if user specified email address
	if msg.Email != nil && *msg.Email != "" && s.conf.EmailServer != "" {
		// Fetch template and configuration data for users language, falling back if needed
		template, ok := s.conf.RegistrationEmailTemplates[msg.Language]
		if !ok {
			template = s.conf.RegistrationEmailTemplates[s.conf.DefaultLanguage]
		}
		verificationBaseURL, ok := s.conf.VerificationURL[msg.Language]
		if !ok {
			verificationBaseURL = s.conf.VerificationURL[s.conf.DefaultLanguage]
		}
		subject, ok := s.conf.RegistrationEmailSubject[msg.Language]
		if !ok {
			subject = s.conf.RegistrationEmailSubject[s.conf.DefaultLanguage]
		}

		// Generate token
		token := common.NewSessionToken()

		// Add it to the database
		err = s.db.AddEmailVerification(user, *msg.Email, token)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not add email verification record to user")
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}

		// Build message
		var emsg bytes.Buffer
		err = template.Execute(&emsg, map[string]string{"VerificationURL": verificationBaseURL + token})
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not generate email verifcation mail")
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}

		// And send it
		err = server.SendHTMLMail(
			s.conf.EmailServer,
			s.conf.EmailAuth,
			s.conf.EmailFrom,
			*msg.Email,
			subject,
			emsg.Bytes())

		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not send email verifiation mail")
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}
	}

	// Setup and return issuance session for keyshare credential.
	request := irma.NewIssuanceRequest([]*irma.CredentialRequest{
		{
			CredentialTypeID: irma.NewCredentialTypeIdentifier(s.conf.KeyshareCredential),
			Attributes: map[string]string{
				s.conf.KeyshareAttribute: username,
			},
		}})
	sessionptr, _, err := s.sessionserver.StartSession(request, nil)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not start keyshare credential issuance sessions")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	server.WriteResponse(w, sessionptr, nil)
}

// Generate a base62 "username".
//  this is a direct port of what the old java server uses.
func generateUsername() string {
	bts := make([]byte, 8)
	_, err := rand.Read(bts)
	if err != nil {
		panic(err)
	}
	raw := make([]byte, 12)
	base64.StdEncoding.Encode(raw, bts)
	return strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(
				string(raw),
				"+",
				""),
			"/",
			""),
		"=",
		"")
}
