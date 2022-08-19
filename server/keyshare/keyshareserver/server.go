package keyshareserver

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-co-op/gocron"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/hashicorp/go-multierror"
	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"

	"github.com/privacybydesign/irmago/internal/common"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/privacybydesign/irmago/server/keyshare"

	"github.com/go-chi/chi/v5"
)

type Server struct {
	// configuration
	conf *Configuration

	// external components
	core     *keysharecore.Core
	irmaserv *irmaserver.Server
	db       DB

	// Scheduler used to clean sessions
	scheduler *gocron.Scheduler

	// Session data, keeping track of current keyshare protocol session state for each user
	store sessionStore
}

var errMissingCommitment = errors.New("missing previous call to getCommitments")

func New(conf *Configuration) (*Server, error) {
	var err error
	s := &Server{
		conf:      conf,
		store:     newMemorySessionStore(10 * time.Second),
		scheduler: gocron.NewScheduler(time.UTC),
	}

	// Setup IRMA session server
	s.irmaserv, err = irmaserver.New(conf.Configuration)
	if err != nil {
		return nil, err
	}

	// Process configuration and create keyshare core
	err = validateConf(conf)
	if err != nil {
		return nil, err
	}
	if conf.DB != nil {
		s.db = conf.DB
	} else {
		s.db, err = setupDatabase(conf)
		if err != nil {
			return nil, err
		}
	}
	s.core, err = setupCore(conf)
	if err != nil {
		return nil, err
	}

	// Load Idemix keys into core, and ensure that new keys added in the future will be loaded as well.
	if err = s.loadIdemixKeys(conf.IrmaConfiguration); err != nil {
		return nil, err
	}
	conf.IrmaConfiguration.UpdateListeners = append(conf.IrmaConfiguration.UpdateListeners, func(c *irma.Configuration) {
		if err := s.loadIdemixKeys(c); err != nil {
			// run periodically; can only log the error here
			_ = server.LogError(err)
		}
	})

	// Setup session cache clearing
	if _, err := s.scheduler.Every(10).Seconds().Do(s.store.flush); err != nil {
		return nil, err
	}
	s.scheduler.StartAsync()

	return s, nil
}

func (s *Server) Stop() {
	s.scheduler.Stop()
	s.irmaserv.Stop()
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()

	router.Group(func(router chi.Router) {
		router.Use(server.SizeLimitMiddleware)
		router.Use(server.TimeoutMiddleware(nil, server.WriteTimeout))

		opts := server.LogOptions{Response: true, Headers: true, From: false, EncodeBinary: true}
		router.Use(server.LogMiddleware("keyshareserver", opts))

		// Registration
		router.Post("/client/register", s.handleRegister)

		// authentication
		router.Post("/users/verify_start", s.handleVerifyStart)
		// The following two are so similar that they are both handled by handleVerify().
		// NB: handleVerify() contains the strings "/users/verify/pin" and "/users/verify/pin_challengeresponse"
		// to check, using its input, that the user has invoked the correct endpoint.
		router.Post("/users/verify/pin", s.handleVerify)
		router.Post("/users/verify/pin_challengeresponse", s.handleVerify)

		// Other
		router.Post("/users/change/pin", s.handleChangePin)
		router.Post("/users/register_publickey", s.handleRegisterPublicKey)

		// Keyshare sessions
		router.Group(func(router chi.Router) {
			router.Use(s.userMiddleware)
			router.Use(s.authorizationMiddleware)
			router.Post("/prove/getCommitments", s.handleCommitments)
			router.Post("/prove/getResponse", s.handleResponse)
		})
	})

	// IRMA server for issuing myirma credential during registration
	router.Mount("/irma/", s.irmaserv.HandlerFunc())
	return router
}

// On configuration changes, update the keyshare core with all current public keys of the IRMA issuers.
func (s *Server) loadIdemixKeys(conf *irma.Configuration) error {
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
	user := r.Context().Value("user").(*User)
	authorization := r.Context().Value("authorization").(string)

	// Read keys
	var keys []irma.PublicKeyIdentifier
	if err := server.ParseBody(r, &keys); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	if len(keys) == 0 {
		s.conf.Logger.Info("Malformed request: no keys for commitment specified")
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

func (s *Server) generateCommitments(user *User, authorization string, keys []irma.PublicKeyIdentifier) (*irma.ProofPCommitmentMap, error) {
	// Generate commitments
	commitments, commitID, err := s.core.GenerateCommitments(user.Secrets, authorization, keys)
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
	// Of all keys involved in the current session, store the ID of the first one to be used when
	// the user comes back later to retrieve her response. gabi.ProofP.P will depend on this public
	// key, which is used only during issuance. Thus, this assumes that during issuance, the user
	// puts the key ID of the credential(s) being issued at index 0.
	s.store.add(user.Username, &session{
		KeyID:    keys[0],
		CommitID: commitID,
	})

	// And send response
	return &irma.ProofPCommitmentMap{Commitments: mappedCommitments}, nil
}

// /prove/getResponse
func (s *Server) handleResponse(w http.ResponseWriter, r *http.Request) {
	// Fetch from context
	user := r.Context().Value("user").(*User)
	authorization := r.Context().Value("authorization").(string)

	// Read challenge
	challenge := new(big.Int)
	if err := server.ParseBody(r, challenge); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// verify access (avoids leaking whether there is a session ongoing to unauthorized callers)
	if !r.Context().Value("hasValidAuthorization").(bool) {
		s.conf.Logger.Warn("Could not generate keyshare response due to invalid authorization")
		server.WriteError(w, server.ErrorInvalidRequest, "Invalid authorization")
		return
	}

	// And do the actual responding
	proofResponse, err := s.generateResponse(user, authorization, challenge)
	if err != nil &&
		(err == keysharecore.ErrInvalidChallenge ||
			err == keysharecore.ErrInvalidJWT ||
			err == errMissingCommitment) {
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

func (s *Server) generateResponse(user *User, authorization string, challenge *big.Int) (string, error) {
	// Get data from session
	sessionData := s.store.get(user.Username)
	if sessionData == nil {
		s.conf.Logger.Warn("Request for response without previous call to get commitments")
		return "", errMissingCommitment
	}

	// Indicate activity on user account
	err := s.db.setSeen(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not mark user as seen recently")
		// Do not send to user
	}

	// Make log entry
	err = s.db.addLog(user, eventTypeIRMASession, nil)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
		return "", err
	}

	proofResponse, err := s.core.GenerateResponse(user.Secrets, authorization, sessionData.CommitID, challenge, sessionData.KeyID)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not generate response for request")
		return "", err
	}

	return proofResponse, nil
}

// /users/verify_start
func (s *Server) handleVerifyStart(w http.ResponseWriter, r *http.Request) {
	// Extract request
	var msg irma.KeyshareAuthRequest
	if err := server.ParseBody(r, &msg); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	claims := &irma.KeyshareAuthRequestClaims{}
	// We need the username inside the JWT here. The JWT is verified later within startAuth().
	_, _, err := jwt.NewParser().ParseUnverified(msg.AuthRequestJWT, claims)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Failed to parse challenge-response JWT")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	// Fetch user
	user, err := s.db.user(claims.Username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": claims.Username, "error": err}).Warn("Could not find user in db")
		server.WriteError(w, server.ErrorUserNotRegistered, "")
		return
	}

	result, err := s.startAuth(user, msg.AuthRequestJWT)
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteJson(w, result)
}

func (s *Server) startAuth(user *User, jwtt string) (irma.KeyshareAuthChallenge, error) {
	challenge, err := s.core.GenerateChallenge(user.Secrets, jwtt)
	if err != nil {
		return irma.KeyshareAuthChallenge{}, err
	}
	return irma.KeyshareAuthChallenge{
		Candidates: []string{irma.KeyshareAuthMethodChallengeResponse},
		Challenge:  challenge,
	}, nil
}

// /users/verify/pin or /users/verify/pin_challengeresponse
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	// Extract request
	var msg irma.KeyshareAuthResponse
	if err := server.ParseBody(r, &msg); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	var username string
	if msg.AuthResponseJWT == "" {
		if r.URL.Path != "/users/verify/pin" {
			server.WriteError(w, server.ErrorInvalidRequest, "wrong endpoint")
			return
		}
		username = msg.Username
	} else {
		if r.URL.Path != "/users/verify/pin_challengeresponse" {
			server.WriteError(w, server.ErrorInvalidRequest, "wrong endpoint")
			return
		}
		claims := &irma.KeyshareAuthResponseClaims{}
		// We need the username inside the JWT here. The JWT is verified later within verifyAuth().
		_, _, err := jwt.NewParser().ParseUnverified(msg.AuthResponseJWT, claims)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Failed to parse challenge-response JWT")
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}
		username = claims.Username
	}

	// Fetch user
	user, err := s.db.user(username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": username, "error": err}).Warn("Could not find user in db")
		server.WriteError(w, server.ErrorUserNotRegistered, "")
		return
	}

	// and verify pin
	result, err := s.verifyAuth(user, msg)
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}

	server.WriteJson(w, result)
}

func (s *Server) verifyAuth(user *User, msg irma.KeyshareAuthResponse) (irma.KeysharePinStatus, error) {
	// Check whether pin check is currently allowed
	ok, tries, wait, err := s.reservePinCheck(user)
	if err != nil {
		return irma.KeysharePinStatus{}, err
	}
	if !ok {
		return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
	}

	// At this point, we are allowed to do an actual check (we have successfully reserved a spot for it), so do it.
	var jwtt string
	if msg.AuthResponseJWT == "" {
		jwtt, err = s.core.ValidateAuthLegacy(user.Secrets, msg.Pin)
	} else {
		jwtt, err = s.core.ValidateAuth(user.Secrets, msg.AuthResponseJWT)
	}

	if err != nil && err != keysharecore.ErrInvalidPin {
		// Errors other than invalid pin are real errors
		s.conf.Logger.WithField("error", err).Error("Could not validate pin")
		return irma.KeysharePinStatus{}, err
	}

	if err == keysharecore.ErrInvalidPin {
		// Handle invalid pin
		err = s.db.addLog(user, eventTypePinCheckFailed, tries)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
			return irma.KeysharePinStatus{}, err
		}
		if tries == 0 {
			err = s.db.addLog(user, eventTypePinCheckBlocked, wait)
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
	err = s.db.resetPinTries(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reset users pin check logic")
		// Do not send to user
	}
	err = s.db.setSeen(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not indicate user activity")
		// Do not send to user
	}
	err = s.db.addLog(user, eventTypePinCheckSuccess, nil)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
		return irma.KeysharePinStatus{}, err
	}

	return irma.KeysharePinStatus{Status: "success", Message: jwtt}, err
}

// /users/change/pin
func (s *Server) handleChangePin(w http.ResponseWriter, r *http.Request) {
	// Extract request
	var (
		msg irma.KeyshareChangePin
		err error
	)
	if err = server.ParseBody(r, &msg); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	if msg.ChangePinJWT == "" {
		s.handleChangePinLegacy(w, msg.KeyshareChangePinData)
		return
	}

	claims := &irma.KeyshareChangePinClaims{}
	// We need the username inside the JWT here. The JWT is verified later within updatePin().
	_, _, err = jwt.NewParser().ParseUnverified(msg.ChangePinJWT, claims)

	user, err := s.db.user(claims.Username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": claims.Username, "error": err}).Warn("Could not find user in db")
		server.WriteError(w, server.ErrorUserNotRegistered, "")
		return
	}

	result, err := s.updatePin(user, msg.ChangePinJWT)

	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	server.WriteJson(w, result)
}

func (s *Server) updatePin(user *User, jwtt string) (irma.KeysharePinStatus, error) {
	// Check whether pin check is currently allowed
	ok, tries, wait, err := s.reservePinCheck(user)
	if err != nil {
		return irma.KeysharePinStatus{}, err
	}
	if !ok {
		return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
	}

	// Try to do the update
	user.Secrets, err = s.core.ChangePin(user.Secrets, jwtt)
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
	err = s.db.resetPinTries(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reset users pin check logic")
		// Do not send to user
	}

	// Write user back
	err = s.db.updateUser(user)
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
	if err := server.ParseBody(r, &msg); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	sessionptr, err := s.register(msg)
	if err == keysharecore.ErrPinTooLong || err == keyshare.ErrInvalidEmail {
		// Too long pin or invalid email address is not an internal error
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}
	if err == errTooManyTokens {
		server.WriteError(w, server.ErrorTooManyRequests, err.Error())
		return
	}
	if err != nil {
		// Already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	server.WriteJson(w, sessionptr)
}

func (s *Server) parseRegistrationMessage(msg irma.KeyshareEnrollment) (*irma.KeyshareEnrollmentData, *ecdsa.PublicKey, error) {
	if msg.EnrollmentJWT == "" {
		return parseLegacyRegistrationMessage(msg)
	}

	var (
		pk     *ecdsa.PublicKey
		err    error
		claims = &irma.KeyshareEnrollmentClaims{}
	)
	_, err = jwt.ParseWithClaims(msg.EnrollmentJWT, claims, func(token *jwt.Token) (interface{}, error) {
		// Similar to a CSR, the JWT contains in its body the public key with which it is signed.
		pk, err = signed.UnmarshalPublicKey(claims.KeyshareEnrollmentData.PublicKey)
		return pk, err
	})
	if err != nil {
		return nil, nil, err
	}

	return &claims.KeyshareEnrollmentData, pk, nil
}

func (s *Server) register(msg irma.KeyshareEnrollment) (*irma.Qr, error) {
	// Generate keyshare server account
	username := common.NewRandomString(12, common.AlphanumericChars)

	data, pk, err := s.parseRegistrationMessage(msg)
	if err != nil {
		return nil, err
	}
	secrets, err := s.core.NewUserSecrets(data.Pin, pk)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not register user")
		return nil, err
	}
	user := &User{Username: username, Language: data.Language, Secrets: secrets}
	err = s.db.AddUser(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not store new user in database")
		return nil, err
	}

	// Send email if user specified email address
	if data.Email != nil && *data.Email != "" && s.conf.EmailServer != "" {
		err = s.sendRegistrationEmail(user, data.Language, *data.Email)
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
	sessionptr, _, _, err := s.irmaserv.StartSession(request, nil)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not start keyshare credential issuance sessions")
		return nil, err
	}
	return sessionptr, nil
}

func (s *Server) sendRegistrationEmail(user *User, language, email string) error {
	// Generate token
	token := common.NewSessionToken()

	// Add it to the database
	err := s.db.addEmailVerification(user, email, token)
	if err != nil {
		// Rate limiting errors do not need logging.
		if err != errTooManyTokens {
			s.conf.Logger.WithField("error", err).Error("Could not generate email verification mail record")
		}
		return err
	}

	verificationBaseURL := s.conf.TranslateString(s.conf.VerificationURL, language)
	return s.conf.SendEmail(
		s.conf.registrationEmailTemplates,
		s.conf.RegistrationEmailSubjects,
		map[string]string{"VerificationURL": verificationBaseURL + token},
		email,
		language,
	)
}

func (s *Server) userMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract username from request
		username := r.Header.Get("X-IRMA-Keyshare-Username")

		// and fetch its information
		user, err := s.db.user(username)
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
		err := s.core.ValidateJWT(ctx.Value("user").(*User).Secrets, authorization)
		hasValidAuthorization := err == nil

		// Construct new context with both authorization and its validity
		nextContext := context.WithValue(
			context.WithValue(ctx, "authorization", authorization),
			"hasValidAuthorization", hasValidAuthorization)

		next.ServeHTTP(w, r.WithContext(nextContext))
	})
}

func (s *Server) reservePinCheck(user *User) (bool, int, int64, error) {
	ok, tries, wait, err := s.db.reservePinTry(user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reserve pin check slot")
		return false, 0, 0, err
	}
	if !ok {
		err = s.db.addLog(user, eventTypePinCheckRefused, nil)
		if err != nil {
			s.conf.Logger.WithField("error", err).Error("Could not add log entry for user")
			return false, 0, 0, err
		}
		return false, tries, wait, nil
	}
	return true, tries, wait, nil
}
