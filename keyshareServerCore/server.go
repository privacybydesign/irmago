package keyshareServerCore

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/privacybydesign/gabi"
	"github.com/privacybydesign/gabi/big"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"

	"github.com/privacybydesign/irmago/keyshareCore"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

type SessionData struct {
	LastKeyid    irma.PublicKeyIdentifier
	LastCommitID uint64
}

type Server struct {
	conf *Configuration

	core          *keyshareCore.KeyshareCore
	sessionserver *irmaserver.Server
	db            KeyshareDB

	sessions    map[string]*SessionData
	sessionLock sync.Mutex
}

func New(conf *Configuration) (*Server, error) {
	var err error
	s := &Server{
		conf:     conf,
		sessions: map[string]*SessionData{},
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

	// Setup irma session server
	s.sessionserver, err = irmaserver.New(conf.ServerConfiguration)
	if err != nil {
		return nil, err
	}

	// Setup DB
	s.db = conf.DB

	return s, nil
}

func (s *Server) Handler() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Post("/api/v1/client/register", s.handleRegister)
	router.Post("/api/v1/users/isAuthorized", s.handleValidate)
	router.Post("/api/v1/users/verify/pin", s.handleVerifyPin)
	router.Post("/api/v1/users/change/pin", s.handleChangePin)
	router.Post("/api/v1/prove/getCommitments", s.handleCommitments)
	router.Post("/api/v1/prove/getResponse", s.handleResponse)
	router.Mount("/irma/", s.sessionserver.HandlerFunc())
	return router
}

func (s *Server) LoadIdemixKeys(conf *irma.Configuration) {
	for _, issuer := range conf.Issuers {
		keyIds, err := conf.PublicKeyIndices(issuer.Identifier())
		if err != nil {
			s.conf.Logger.WithFields(logrus.Fields{"issuer": issuer, "error": err}).Warn("Could not find key ids for issuer")
			continue
		}
		for _, id := range keyIds {
			key, err := conf.PublicKey(issuer.Identifier(), id)
			if err != nil {
				s.conf.Logger.WithFields(logrus.Fields{"keyid": id, "error": err}).Warn("Could not fetch public key for issuer")
				continue
			}
			s.core.DangerousAddTrustedPublicKey(irma.PublicKeyIdentifier{Issuer: issuer.Identifier(), Counter: uint(id)}, key)
		}
	}
}

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

	user, err := s.db.User(username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": username, "error": err}).Warn("User not found in db")
		server.WriteError(w, server.ErrorUserNotRegistered, err.Error())
		return
	}

	// Generate commitments
	commitments, commitId, err := s.core.GenerateCommitments(user.Data().Coredata, authorization, keys)
	if err != nil {
		s.conf.Logger.WithField("error", err).Warn("Could not generate commitments for request")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Prepare output message format
	mappedCommitments := map[string]*gabi.ProofPCommitment{}
	for i, keyid := range keys {
		keyidV, err := keyid.MarshalText()
		if err != nil {
			s.conf.Logger.WithFields(logrus.Fields{"keyid": keyid, "error": err}).Error("Could not convert key identifier to string")
			server.WriteError(w, server.ErrorInternal, err.Error())
			return
		}
		mappedCommitments[string(keyidV)] = commitments[i]
	}

	// Store needed data for later requests.
	s.sessionLock.Lock()
	if _, ok := s.sessions[username]; !ok {
		s.sessions[username] = &SessionData{}
	}
	s.sessions[username].LastCommitID = commitId
	s.sessions[username].LastKeyid = keys[0]
	s.sessionLock.Unlock()

	// And send response
	server.WriteJson(w, proofPCommitmentMap{Commitments: mappedCommitments})
}

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

	proofResponse, err := s.core.GenerateResponse(user.Data().Coredata, authorization, sessionData.LastCommitID, challenge, sessionData.LastKeyid)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not generate response for request")
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	server.WriteString(w, proofResponse)
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	// Extract username and authorization from request
	username := r.Header.Get("X-IRMA-Keyshare-Username")
	authorization := r.Header.Get("Authorization")

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
		server.WriteJson(w, keysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)})
		return
	}
	jwtt, err := s.core.ValidatePin(user.Data().Coredata, msg.Pin, msg.Username)
	if err == keyshareCore.ErrInvalidPin {
		if tries == 0 {
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

		server.WriteJson(w, keysharePinStatus{Status: "success", Message: jwtt})
	}
}

func (s *Server) handleChangePin(w http.ResponseWriter, r *http.Request) {
	// Extract request
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.conf.Logger.WithField("error", err).Info("Malformed request: could not read request body")
		server.WriteError(w, server.ErrorInvalidRequest, "could not read request body")
		return
	}
	var msg keyshareChangepin
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
	if err == keyshareCore.ErrInvalidPin {
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
	err = s.db.NewUser(KeyshareUserData{Username: username, Coredata: coredata})
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not store new user in database")
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
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
