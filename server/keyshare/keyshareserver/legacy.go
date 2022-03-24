package keyshareserver

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

// /users/register_publickey
func (s *Server) handleRegisterPublicKey(w http.ResponseWriter, r *http.Request) {
	var msg irma.KeysharePublicKeyRegistration
	if err := server.ParseBody(r, &msg); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	var (
		pk     *ecdsa.PublicKey
		claims = &irma.KeysharePublicKeyRegistrationClaims{}
		err    error
	)
	_, err = jwt.ParseWithClaims(msg.PublicKeyRegistrationJWT, claims, func(token *jwt.Token) (interface{}, error) {
		pk, err = signed.UnmarshalPublicKey(claims.PublicKey)
		return pk, err
	})
	if err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Fetch user
	user, err := s.db.user(claims.Username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": claims.Username, "error": err}).Warn("Could not find user in db")
		server.WriteError(w, server.ErrorUserNotRegistered, "")
		return
	}

	result, err := s.registerPublicKey(user, &claims.KeysharePublicKeyRegistrationData, pk)
	if err != nil {
		// already logged
		server.WriteError(w, server.ErrorInternal, err.Error())
		return
	}
	server.WriteJson(w, result)
}

func (s *Server) registerPublicKey(user *User, keydata *irma.KeysharePublicKeyRegistrationData, pk *ecdsa.PublicKey) (irma.KeysharePinStatus, error) {
	// Check whether pin check is currently allowed
	ok, _, wait, err := s.reservePinCheck(user)
	if err != nil {
		return irma.KeysharePinStatus{}, err
	}
	if !ok {
		return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
	}

	jwtt, err := s.core.SetUserPublicKey(user.Secrets, keydata.Pin, pk)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not set user public key")
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

	return irma.KeysharePinStatus{Status: "success", Message: jwtt}, nil
}

func parseLegacyRegistrationMessage(msg irma.KeyshareEnrollment) (*irma.KeyshareEnrollmentData, *ecdsa.PublicKey, error) {
	if msg.KeyshareEnrollmentData.PublicKey != nil {
		return nil, nil, errors.New("when public key is specified, registration message must be signed")
	}
	return &msg.KeyshareEnrollmentData, nil, nil
}
