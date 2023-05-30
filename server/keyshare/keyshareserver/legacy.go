package keyshareserver

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"

	"github.com/go-errors/errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/privacybydesign/gabi/signed"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/keyshare"
	"github.com/sirupsen/logrus"
)

// /users/register_publickey
func (s *Server) handleRegisterPublicKey(w http.ResponseWriter, r *http.Request) {
	var msg irma.KeyshareKeyRegistration
	if err := server.ParseBody(r, &msg); err != nil {
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	var (
		pk     *ecdsa.PublicKey
		claims = &irma.KeyshareKeyRegistrationClaims{}
		err    error
	)
	_, err = jwt.ParseWithClaims(msg.PublicKeyRegistrationJWT, claims, func(token *jwt.Token) (interface{}, error) {
		pk, err = signed.UnmarshalPublicKey(claims.PublicKey)
		return pk, err
	})
	if err != nil {
		keyshare.WriteError(w, err)
		return
	}

	// Fetch user
	user, err := s.db.user(r.Context(), claims.Username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": claims.Username, "error": err}).Warn("Could not find user in db")
		keyshare.WriteError(w, err)
		return
	}

	result, err := s.registerPublicKey(r.Context(), user, claims.Pin, pk)
	if err != nil {
		// already logged
		keyshare.WriteError(w, err)
		return
	}
	server.WriteJson(w, result)
}

func (s *Server) registerPublicKey(ctx context.Context, user *User, pin string, pk *ecdsa.PublicKey) (irma.KeysharePinStatus, error) {
	// Check whether pin check is currently allowed
	ok, tries, wait, err := s.reservePinCheck(ctx, user)
	if err != nil {
		return irma.KeysharePinStatus{}, err
	}
	if !ok {
		return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
	}

	var jwtt string
	jwtt, user.Secrets, err = s.core.SetUserPublicKey(user.Secrets, pin, pk)
	if err == keysharecore.ErrInvalidPin {
		if tries == 0 {
			return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
		} else {
			return irma.KeysharePinStatus{Status: "failure", Message: fmt.Sprintf("%v", tries)}, nil
		}
	} else if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not set user public key")
		return irma.KeysharePinStatus{}, err
	}

	// Mark pincheck as success, resetting users wait and count
	err = s.db.resetPinTries(ctx, user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reset users pin check logic")
		// Do not send to user
	}

	// Write user back
	err = s.db.updateUser(ctx, user)
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

func (s *Server) updatePinLegacy(ctx context.Context, user *User, oldPin, newPin string) (irma.KeysharePinStatus, error) {
	// Check whether pin check is currently allowed
	ok, tries, wait, err := s.reservePinCheck(ctx, user)
	if err != nil {
		return irma.KeysharePinStatus{}, err
	}
	if !ok {
		return irma.KeysharePinStatus{Status: "error", Message: fmt.Sprintf("%v", wait)}, nil
	}

	// Try to do the update
	user.Secrets, err = s.core.ChangePinLegacy(user.Secrets, oldPin, newPin)
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
	err = s.db.resetPinTries(ctx, user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not reset users pin check logic")
		// Do not send to user
	}

	// Write user back
	err = s.db.updateUser(ctx, user)
	if err != nil {
		s.conf.Logger.WithField("error", err).Error("Could not write updated user to database")
		return irma.KeysharePinStatus{}, err
	}

	return irma.KeysharePinStatus{Status: "success"}, nil
}

func (s *Server) handleChangePinLegacy(ctx context.Context, w http.ResponseWriter, msg irma.KeyshareChangePinData) {
	username := msg.Username
	user, err := s.db.user(ctx, username)
	if err != nil {
		s.conf.Logger.WithFields(logrus.Fields{"username": username, "error": err}).Warn("Could not find user in db")
		keyshare.WriteError(w, err)
		return
	}

	result, err := s.updatePinLegacy(ctx, user, msg.OldPin, msg.NewPin)

	if err != nil {
		// already logged
		keyshare.WriteError(w, err)
		return
	}
	server.WriteJson(w, result)
}
