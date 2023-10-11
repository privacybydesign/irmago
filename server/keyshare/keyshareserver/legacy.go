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
		server.WriteError(w, server.ErrorInvalidRequest, err.Error())
		return
	}

	// Fetch user
	user, err := s.db.user(r.Context(), claims.Username)
	if err != nil {
		// Already logged
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
	jwtt, secrets, err := s.core.SetUserPublicKey(keysharecore.UserSecrets(user.Secrets), pin, pk)
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
	user.Secrets = UserSecrets(secrets)

	// Mark pincheck as success, resetting users wait and count. Do not send error to user.
	_ = s.db.resetPinTries(ctx, user)

	// Write user back
	err = s.db.updateUser(ctx, user)
	if err != nil {
		// Already logged
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
	secrets, err := s.core.ChangePinLegacy(keysharecore.UserSecrets(user.Secrets), oldPin, newPin)
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
	user.Secrets = UserSecrets(secrets)

	// Mark pincheck as success, resetting users wait and count. Do not send error to user.
	_ = s.db.resetPinTries(ctx, user)

	// Write user back
	err = s.db.updateUser(ctx, user)
	if err != nil {
		// Already logged
		return irma.KeysharePinStatus{}, err
	}

	return irma.KeysharePinStatus{Status: "success"}, nil
}

func (s *Server) handleChangePinLegacy(ctx context.Context, w http.ResponseWriter, msg irma.KeyshareChangePinData) {
	username := msg.Username
	user, err := s.db.user(ctx, username)
	if err != nil {
		// Already logged
		keyshare.WriteError(w, err)
		return
	}

	result, err := s.updatePinLegacy(ctx, user, msg.OldPin, msg.NewPin)

	if err != nil {
		// Already logged
		keyshare.WriteError(w, err)
		return
	}
	server.WriteJson(w, result)
}
