package keyshare

import (
	"github.com/go-errors/errors"
	"github.com/privacybydesign/irmago/internal/keysharecore"
	"github.com/privacybydesign/irmago/server"
	"net/http"
)

var (
	// Database errors:

	ErrUserNotFound = errors.New("could not find specified user")

	// Email errors:

	ErrInvalidEmail = errors.New("invalid email address")
)

func WriteError(w http.ResponseWriter, err error) {
	var msg string
	if err != nil {
		msg = err.Error()
	}

	var serverError server.Error
	switch err {
	case ErrUserNotFound:
		serverError = server.ErrorUserNotRegistered
	case ErrInvalidEmail:
		serverError = server.ErrorInvalidRequest
	case keysharecore.ErrInvalidPin:
		// This error should never be handled here. We want to include information about how
		// many PIN attempts the user has left, and if zero, how long the user is blocked.
		serverError = server.ErrorInternal
	case keysharecore.ErrPinTooLong:
		serverError = server.ErrorInvalidRequest
	case keysharecore.ErrInvalidChallenge:
		serverError = server.ErrorInvalidRequest
	case keysharecore.ErrInvalidJWT:
		serverError = server.ErrorInvalidRequest
	case keysharecore.ErrKeyNotFound:
		serverError = server.ErrorInvalidRequest
	case keysharecore.ErrUnknownCommit:
		// Commit IDs are only used for internal bookkeeping, so this must be a server issue.
		serverError = server.ErrorInternal
	case keysharecore.ErrChallengeResponseRequired:
		serverError = server.ErrorUnexpectedRequest
	case keysharecore.ErrWrongChallenge:
		serverError = server.ErrorUnexpectedRequest
	default:
		serverError = server.ErrorInternal
	}

	server.WriteError(w, serverError, msg)
}
