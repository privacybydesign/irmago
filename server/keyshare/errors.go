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

	switch err {
	case ErrUserNotFound:
		server.WriteError(w, server.ErrorUserNotRegistered, msg)
	case ErrInvalidEmail:
		server.WriteError(w, server.ErrorInvalidRequest, msg)
	case keysharecore.ErrInvalidPin:
		// This error should never be handled here. We want to include information about how
		// many PIN attempts the user has left, and if zero, how long the user is blocked.
		server.WriteError(w, server.ErrorInternal, msg)
	case keysharecore.ErrPinTooLong:
		server.WriteError(w, server.ErrorInvalidRequest, msg)
	case keysharecore.ErrInvalidChallenge:
		server.WriteError(w, server.ErrorInvalidRequest, msg)
	case keysharecore.ErrInvalidJWT:
		server.WriteError(w, server.ErrorInvalidRequest, msg)
	case keysharecore.ErrKeyNotFound:
		server.WriteError(w, server.ErrorInvalidRequest, msg)
	case keysharecore.ErrUnknownCommit:
		// Commit IDs are only used for internal bookkeeping, so this must be a server issue.
		server.WriteError(w, server.ErrorInternal, msg)
	case keysharecore.ErrChallengeResponseRequired:
		server.WriteError(w, server.ErrorUnexpectedRequest, msg)
	case keysharecore.ErrWrongChallenge:
		server.WriteError(w, server.ErrorUnexpectedRequest, msg)
	default:
		server.WriteError(w, server.ErrorInternal, msg)
	}
}
