package eudi

import (
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// ErrPartyValidation marks an error as the identity gate rejecting the party on
// the other end of a session: a broken or revoked certificate chain, an invalid
// request signature, an unresolvable DID.
//
// It is a marker wrapped around the failure that actually happened, so the
// session error the app receives can carry a code it can switch on. That
// distinction matters to the user: a rejected party means "the request is not
// trustworthy, no data has been shared", while a network or protocol error means
// "something went wrong, try again".
//
// A party the wallet cannot find any vouching for is not this. That is a low
// trust level, and the session proceeds.
var ErrPartyValidation = errors.New("party validation failed")

// PartyValidationFailed marks err as an identity gate failure. It returns nil
// for a nil error, so it can wrap a call's error result directly.
func PartyValidationFailed(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %v", ErrPartyValidation, err)
}

// IsPartyValidationFailure reports whether err (or anything it wraps) is an
// identity gate failure, so the session can report it with a code the app
// switches on rather than as a generic error.
func IsPartyValidationFailure(err error) bool {
	return errors.Is(err, ErrPartyValidation)
}

// SessionErrorType is the code a failed session reports err under: the one the
// app switches on when the party itself was rejected, and the empty generic code
// for everything else. It lives next to the marker so both protocols read the
// marker the same way rather than each mapping it for itself.
func SessionErrorType(err error) string {
	if IsPartyValidationFailure(err) {
		return clientmodels.ErrorType_PartyValidationFailed
	}
	return ""
}
