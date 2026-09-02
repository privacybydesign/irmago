package eudi

import (
	"errors"
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/trust"
)

// ErrPartyValidation marks an error as the identity gate rejecting the party on
// the other end of a session: a broken, expired or revoked certificate chain, an
// invalid request signature, an unresolvable DID. Wrapped around the failure
// that actually happened, so the session error carries a code the app can
// switch on — "the request is not trustworthy, nothing was shared" rather than
// "try again".
//
// A party nobody vouches for is not this: that is a low trust level, and the
// session proceeds (subject to the policy, see trust.CheckMinimum).
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
// identity gate failure.
func IsPartyValidationFailure(err error) bool {
	return errors.Is(err, ErrPartyValidation)
}

// SessionErrorType is the code a failed session reports err under: one the app
// switches on when the party was rejected, its level fell short of the policy,
// or the app must update; the empty generic code otherwise. Next to the markers
// so both protocols map them the same way.
func SessionErrorType(err error) string {
	switch {
	case errors.Is(err, ErrPartyValidation):
		return clientmodels.ErrorType_PartyValidationFailed
	case errors.Is(err, trust.ErrBelowMinimumTrustLevel):
		return clientmodels.ErrorType_TrustLevelBelowMinimum
	case errors.Is(err, trust.ErrAppUpdateRequired):
		return clientmodels.ErrorType_AppUpdateRequired
	}
	return ""
}
