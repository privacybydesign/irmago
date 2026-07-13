package wallet

import (
	"fmt"

	"github.com/privacybydesign/irmago/common/clientmodels"
)

// sessionErrorToError flattens a clientmodels.SessionError (the protocol
// clients' structured failure type) into a plain error for the wallet's
// synchronous API. phase is "issuance" or "disclosure".
func sessionErrorToError(phase string, err *clientmodels.SessionError) error {
	if err == nil {
		return fmt.Errorf("wallet: %s session failed", phase)
	}
	msg := err.WrappedError
	if msg == "" {
		msg = err.Info
	}
	if err.RemoteError != nil && err.RemoteError.Description != "" {
		msg = fmt.Sprintf("%s (remote: %s)", msg, err.RemoteError.Description)
	}
	if err.ErrorType != "" {
		return fmt.Errorf("wallet: %s session failed [%s]: %s", phase, err.ErrorType, msg)
	}
	return fmt.Errorf("wallet: %s session failed: %s", phase, msg)
}
