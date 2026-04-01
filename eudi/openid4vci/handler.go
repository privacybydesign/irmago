package openid4vci

import (
	"github.com/privacybydesign/irmago/common/clientmodels"
)

// AuthCodeHandler is a callback for providing the authorization code from the app side.
type AuthCodeHandler func(proceed bool, code *string)

// TokenHandler is a callback for providing the access token (and optionally refresh token)
// from the app side when the authorization has completed, the code was exchanged for an access token and the flow is hereby returned to the app.
type TokenHandler func(proceed bool, accessToken string, refreshToken *string)

// TokenPermissionHandler is a callback for providing permission for an Pre-Authorized Code issuance session to proceed.
type TokenPermissionHandler func(proceed bool, transactionCode *string)

// SessionDismisser allows dismissing the current session.
type SessionDismisser interface {
	Dismiss()
}

type Handler interface {
	// Shared interface functions with irmaclient.Handler
	Success(result string)
	Cancelled()
	Failure(err *clientmodels.SessionError)

	// OpenID specific interface functions
	RequestPreAuthorizedCodeFlowPermission(
		request *clientmodels.PreAuthorizedCodeFlowPermissionRequest,
		requestorInfo *clientmodels.TrustedParty,
		callback TokenPermissionHandler,
	)

	RequestAuthorizationCodeFlowPermission(
		request *clientmodels.AuthorizationCodeFlowRequest,
		requestorInfo *clientmodels.TrustedParty,
		callback AuthCodeHandler,
	)
}
