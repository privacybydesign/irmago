package openid4vci

import "github.com/privacybydesign/irmago/irma"

// AuthCodeHandler is a callback for providing the authorization code from the app side.
type AuthCodeHandler func(proceed bool, code *string)

// TokenHandler is a callback for providing the access token (and optionally refresh token)
// from the app side when the authorization has completed, the code was exchanged for an access token and the flow is hereby returned to the app.
type TokenHandler func(proceed bool, accessToken string, refreshToken *string)

// TokenPermissionHandler is a callback for providing permission for an Pre-Authorized Code issuance session to proceed.
type TokenPermissionHandler func(proceed bool, transactionCode *string)

type Handler interface {
	// Shared interface functions with irmaclient.Handler
	Success(result string)
	Cancelled()
	Failure(err *irma.SessionError)

	// OpenID specific interface functions
	RequestPreAuthorizedCodeFlowPermission(
		request *irma.PreAuthorizedCodeFlowPermissionRequest,
		requestorInfo *irma.RequestorInfo,
		callback TokenPermissionHandler,
	)

	RequestAuthorizationCodeFlowPermission(
		request *irma.AuthorizationCodeFlowRequest,
		requestorInfo *irma.RequestorInfo,
		callback AuthCodeHandler,
	)
}
