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

// PermissionHandler is a callback for the user granting or denying permission
// to add the offered credentials to the wallet.
type PermissionHandler func(proceed bool)

// SessionDismisser allows dismissing the current session.
type SessionDismisser interface {
	Dismiss()
}

type Handler interface {
	// Shared interface functions with irmaclient.Handler
	Success(result string, issuedCredentials []*clientmodels.Credential)
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

	// RequestPermission asks the user whether the offered credentials may be
	// added to the wallet. Called after the grant handler has obtained an access
	// token but before the credentials are actually fetched.
	RequestPermission(
		offeredCredentials []*clientmodels.Credential,
		requestorInfo *clientmodels.TrustedParty,
		callback PermissionHandler,
	)
}
