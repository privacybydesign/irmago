package client

import (
	"fmt"
	"net/url"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/eudi/services"
)

// openid4vciSessionAdapter adapts the session struct to the openid4vci client's Handler interface.
type openid4vciSessionAdapter struct {
	session *session
}

func (a *openid4vciSessionAdapter) Failure(err *clientmodels.SessionError) {
	a.session.State.Status = clientmodels.Status_Error
	a.session.State.Error = err
	a.session.finish()
}

func (a *openid4vciSessionAdapter) Cancelled() {
	a.session.State.Status = clientmodels.Status_Dismissed
	a.session.finish()
}

func (a *openid4vciSessionAdapter) Success(result string, issuedCredentials []*clientmodels.Credential) {
	eudi.Logger.Infof("openid4vci session success: %s", result)

	// Store issuance log.
	if len(issuedCredentials) > 0 {
		logCreds := make([]clientmodels.LogCredential, len(issuedCredentials))
		for i, c := range issuedCredentials {
			logCreds[i] = clientmodels.CredentialToLogCredential(c)
		}
		logService := services.NewEudiLogService(a.session.client.eudiStorage)
		if err := logService.AddIssuanceLog(
			clientmodels.Protocol_OpenID4VCI,
			a.session.State.Requestor,
			logCreds,
		); err != nil {
			eudi.Logger.Errorf("failed to store openid4vci issuance log: %v", err)
		}
	}

	a.session.State.Status = clientmodels.Status_Success
	a.session.finish()
}

func (a *openid4vciSessionAdapter) RequestAuthorizationCodeFlowPermission(
	request *clientmodels.AuthorizationCodeFlowRequest,
	requestorInfo *clientmodels.TrustedParty,
	callback openid4vci.AuthCodeHandler,
) {
	a.session.State.OpenID4VCIState = request.OpenID4VCIState

	// Add the state to the authorization parameters so it will be send to the authorization server and back to us, to verify the response belongs to this session
	authParams := url.Values(request.AuthorizationParameters)
	authParams.Add("state", a.session.State.OpenID4VCIState)

	// Construct the URL that the client should open in the browser to start the authorization code flow
	authRequestUrl, err := url.Parse(request.AuthorizationEndpoint)
	if err != nil {
		a.session.error(fmt.Errorf("failed to parse authorization endpoint URL: %v", err))
		return
	}

	authRequestUrl.RawQuery = authParams.Encode()

	a.session.State.Status = clientmodels.Status_RequestAuthorizationCode
	a.session.State.Type = clientmodels.Type_Issuance
	a.session.State.OfferedCredentialTypes = request.Credentials
	if requestorInfo != nil {
		a.session.State.Requestor = *requestorInfo
	}
	a.session.State.AuthorizationRequestUrl = authRequestUrl.String()
	a.session.authCodeHandler = callback

	// Quick fix for OID4VCI flow, to open the correct success-screen after issuance
	a.session.State.ContinueOnSecondDevice = true

	a.session.dispatchState()
}

func (a *openid4vciSessionAdapter) RequestPermission(
	offeredCredentials []*clientmodels.Credential,
	requestorInfo *clientmodels.TrustedParty,
	callback openid4vci.PermissionHandler,
) {
	a.session.State.OfferedCredentials = offeredCredentials
	a.session.State.Status = clientmodels.Status_RequestPermission
	a.session.openid4vciPermissionHandler = callback
	a.session.dispatchState()
}

func (a *openid4vciSessionAdapter) RequestPreAuthorizedCodeFlowPermission(
	request *clientmodels.PreAuthorizedCodeFlowPermissionRequest,
	requestorInfo *clientmodels.TrustedParty,
	callback openid4vci.TokenPermissionHandler,
) {
	a.session.State.Status = clientmodels.Status_RequestPreAuthorizedCode
	a.session.State.Type = clientmodels.Type_Issuance
	a.session.State.OfferedCredentialTypes = request.Credentials
	if requestorInfo != nil {
		a.session.State.Requestor = *requestorInfo
	}
	if request.TransactionCodeParameters != nil {
		a.session.State.TransactionCodeParameters = request.TransactionCodeParameters
	}
	a.session.State.RemainingTxCodeAttempts = request.RemainingAttempts
	a.session.preAuthorizedCodeHandler = callback

	// Quick fix for OID4VCI flow, to open the correct success-screen after issuance
	a.session.State.ContinueOnSecondDevice = true

	a.session.dispatchState()
}
