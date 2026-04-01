package client

import (
	"fmt"
	"net/url"

	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi/openid4vci"
	"github.com/privacybydesign/irmago/irma"
)

func parseAuthorizationEndpoint(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authorization endpoint URL: %v", err)
	}
	return u, nil
}

// openid4vciSessionAdapter adapts the session struct to the openid4vci client's Handler interface.
type openid4vciSessionAdapter struct {
	session *session
}

func (a *openid4vciSessionAdapter) Failure(err *clientmodels.SessionError) {
	a.session.State.Status = clientmodels.Status_Error
	a.session.State.Error = err
	a.session.dispatchState()
}

func (a *openid4vciSessionAdapter) Cancelled() {
	a.session.State.Status = clientmodels.Status_Dismissed
	a.session.dispatchState()
}

func (a *openid4vciSessionAdapter) Success(result string) {
	irma.Logger.Infof("openid4vci session success: %s", result)
	a.session.State.Status = clientmodels.Status_Success
	a.session.dispatchState()
}

func (a *openid4vciSessionAdapter) RequestAuthorizationCodeFlowPermission(
	request *clientmodels.AuthorizationCodeFlowRequest,
	requestorInfo *clientmodels.TrustedParty,
	callback openid4vci.AuthCodeHandler,
) {
	a.session.setPseudoRandomOpenIdState()

	// Add the state to the authorization parameters so it will be send to the authorization server and back to us, to verify the response belongs to this session
	authParams := url.Values(request.AuthorizationParameters)
	authParams.Add("state", a.session.State.Oid4VciState)

	// Construct the URL that the client should open in the browser to start the authorization code flow
	authRequestUrl, err := parseAuthorizationEndpoint(request.AuthorizationEndpoint)
	if err != nil {
		a.session.error(err)
		return
	}
	authRequestUrl.RawQuery = authParams.Encode()

	a.session.State.Status = clientmodels.Status_RequestAuthorizationCode
	a.session.State.Type = clientmodels.Type_Issuance
	a.session.State.OfferedCredentialTypes = credentialTypeInfoListToSchemaless(request.CredentialTypeInfoList)
	if requestorInfo != nil {
		a.session.State.Requestor = *requestorInfo
	}
	a.session.State.AuthorizationRequestUrl = authRequestUrl.String()
	a.session.authCodeHandler = callback

	// Quick fix for OID4VCI flow, to open the correct success-screen after issuance
	a.session.State.ContinueOnSecondDevice = true

	a.session.dispatchState()
}

func (a *openid4vciSessionAdapter) RequestPreAuthorizedCodeFlowPermission(
	request *clientmodels.PreAuthorizedCodeFlowPermissionRequest,
	requestorInfo *clientmodels.TrustedParty,
	callback openid4vci.TokenPermissionHandler,
) {
	a.session.State.Status = clientmodels.Status_RequestPreAuthorizedCode
	a.session.State.Type = clientmodels.Type_Issuance
	a.session.State.OfferedCredentialTypes = credentialTypeInfoListToSchemaless(request.CredentialTypeInfoList)
	if requestorInfo != nil {
		a.session.State.Requestor = *requestorInfo
	}
	if request.TransactionCodeParameters != nil {
		a.session.State.TransactionCodeParameters = request.TransactionCodeParameters
	}
	a.session.preAuthorizedCodeHandler = callback

	// Quick fix for OID4VCI flow, to open the correct success-screen after issuance
	a.session.State.ContinueOnSecondDevice = true

	a.session.dispatchState()
}
