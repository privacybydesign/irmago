package client

import (
	"github.com/privacybydesign/irmago/common/clientmodels"
	"github.com/privacybydesign/irmago/eudi"
	"github.com/privacybydesign/irmago/eudi/openid4vp"
	"github.com/privacybydesign/irmago/eudi/services"
)

// openid4vpSessionAdapter adapts the session struct to the openid4vp client's Handler interface.
type openid4vpSessionAdapter struct {
	session *session
}

func (a *openid4vpSessionAdapter) Failure(err *clientmodels.SessionError) {
	a.session.State.Status = clientmodels.Status_Error
	a.session.State.Error = err
	a.session.finish()
}

func (a *openid4vpSessionAdapter) Cancelled() {
	a.session.State.Status = clientmodels.Status_Dismissed
	a.session.finish()
}

// DeliverDcApiResponse stores the Authorization Response on the session state so
// that the state dispatched on success carries it to the app, which returns it to
// the platform's Digital Credentials API.
func (a *openid4vpSessionAdapter) DeliverDcApiResponse(response string) {
	a.session.State.DcApiResponse = response
}

func (a *openid4vpSessionAdapter) Success(result string, credentialLogs []clientmodels.LogCredential) {
	eudi.Logger.Infof("openid4vp session success: %s", result)

	// Store the disclosure log in the EUDI SQLCipher database. We log even when
	// no credentials were shared (all-optional sets skipped by the user) so the
	// user can still see which verifier they had a session with.
	logService := services.NewEudiLogService(a.session.client.eudiStorage, a.session.client.locale())
	if err := logService.AddDisclosureLog(a.session.State.Requestor, credentialLogs); err != nil {
		eudi.Logger.Errorf("failed to store openid4vp disclosure log: %v", err)
	}

	a.session.State.Status = clientmodels.Status_Success
	a.session.finish()
}

func (a *openid4vpSessionAdapter) RequestVerificationPermission(
	disclosurePlan *clientmodels.DisclosurePlan,
	requestor *clientmodels.TrustedParty,
	responseMode openid4vp.ResponseMode,
	callback openid4vp.PermissionHandler,
) {
	a.session.State.Status = clientmodels.Status_RequestPermission
	a.session.State.Type = clientmodels.Type_Disclosure
	a.session.State.Protocol = clientmodels.Protocol_OpenID4VP
	a.session.State.ResponseMode = string(responseMode)
	if requestor != nil {
		a.session.State.Requestor = *requestor
	}
	// Which issued card does not fit is only known here, where the wallet's
	// credentials are; the cards held when the request arrived count as not
	// issued for it.
	if allCreds, _, err := a.session.client.GetCredentials(); err == nil {
		a.session.snapshotPreExistingCredentials(allCreds)
		disclosurePlan.WrongCredentialIssued = detectWrongCredentialIssued(
			disclosurePlan, a.session.State.DisclosurePlan, allCreds, a.session.preExistingCredentialHashes)
	}

	a.session.State.DisclosurePlan = disclosurePlan
	a.session.openid4vpPermissionHandler = callback
	a.session.dispatchState()
}
