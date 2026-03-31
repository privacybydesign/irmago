package client

import (
	"time"

	"github.com/privacybydesign/irmago/common/clientmodels"
	openid4vpclient "github.com/privacybydesign/irmago/eudi/openid4vp/client"
	"github.com/privacybydesign/irmago/irma"
	"github.com/privacybydesign/irmago/irma/irmaclient"
)

// openid4vpSessionAdapter adapts the session struct to the openid4vp client's Handler interface.
type openid4vpSessionAdapter struct {
	session *session
}

func (a *openid4vpSessionAdapter) Failure(err *clientmodels.SessionError) {
	a.session.State.Status = Status_Error
	a.session.State.Error = err
	a.session.dispatchState()
}

func (a *openid4vpSessionAdapter) Cancelled() {
	a.session.Cancelled()
}

func (a *openid4vpSessionAdapter) Success(result string, credentialLogs []clientmodels.LogCredential) {
	irma.Logger.Infof("openid4vp session success: %s", result)

	// Store the disclosure log
	if a.session.client.logsStorage != nil && len(credentialLogs) > 0 {
		logEntry := openid4vpCredentialLogsToIrmaclientLogEntry(credentialLogs, a.session.State.Requestor)
		if err := a.session.client.logsStorage.AddLogEntry(logEntry); err != nil {
			irma.Logger.Errorf("failed to store openid4vp log: %v", err)
		}
	}

	a.session.State.Status = Status_Success
	a.session.dispatchState()
}

func (a *openid4vpSessionAdapter) RequestVerificationPermission(
	disclosurePlan *clientmodels.DisclosurePlan,
	requestor *clientmodels.TrustedParty,
	callback openid4vpclient.PermissionHandler,
) {
	a.session.State.Status = Status_RequestPermission
	a.session.State.Type = Type_Disclosure
	a.session.State.Protocol = clientmodels.Protocol_OpenID4VP
	if requestor != nil {
		a.session.State.Requestor = *requestor
	}
	a.session.State.DisclosurePlan = disclosurePlan
	a.session.openid4vpPermissionHandler = callback
	a.session.dispatchState()
}

// openid4vpCredentialLogsToIrmaclientLogEntry converts OpenID4VP credential logs
// into an irmaclient LogEntry for storage.
func openid4vpCredentialLogsToIrmaclientLogEntry(
	credentialLogs []clientmodels.LogCredential,
	requestor TrustedParty,
) *irmaclient.LogEntry {
	var disclosed []irmaclient.CredentialLog
	for _, cl := range credentialLogs {
		attrs := make(map[string]string)
		for _, a := range cl.Attributes {
			if a.Value != nil && a.Value.TranslatedString != nil {
				// Use the first available translation as the string value
				for _, v := range *a.Value.TranslatedString {
					attrs[a.Id] = v
					break
				}
			}
		}
		disclosed = append(disclosed, irmaclient.CredentialLog{
			Formats:        cl.Formats,
			CredentialType: cl.CredentialId,
			Attributes:     attrs,
		})
	}
	requestorInfo := &irma.RequestorInfo{
		ID:   irma.NewRequestorIdentifier(requestor.Id),
		Name: irma.TranslatedString(requestor.Name),
	}
	return &irmaclient.LogEntry{
		Type:       irma.ActionDisclosing,
		Time:       irma.Timestamp(time.Now()),
		ServerName: requestorInfo,
		OpenID4VP: &irmaclient.OpenID4VPDisclosureLog{
			DisclosedCredentials: disclosed,
		},
	}
}
